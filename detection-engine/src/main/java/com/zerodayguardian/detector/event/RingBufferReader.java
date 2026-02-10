package com.zerodayguardian.detector.event;

import com.zerodayguardian.detector.config.RingBufferConfig;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Lock-free SPSC ring buffer reader backed by a memory-mapped tmpfs file.
 *
 * <p>
 * The file layout is defined in {@code proto/events.md}:
 * </p>
 * <ul>
 * <li>Bytes [0, 8): write_pos (u64, little-endian, written by Rust
 * producer)</li>
 * <li>Bytes [8, 16): read_pos (u64, little-endian, written by this reader)</li>
 * <li>Bytes [16, 24): capacity (u64)</li>
 * <li>Bytes [24, 32): flags (u64)</li>
 * <li>Bytes [32, 64): reserved</li>
 * <li>Bytes [64, 64 + capacity): event data ring</li>
 * </ul>
 *
 * <p>
 * Atomic visibility is achieved through {@link VarHandle}
 * acquire/release fences on the header positions.
 * </p>
 *
 * @author Naveed Gung
 */
@Component
public class RingBufferReader {

    private static final Logger log = LoggerFactory.getLogger(RingBufferReader.class);

    /** Header size in bytes (matches RingBufferHeader in Rust). */
    private static final int HEADER_SIZE = 64;

    /** Offsets within the header. */
    private static final int WRITE_POS_OFFSET = 0;
    private static final int READ_POS_OFFSET = 8;
    private static final int CAPACITY_OFFSET = 16;

    private static final VarHandle FENCE = MethodHandles.arrayElementVarHandle(long[].class);

    private final RingBufferConfig config;
    private final MeterRegistry meterRegistry;

    private MappedByteBuffer mappedBuffer;
    private RandomAccessFile raf;
    private long capacity;

    private ScheduledExecutorService pollExecutor;
    private final List<Consumer<SyscallEvent>> listeners = new ArrayList<>();

    private Counter eventsRead;
    private Counter eventsDecodeErrors;

    public RingBufferReader(RingBufferConfig config, MeterRegistry meterRegistry) {
        this.config = config;
        this.meterRegistry = meterRegistry;
    }

    /**
     * Register a listener that will be invoked for each decoded event.
     * Must be called before {@link #start()}.
     */
    public void addListener(Consumer<SyscallEvent> listener) {
        listeners.add(listener);
    }

    @PostConstruct
    public void init() {
        eventsRead = Counter.builder("guardian.ringbuffer.events.read")
                .description("Total events read from ring buffer")
                .register(meterRegistry);
        eventsDecodeErrors = Counter.builder("guardian.ringbuffer.events.decode_errors")
                .description("Events that failed to decode")
                .register(meterRegistry);
    }

    /**
     * Open the shared memory-mapped file and begin polling.
     */
    public void start() {
        String path = config.getPath();
        log.info("Opening ring buffer at {}", path);

        try {
            raf = new RandomAccessFile(path, "rw");
            long fileSize = raf.length();
            if (fileSize < HEADER_SIZE) {
                throw new IllegalStateException(
                        "Ring buffer file too small: " + fileSize + " bytes (need >= " + HEADER_SIZE + ")");
            }

            mappedBuffer = raf.getChannel().map(FileChannel.MapMode.READ_WRITE, 0, fileSize);
            mappedBuffer.order(ByteOrder.LITTLE_ENDIAN);

            capacity = mappedBuffer.getLong(CAPACITY_OFFSET);
            if (capacity <= 0 || capacity > fileSize - HEADER_SIZE) {
                throw new IllegalStateException("Invalid ring buffer capacity: " + capacity);
            }

            log.info("Ring buffer opened: capacity={} bytes, event_slots={}",
                    capacity, capacity / SyscallEvent.SERIALIZED_SIZE);

            pollExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "ringbuf-reader");
                t.setDaemon(true);
                return t;
            });
            pollExecutor.scheduleWithFixedDelay(
                    this::pollEvents,
                    0,
                    config.getPollIntervalMs(),
                    TimeUnit.MILLISECONDS);

        } catch (IOException e) {
            throw new IllegalStateException("Failed to open ring buffer at " + path, e);
        }
    }

    /**
     * Single poll iteration: drain all available events from the ring buffer.
     */
    void pollEvents() {
        try {
            int drained = 0;
            while (drained < 1024) { // cap per-poll to avoid starving other work
                long writePos = readWritePos();
                long readPos = readReadPos();

                long available = writePos - readPos;
                if (available < SyscallEvent.SERIALIZED_SIZE) {
                    break;
                }

                long ringOffset = HEADER_SIZE + (readPos % capacity);
                long remaining = capacity - (readPos % capacity);

                ByteBuffer eventBuf;
                if (remaining >= SyscallEvent.SERIALIZED_SIZE) {
                    // Contiguous read
                    eventBuf = mappedBuffer.slice((int) ringOffset, SyscallEvent.SERIALIZED_SIZE);
                    eventBuf.order(ByteOrder.LITTLE_ENDIAN);
                } else {
                    // Event wraps around ring boundary: assemble into temp buffer
                    byte[] assembled = new byte[SyscallEvent.SERIALIZED_SIZE];
                    int firstPart = (int) remaining;
                    mappedBuffer.slice((int) ringOffset, firstPart).get(assembled, 0, firstPart);
                    mappedBuffer.slice(HEADER_SIZE, SyscallEvent.SERIALIZED_SIZE - firstPart)
                            .get(assembled, firstPart, SyscallEvent.SERIALIZED_SIZE - firstPart);
                    eventBuf = ByteBuffer.wrap(assembled).order(ByteOrder.LITTLE_ENDIAN);
                }

                try {
                    SyscallEvent event = SyscallEvent.decode(eventBuf);
                    eventsRead.increment();
                    for (Consumer<SyscallEvent> listener : listeners) {
                        listener.accept(event);
                    }
                } catch (Exception e) {
                    eventsDecodeErrors.increment();
                    log.warn("Failed to decode event at readPos={}: {}", readPos, e.getMessage());
                }

                advanceReadPos(readPos + SyscallEvent.SERIALIZED_SIZE);
                drained++;
            }
        } catch (Exception e) {
            log.error("Error during ring buffer poll", e);
        }
    }

    /** Atomic acquire-read of the producer's write position. */
    private long readWritePos() {
        // Acquire fence to see producer's writes
        long[] fence = new long[1];
        FENCE.getAcquire(fence, 0);
        return mappedBuffer.getLong(WRITE_POS_OFFSET);
    }

    /** Read the consumer's current read position. */
    private long readReadPos() {
        return mappedBuffer.getLong(READ_POS_OFFSET);
    }

    /**
     * Advance the read position with a release store so the producer can reclaim
     * space.
     */
    private void advanceReadPos(long newPos) {
        mappedBuffer.putLong(READ_POS_OFFSET, newPos);
        long[] fence = new long[1];
        FENCE.setRelease(fence, 0, 0L);
    }

    /** Return the number of events currently pending in the buffer. */
    public long pendingEvents() {
        long writePos = readWritePos();
        long readPos = readReadPos();
        long available = writePos - readPos;
        return Math.max(0, available / SyscallEvent.SERIALIZED_SIZE);
    }

    @PreDestroy
    public void stop() {
        log.info("Shutting down ring buffer reader");
        if (pollExecutor != null) {
            pollExecutor.shutdown();
            try {
                if (!pollExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    pollExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                pollExecutor.shutdownNow();
            }
        }
        if (raf != null) {
            try {
                raf.close();
            } catch (IOException e) {
                log.warn("Error closing ring buffer file", e);
            }
        }
    }
}
