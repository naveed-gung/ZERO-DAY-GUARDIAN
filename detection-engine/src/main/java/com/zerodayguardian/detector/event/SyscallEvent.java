package com.zerodayguardian.detector.event;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * Java representation of the 384-byte {@code SyscallEvent} from the ring
 * buffer.
 *
 * <p>
 * Layout matches the {@code #[repr(C)]} struct in
 * {@code ebpf-monitor-common/src/lib.rs} exactly:
 * </p>
 *
 * <pre>
 * Offset  Size  Field
 * ------  ----  -----
 *   0       4   magic        (0xDEADBEEF)
 *   4       1   version
 *   5       1   event_type
 *   6       2   flags
 *   8       8   timestamp_ns (monotonic)
 *  16       4   pid
 *  20       4   tgid
 *  24       4   uid
 *  28       4   gid
 *  32      16   comm
 *  48     256   filename
 * 304       8   cgroup_id
 * 312      64   container_id
 * 376       4   syscall_nr
 * 380       4   return_value
 * ------  ----
 * Total: 384 bytes
 * </pre>
 *
 * @author Naveed Gung
 */
public record SyscallEvent(
        int magic,
        int version,
        EventType eventType,
        int flags,
        long timestampNs,
        int pid,
        int tgid,
        int uid,
        int gid,
        String comm,
        String filename,
        long cgroupId,
        String containerId) {

    /** Expected magic value for valid events. */
    public static final int MAGIC = 0xDEADBEEF;

    /** Current wire protocol version. */
    public static final int CURRENT_VERSION = 1;

    /** Total serialized size in bytes. */
    public static final int SERIALIZED_SIZE = 384;

    /* ---- Flag bit masks ---- */
    public static final int FLAG_FROM_CONTAINER = 1;
    public static final int FLAG_PRIVILEGED_CTX = 1 << 1;
    public static final int FLAG_HOST_NAMESPACE = 1 << 2;
    public static final int FLAG_SUSPICIOUS = 1 << 3;

    /**
     * Decode a single event from the given little-endian buffer.
     *
     * @param buf a ByteBuffer positioned at the start of a 384-byte event
     * @return the decoded SyscallEvent
     * @throws IllegalArgumentException if magic or version mismatches
     */
    public static SyscallEvent decode(ByteBuffer buf) {
        if (buf.remaining() < SERIALIZED_SIZE) {
            throw new IllegalArgumentException("Truncated syscall event");
        }
        buf.order(ByteOrder.LITTLE_ENDIAN);

        int magic = buf.getInt();
        if (magic != MAGIC) {
            throw new IllegalArgumentException(
                    String.format("Invalid magic: 0x%08X (expected 0x%08X)", magic, MAGIC));
        }

        int version = Byte.toUnsignedInt(buf.get());
        if (version != CURRENT_VERSION) {
            throw new IllegalArgumentException(
                    "Unsupported event version: " + version + " (expected " + CURRENT_VERSION + ")");
        }

        int eventTypeWire = Byte.toUnsignedInt(buf.get());
        EventType eventType = EventType.fromWireValue(eventTypeWire);
        int flags = Short.toUnsignedInt(buf.getShort());
        long timestampNs = buf.getLong();
        int pid = buf.getInt();
        int tgid = buf.getInt();
        int uid = buf.getInt();
        int gid = buf.getInt();

        String comm = readFixedString(buf, 16);
        String filename = readFixedString(buf, 256);
        long cgroupId = buf.getLong();
        String containerId = readFixedString(buf, 64);
        buf.position(buf.position() + 2 * Integer.BYTES);

        return new SyscallEvent(
                magic, version, eventType, flags, timestampNs,
                pid, tgid, uid, gid, comm, filename, cgroupId, containerId);
    }

    /** Read a null-terminated string from a fixed-width byte field. */
    private static String readFixedString(ByteBuffer buf, int fieldWidth) {
        byte[] raw = new byte[fieldWidth];
        buf.get(raw);
        int len = 0;
        while (len < fieldWidth && raw[len] != 0) {
            len++;
        }
        return new String(raw, 0, len, StandardCharsets.UTF_8);
    }

    // ---- Convenience flag inspectors ----

    public boolean isFromContainer() {
        return (flags & FLAG_FROM_CONTAINER) != 0;
    }

    public boolean isPrivileged() {
        return (flags & FLAG_PRIVILEGED_CTX) != 0;
    }

    public boolean isHostNamespace() {
        return (flags & FLAG_HOST_NAMESPACE) != 0;
    }

    public boolean isSuspicious() {
        return (flags & FLAG_SUSPICIOUS) != 0;
    }

    /** True when the event carries a non-empty container ID. */
    public boolean hasContainerId() {
        return containerId != null && !containerId.isEmpty();
    }
}
