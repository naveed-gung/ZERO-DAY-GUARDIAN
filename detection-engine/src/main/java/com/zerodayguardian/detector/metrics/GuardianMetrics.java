package com.zerodayguardian.detector.metrics;

import com.zerodayguardian.detector.detection.CryptojackingDetector;
import com.zerodayguardian.detector.detection.LateralMovementDetector;
import com.zerodayguardian.detector.detection.SyscallSequenceAnalyzer;
import com.zerodayguardian.detector.event.RingBufferReader;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Exposes Guardian-specific metrics via Micrometer/Prometheus.
 *
 * <p>
 * Registered metrics (in addition to per-component counters/timers):
 * </p>
 * <ul>
 * <li>{@code guardian.ringbuffer.pending_events} - Events waiting in ring
 * buffer</li>
 * <li>{@code guardian.uptime_seconds} - Detection engine uptime</li>
 * </ul>
 *
 * <p>
 * Also runs periodic maintenance tasks for detector state cleanup.
 * </p>
 *
 * @author Naveed Gung
 */
@Component
public class GuardianMetrics {

    private static final Logger log = LoggerFactory.getLogger(GuardianMetrics.class);

    private final RingBufferReader ringBufferReader;
    private final CryptojackingDetector cryptojackingDetector;
    private final LateralMovementDetector lateralMovementDetector;
    private final SyscallSequenceAnalyzer sequenceAnalyzer;
    private final MeterRegistry meterRegistry;

    private final long startTime = System.currentTimeMillis();

    public GuardianMetrics(
            RingBufferReader ringBufferReader,
            CryptojackingDetector cryptojackingDetector,
            LateralMovementDetector lateralMovementDetector,
            SyscallSequenceAnalyzer sequenceAnalyzer,
            MeterRegistry meterRegistry) {
        this.ringBufferReader = ringBufferReader;
        this.cryptojackingDetector = cryptojackingDetector;
        this.lateralMovementDetector = lateralMovementDetector;
        this.sequenceAnalyzer = sequenceAnalyzer;
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void registerGauges() {
        Gauge.builder("guardian.ringbuffer.pending_events", ringBufferReader, RingBufferReader::pendingEvents)
                .description("Number of events pending in the ring buffer")
                .register(meterRegistry);

        Gauge.builder("guardian.uptime_seconds", this, g -> (System.currentTimeMillis() - g.startTime) / 1000.0)
                .description("Detection engine uptime in seconds")
                .register(meterRegistry);

        log.info("Guardian metrics registered");
    }

    /**
     * Periodic maintenance: reset detector counters and prune stale state.
     * Runs every 5 minutes.
     */
    @Scheduled(fixedRate = 300_000, initialDelay = 300_000)
    public void periodicMaintenance() {
        log.debug("Running periodic maintenance");

        try {
            cryptojackingDetector.resetCounters();
            lateralMovementDetector.resetCounters();
            sequenceAnalyzer.pruneEmptyWindows();
        } catch (Exception e) {
            log.error("Periodic maintenance failed: {}", e.getMessage(), e);
        }
    }
}
