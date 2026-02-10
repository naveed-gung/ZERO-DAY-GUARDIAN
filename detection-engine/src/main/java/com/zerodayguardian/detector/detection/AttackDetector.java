package com.zerodayguardian.detector.detection;

import com.zerodayguardian.detector.action.SafeActionExecutor;
import com.zerodayguardian.detector.alert.AlertService;
import com.zerodayguardian.detector.event.RingBufferReader;
import com.zerodayguardian.detector.event.SyscallEvent;
import com.zerodayguardian.detector.forensic.EvidenceCollector;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;

/**
 * Central detection orchestrator.
 *
 * <p>
 * Receives every {@link SyscallEvent} from the ring buffer reader, runs it
 * through all registered detectors, and dispatches positive detections to the
 * action executor, alert service, and evidence collector.
 * </p>
 *
 * @author Naveed Gung
 */
@Component
public class AttackDetector {

    private static final Logger log = LoggerFactory.getLogger(AttackDetector.class);

    private final RingBufferReader ringBufferReader;
    private final List<Detector> detectors;
    private final SafeActionExecutor actionExecutor;
    private final AlertService alertService;
    private final EvidenceCollector evidenceCollector;
    private final MeterRegistry meterRegistry;

    private Counter eventsProcessed;
    private Counter threatsDetected;
    private Timer detectionLatency;

    public AttackDetector(
            RingBufferReader ringBufferReader,
            List<Detector> detectors,
            SafeActionExecutor actionExecutor,
            AlertService alertService,
            EvidenceCollector evidenceCollector,
            MeterRegistry meterRegistry) {
        this.ringBufferReader = ringBufferReader;
        this.detectors = detectors;
        this.actionExecutor = actionExecutor;
        this.alertService = alertService;
        this.evidenceCollector = evidenceCollector;
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void init() {
        eventsProcessed = Counter.builder("guardian.detection.events.processed")
                .description("Total events passed through detection pipeline")
                .register(meterRegistry);
        threatsDetected = Counter.builder("guardian.detection.threats.detected")
                .description("Total threats detected")
                .register(meterRegistry);
        detectionLatency = Timer.builder("guardian.detection.latency")
                .description("Time to run all detectors on one event")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(meterRegistry);

        // Register as a listener on the ring buffer reader
        ringBufferReader.addListener(this::onEvent);
        ringBufferReader.start();
        log.info("Attack detector initialized with {} detectors: {}",
                detectors.size(), detectors.stream().map(d -> d.getClass().getSimpleName()).toList());
    }

    /**
     * Process a single event through the detection pipeline.
     */
    void onEvent(SyscallEvent event) {
        eventsProcessed.increment();

        Timer.Sample sample = Timer.start(meterRegistry);
        try {
            for (Detector detector : detectors) {
                try {
                    DetectionResult result = detector.analyze(event);
                    if (result.detected()) {
                        threatsDetected.increment();
                        handleDetection(event, result);
                    }
                } catch (Exception e) {
                    log.error("Detector {} threw an exception for event pid={}: {}",
                            detector.getClass().getSimpleName(), event.pid(), e.getMessage(), e);
                }
            }
        } finally {
            sample.stop(detectionLatency);
        }
    }

    /**
     * Handle a confirmed detection: collect evidence, execute response, send alert.
     */
    private void handleDetection(SyscallEvent event, DetectionResult result) {
        log.warn("THREAT DETECTED: category={} severity={} pid={} comm={} container={} detail={}",
                result.category(), result.severity(), event.pid(), event.comm(),
                event.containerId(), result.detail());

        try {
            evidenceCollector.collect(event, result);
        } catch (Exception e) {
            log.error("Evidence collection failed for pid={}: {}", event.pid(), e.getMessage());
        }

        try {
            actionExecutor.executeResponse(event, result);
        } catch (Exception e) {
            log.error("Action execution failed for pid={}: {}", event.pid(), e.getMessage());
        }

        try {
            alertService.sendAlert(event, result);
        } catch (Exception e) {
            log.error("Alert delivery failed for pid={}: {}", event.pid(), e.getMessage());
        }
    }

    /** Functional interface for pluggable detectors. */
    public interface Detector {
        /**
         * Analyze a syscall event for potential threats.
         *
         * @param event the event to analyze
         * @return the detection result (never null)
         */
        DetectionResult analyze(SyscallEvent event);
    }
}
