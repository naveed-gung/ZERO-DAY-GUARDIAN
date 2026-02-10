package com.zerodayguardian.detector.alert;

import com.zerodayguardian.detector.detection.DetectionResult;
import com.zerodayguardian.detector.event.SyscallEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Central alert dispatch service.
 *
 * <p>
 * Routes detection alerts to all configured SIEM integrations
 * (Splunk HEC, Elasticsearch) in parallel, with per-integration
 * error isolation.
 * </p>
 *
 * @author Naveed Gung
 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    private final List<SiemIntegration> integrations;
    private final MeterRegistry meterRegistry;

    private Counter alertsSent;
    private Counter alertsFailed;

    public AlertService(List<SiemIntegration> integrations, MeterRegistry meterRegistry) {
        this.integrations = integrations;
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void init() {
        alertsSent = Counter.builder("guardian.alert.sent")
                .description("Total alerts sent to SIEM integrations")
                .register(meterRegistry);
        alertsFailed = Counter.builder("guardian.alert.failed")
                .description("Alert delivery failures")
                .register(meterRegistry);

        log.info("Alert service initialized with {} integrations: {}",
                integrations.size(),
                integrations.stream().map(i -> i.getClass().getSimpleName()).toList());
    }

    /**
     * Send a detection alert to all configured SIEM integrations.
     *
     * @param event  the triggering event
     * @param result the detection result
     */
    public void sendAlert(SyscallEvent event, DetectionResult result) {
        AlertPayload payload = AlertPayload.from(event, result);

        for (SiemIntegration integration : integrations) {
            try {
                integration.send(payload);
                alertsSent.increment();
            } catch (Exception e) {
                alertsFailed.increment();
                log.error("Alert delivery failed for {}: {}",
                        integration.getClass().getSimpleName(), e.getMessage());
            }
        }
    }

    /** Pluggable SIEM integration interface. */
    public interface SiemIntegration {
        void send(AlertPayload payload);
    }
}
