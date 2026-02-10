package com.zerodayguardian.detector.alert;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.Map;

/**
 * Splunk HTTP Event Collector (HEC) integration.
 *
 * <p>
 * Sends detection alerts to Splunk via the HEC endpoint.
 * Configured via environment variables for token and URL.
 * </p>
 *
 * @see <a href=
 *      "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector">Splunk
 *      HEC</a>
 * @author Naveed Gung
 */
@Component
@ConditionalOnProperty(prefix = "guardian.siem.splunk", name = "enabled", havingValue = "true")
public class SplunkIntegration implements AlertService.SiemIntegration {

    private static final Logger log = LoggerFactory.getLogger(SplunkIntegration.class);

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    @Value("${guardian.siem.splunk.index:main}")
    private String index;

    @Value("${guardian.siem.splunk.source-type:zero_day_guardian}")
    private String sourceType;

    public SplunkIntegration(
            @Value("${guardian.siem.splunk.hec-url}") String hecUrl,
            @Value("${guardian.siem.splunk.hec-token}") String hecToken,
            ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.webClient = WebClient.builder()
                .baseUrl(hecUrl)
                .defaultHeader("Authorization", "Splunk " + hecToken)
                .defaultHeader("Content-Type", "application/json")
                .build();
    }

    @Override
    public void send(AlertPayload payload) {
        try {
            Map<String, Object> hecEvent = Map.of(
                    "time", payload.timestamp().getEpochSecond(),
                    "host", "zero-day-guardian",
                    "source", "detection-engine",
                    "sourcetype", sourceType,
                    "index", index,
                    "event", payload);

            String body = objectMapper.writeValueAsString(hecEvent);

            webClient.post()
                    .uri("/services/collector/event")
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(5))
                    .doOnSuccess(resp -> log.debug("Splunk HEC accepted alert {}", payload.alertId()))
                    .doOnError(e -> log.warn("Splunk HEC rejected alert {}: {}", payload.alertId(), e.getMessage()))
                    .subscribe();

        } catch (Exception e) {
            log.error("Failed to send alert {} to Splunk: {}", payload.alertId(), e.getMessage());
            throw new RuntimeException("Splunk HEC delivery failed", e);
        }
    }
}
