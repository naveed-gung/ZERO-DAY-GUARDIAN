package com.zerodayguardian.detector.alert;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * Elasticsearch integration for alert indexing.
 *
 * <p>
 * Sends detection alerts to an Elasticsearch index for
 * long-term storage, search, and visualization in Kibana.
 * </p>
 *
 * @author Naveed Gung
 */
@Component
@ConditionalOnProperty(prefix = "guardian.siem.elastic", name = "enabled", havingValue = "true")
public class ElasticIntegration implements AlertService.SiemIntegration {

    private static final Logger log = LoggerFactory.getLogger(ElasticIntegration.class);

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    @Value("${guardian.siem.elastic.index:zero-day-guardian-alerts}")
    private String indexName;

    public ElasticIntegration(
            @Value("${guardian.siem.elastic.url}") String elasticUrl,
            @Value("${guardian.siem.elastic.api-key:}") String apiKey,
            ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;

        WebClient.Builder builder = WebClient.builder()
                .baseUrl(elasticUrl)
                .defaultHeader("Content-Type", "application/json");

        if (apiKey != null && !apiKey.isEmpty()) {
            builder.defaultHeader("Authorization", "ApiKey " + apiKey);
        }

        this.webClient = builder.build();
    }

    @Override
    public void send(AlertPayload payload) {
        try {
            Map<String, Object> document = new HashMap<>();
            document.put("@timestamp", payload.timestamp().toString());
            document.put("alert_id", payload.alertId());
            document.put("severity", payload.severity());
            document.put("category", payload.category());
            document.put("detail", payload.detail());
            document.put("score", payload.score());
            document.put("pid", payload.pid());
            document.put("uid", payload.uid());
            document.put("comm", payload.comm());
            document.put("filename", payload.filename());
            document.put("container_id", payload.containerId());
            document.put("event_type", payload.eventType());
            document.put("from_container", payload.fromContainer());
            document.put("privileged", payload.privileged());
            document.put("metadata", payload.metadata());

            String body = objectMapper.writeValueAsString(document);

            // Use date-based index name: zero-day-guardian-alerts-2026.01.15
            String dateIndex = indexName + "-" +
                    DateTimeFormatter.ofPattern("yyyy.MM.dd")
                            .format(payload.timestamp().atZone(java.time.ZoneOffset.UTC));

            webClient.post()
                    .uri("/{index}/_doc", dateIndex)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(5))
                    .doOnSuccess(resp -> log.debug("Elasticsearch accepted alert {}", payload.alertId()))
                    .doOnError(e -> log.warn("Elasticsearch rejected alert {}: {}", payload.alertId(), e.getMessage()))
                    .subscribe();

        } catch (Exception e) {
            log.error("Failed to send alert {} to Elasticsearch: {}", payload.alertId(), e.getMessage());
            throw new RuntimeException("Elasticsearch delivery failed", e);
        }
    }
}
