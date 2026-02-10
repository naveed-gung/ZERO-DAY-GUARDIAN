package com.zerodayguardian.detector.threatintel;

import com.zerodayguardian.detector.config.ThreatIntelConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * AbuseIPDB API v2 client for IP reputation lookups.
 *
 * @see <a href="https://docs.abuseipdb.com/">AbuseIPDB API v2</a>
 * @author Naveed Gung
 */
@Component
public class AbuseIPDBClient {

    private static final Logger log = LoggerFactory.getLogger(AbuseIPDBClient.class);

    private final WebClient webClient;
    private final ThreatIntelConfig.AbuseIPDB config;
    private final ObjectMapper objectMapper;

    /** Abuse confidence score threshold for flagging as malicious. */
    private static final int ABUSE_THRESHOLD = 50;

    public AbuseIPDBClient(ThreatIntelConfig threatIntelConfig, ObjectMapper objectMapper) {
        this.config = threatIntelConfig.getAbuseIpDb();
        this.objectMapper = objectMapper;
        this.webClient = WebClient.builder()
                .baseUrl(config.getBaseUrl())
                .defaultHeader("Key", config.getApiKey())
                .defaultHeader("Accept", "application/json")
                .build();
    }

    /**
     * Check an IP address against the AbuseIPDB database.
     *
     * @param ipAddress the IP address to check
     * @return the threat intel result
     */
    public Mono<ThreatIntelResult> checkIp(String ipAddress) {
        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/check")
                        .queryParam("ipAddress", ipAddress)
                        .queryParam("maxAgeInDays", "90")
                        .queryParam("verbose", "true")
                        .build())
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofMillis(config.getTimeoutMs()))
                .map(this::parseResponse)
                .onErrorResume(e -> {
                    log.warn("AbuseIPDB check failed for {}: {}", ipAddress, e.getMessage());
                    return Mono.just(ThreatIntelResult.unavailable("abuseipdb"));
                });
    }

    /**
     * Report a malicious IP to AbuseIPDB.
     *
     * @param ipAddress  the IP to report
     * @param categories comma-separated AbuseIPDB category IDs
     * @param comment    description of the abuse
     * @return success flag
     */
    public Mono<Boolean> reportIp(String ipAddress, String categories, String comment) {
        return webClient.post()
                .uri("/report")
                .bodyValue(Map.of(
                        "ip", ipAddress,
                        "categories", categories,
                        "comment", comment))
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofMillis(config.getTimeoutMs()))
                .map(body -> {
                    log.info("Reported IP {} to AbuseIPDB", ipAddress);
                    return true;
                })
                .onErrorResume(e -> {
                    log.warn("AbuseIPDB report failed for {}: {}", ipAddress, e.getMessage());
                    return Mono.just(false);
                });
    }

    private ThreatIntelResult parseResponse(String body) {
        try {
            JsonNode root = objectMapper.readTree(body);
            JsonNode data = root.path("data");

            int abuseConfidenceScore = data.path("abuseConfidenceScore").asInt(0);
            int totalReports = data.path("totalReports").asInt(0);
            boolean isWhitelisted = data.path("isWhitelisted").asBoolean(false);

            double score = abuseConfidenceScore / 100.0;
            boolean isMalicious = !isWhitelisted && abuseConfidenceScore >= ABUSE_THRESHOLD;

            Map<String, Object> details = new HashMap<>();
            details.put("abuse_confidence_score", abuseConfidenceScore);
            details.put("total_reports", totalReports);
            details.put("country_code", data.path("countryCode").asText("unknown"));
            details.put("isp", data.path("isp").asText("unknown"));
            details.put("domain", data.path("domain").asText("unknown"));
            details.put("is_whitelisted", isWhitelisted);
            details.put("usage_type", data.path("usageType").asText("unknown"));

            return isMalicious
                    ? ThreatIntelResult.malicious("abuseipdb", score, details)
                    : ThreatIntelResult.clean("abuseipdb");

        } catch (Exception e) {
            log.error("Failed to parse AbuseIPDB response: {}", e.getMessage());
            return ThreatIntelResult.unavailable("abuseipdb");
        }
    }
}
