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
 * VirusTotal API v3 client for file hash and IP reputation lookups.
 *
 * @see <a href="https://docs.virustotal.com/reference/overview">VirusTotal API
 *      v3</a>
 * @author Naveed Gung
 */
@Component
public class VirusTotalClient {

    private static final Logger log = LoggerFactory.getLogger(VirusTotalClient.class);

    private final WebClient webClient;
    private final ThreatIntelConfig.VirusTotal config;
    private final ObjectMapper objectMapper;

    public VirusTotalClient(ThreatIntelConfig threatIntelConfig, ObjectMapper objectMapper) {
        this.config = threatIntelConfig.getVirusTotal();
        this.objectMapper = objectMapper;
        this.webClient = WebClient.builder()
                .baseUrl(config.getBaseUrl())
                .defaultHeader("x-apikey", config.getApiKey())
                .defaultHeader("Accept", "application/json")
                .build();
    }

    /**
     * Look up a file hash (SHA-256, SHA-1, or MD5).
     *
     * @param fileHash the hash to look up
     * @return the threat intel result
     */
    public Mono<ThreatIntelResult> lookupFileHash(String fileHash) {
        return webClient.get()
                .uri("/files/{hash}", fileHash)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofMillis(config.getTimeoutMs()))
                .map(this::parseFileResponse)
                .onErrorResume(e -> {
                    log.warn("VirusTotal file lookup failed for {}: {}", fileHash, e.getMessage());
                    return Mono.just(ThreatIntelResult.unavailable("virustotal"));
                });
    }

    /**
     * Look up an IP address reputation.
     *
     * @param ipAddress the IP to look up
     * @return the threat intel result
     */
    public Mono<ThreatIntelResult> lookupIp(String ipAddress) {
        return webClient.get()
                .uri("/ip_addresses/{ip}", ipAddress)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofMillis(config.getTimeoutMs()))
                .map(this::parseIpResponse)
                .onErrorResume(e -> {
                    log.warn("VirusTotal IP lookup failed for {}: {}", ipAddress, e.getMessage());
                    return Mono.just(ThreatIntelResult.unavailable("virustotal"));
                });
    }

    private ThreatIntelResult parseFileResponse(String body) {
        try {
            JsonNode root = objectMapper.readTree(body);
            JsonNode attrs = root.path("data").path("attributes");
            JsonNode lastAnalysis = attrs.path("last_analysis_stats");

            int malicious = lastAnalysis.path("malicious").asInt(0);
            int suspicious = lastAnalysis.path("suspicious").asInt(0);
            int total = lastAnalysis.path("malicious").asInt(0)
                    + lastAnalysis.path("undetected").asInt(0)
                    + lastAnalysis.path("harmless").asInt(0)
                    + suspicious;

            double score = total > 0 ? (double) (malicious + suspicious) / total : 0.0;
            boolean isMalicious = malicious > 3;

            Map<String, Object> details = new HashMap<>();
            details.put("malicious_detections", malicious);
            details.put("suspicious_detections", suspicious);
            details.put("total_engines", total);
            details.put("reputation", attrs.path("reputation").asInt(0));

            return isMalicious
                    ? ThreatIntelResult.malicious("virustotal", score, details)
                    : ThreatIntelResult.clean("virustotal");

        } catch (Exception e) {
            log.error("Failed to parse VirusTotal response: {}", e.getMessage());
            return ThreatIntelResult.unavailable("virustotal");
        }
    }

    private ThreatIntelResult parseIpResponse(String body) {
        try {
            JsonNode root = objectMapper.readTree(body);
            JsonNode attrs = root.path("data").path("attributes");
            JsonNode lastAnalysis = attrs.path("last_analysis_stats");

            int malicious = lastAnalysis.path("malicious").asInt(0);
            int suspicious = lastAnalysis.path("suspicious").asInt(0);
            int total = malicious + suspicious
                    + lastAnalysis.path("harmless").asInt(0)
                    + lastAnalysis.path("undetected").asInt(0);

            double score = total > 0 ? (double) (malicious + suspicious) / total : 0.0;
            boolean isMalicious = malicious > 2;

            Map<String, Object> details = new HashMap<>();
            details.put("malicious_detections", malicious);
            details.put("country", attrs.path("country").asText("unknown"));
            details.put("as_owner", attrs.path("as_owner").asText("unknown"));
            details.put("reputation", attrs.path("reputation").asInt(0));

            return isMalicious
                    ? ThreatIntelResult.malicious("virustotal", score, details)
                    : ThreatIntelResult.clean("virustotal");

        } catch (Exception e) {
            log.error("Failed to parse VirusTotal IP response: {}", e.getMessage());
            return ThreatIntelResult.unavailable("virustotal");
        }
    }
}
