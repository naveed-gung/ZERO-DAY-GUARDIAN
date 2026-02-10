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
 * AlienVault OTX (Open Threat Exchange) API v1 client.
 *
 * @see <a href="https://otx.alienvault.com/api">OTX API Documentation</a>
 * @author Naveed Gung
 */
@Component
public class AlienVaultOTXClient {

    private static final Logger log = LoggerFactory.getLogger(AlienVaultOTXClient.class);

    private final WebClient webClient;
    private final ThreatIntelConfig.AlienVaultOTX config;
    private final ObjectMapper objectMapper;

    public AlienVaultOTXClient(ThreatIntelConfig threatIntelConfig, ObjectMapper objectMapper) {
        this.config = threatIntelConfig.getOtx();
        this.objectMapper = objectMapper;
        this.webClient = WebClient.builder()
                .baseUrl(config.getBaseUrl())
                .defaultHeader("X-OTX-API-KEY", config.getApiKey())
                .defaultHeader("Accept", "application/json")
                .build();
    }

    /**
     * Look up an IPv4 indicator for associated threat pulses.
     *
     * @param ipAddress the IP to look up
     * @return the threat intel result
     */
    public Mono<ThreatIntelResult> lookupIp(String ipAddress) {
        return webClient.get()
                .uri("/indicators/IPv4/{ip}/general", ipAddress)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofMillis(config.getTimeoutMs()))
                .map(body -> parseIpResponse(body, ipAddress))
                .onErrorResume(e -> {
                    log.warn("OTX IP lookup failed for {}: {}", ipAddress, e.getMessage());
                    return Mono.just(ThreatIntelResult.unavailable("otx"));
                });
    }

    /**
     * Look up a file hash indicator.
     *
     * @param fileHash SHA-256, SHA-1, or MD5 hash
     * @return the threat intel result
     */
    public Mono<ThreatIntelResult> lookupFileHash(String fileHash) {
        return webClient.get()
                .uri("/indicators/file/{hash}/general", fileHash)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofMillis(config.getTimeoutMs()))
                .map(body -> parseFileResponse(body, fileHash))
                .onErrorResume(e -> {
                    log.warn("OTX file lookup failed for {}: {}", fileHash, e.getMessage());
                    return Mono.just(ThreatIntelResult.unavailable("otx"));
                });
    }

    /**
     * Look up a domain indicator.
     *
     * @param domain the domain name to look up
     * @return the threat intel result
     */
    public Mono<ThreatIntelResult> lookupDomain(String domain) {
        return webClient.get()
                .uri("/indicators/domain/{domain}/general", domain)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofMillis(config.getTimeoutMs()))
                .map(body -> parseDomainResponse(body, domain))
                .onErrorResume(e -> {
                    log.warn("OTX domain lookup failed for {}: {}", domain, e.getMessage());
                    return Mono.just(ThreatIntelResult.unavailable("otx"));
                });
    }

    private ThreatIntelResult parseIpResponse(String body, String ip) {
        try {
            JsonNode root = objectMapper.readTree(body);
            int pulseCount = root.path("pulse_info").path("count").asInt(0);
            double reputation = root.path("reputation").asDouble(0.0);

            boolean isMalicious = pulseCount > 2 || reputation < -1.0;
            double score = Math.min(1.0, pulseCount / 10.0);

            Map<String, Object> details = new HashMap<>();
            details.put("pulse_count", pulseCount);
            details.put("reputation", reputation);
            details.put("country", root.path("country_name").asText("unknown"));
            details.put("asn", root.path("asn").asText("unknown"));

            return isMalicious
                    ? ThreatIntelResult.malicious("otx", score, details)
                    : ThreatIntelResult.clean("otx");

        } catch (Exception e) {
            log.error("Failed to parse OTX IP response for {}: {}", ip, e.getMessage());
            return ThreatIntelResult.unavailable("otx");
        }
    }

    private ThreatIntelResult parseFileResponse(String body, String hash) {
        try {
            JsonNode root = objectMapper.readTree(body);
            int pulseCount = root.path("pulse_info").path("count").asInt(0);

            boolean isMalicious = pulseCount > 0;
            double score = Math.min(1.0, pulseCount / 5.0);

            Map<String, Object> details = new HashMap<>();
            details.put("pulse_count", pulseCount);

            JsonNode analysis = root.path("analysis");
            if (!analysis.isMissingNode()) {
                details.put("analysis_info", analysis.path("info").asText("none"));
            }

            return isMalicious
                    ? ThreatIntelResult.malicious("otx", score, details)
                    : ThreatIntelResult.clean("otx");

        } catch (Exception e) {
            log.error("Failed to parse OTX file response for {}: {}", hash, e.getMessage());
            return ThreatIntelResult.unavailable("otx");
        }
    }

    private ThreatIntelResult parseDomainResponse(String body, String domain) {
        try {
            JsonNode root = objectMapper.readTree(body);
            int pulseCount = root.path("pulse_info").path("count").asInt(0);

            boolean isMalicious = pulseCount > 1;
            double score = Math.min(1.0, pulseCount / 5.0);

            Map<String, Object> details = new HashMap<>();
            details.put("pulse_count", pulseCount);

            return isMalicious
                    ? ThreatIntelResult.malicious("otx", score, details)
                    : ThreatIntelResult.clean("otx");

        } catch (Exception e) {
            log.error("Failed to parse OTX domain response for {}: {}", domain, e.getMessage());
            return ThreatIntelResult.unavailable("otx");
        }
    }
}
