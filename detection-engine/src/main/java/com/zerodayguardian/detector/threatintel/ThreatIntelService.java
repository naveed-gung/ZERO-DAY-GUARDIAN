package com.zerodayguardian.detector.threatintel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Facade that aggregates results from all threat intelligence providers.
 *
 * <p>
 * Queries all providers in parallel via reactive streams, collecting and
 * merging results. A consensus algorithm determines the final verdict.
 * </p>
 *
 * @author Naveed Gung
 */
@Service
public class ThreatIntelService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelService.class);

    private final VirusTotalClient virusTotalClient;
    private final AbuseIPDBClient abuseIPDBClient;
    private final AlienVaultOTXClient otxClient;

    public ThreatIntelService(
            VirusTotalClient virusTotalClient,
            AbuseIPDBClient abuseIPDBClient,
            AlienVaultOTXClient otxClient) {
        this.virusTotalClient = virusTotalClient;
        this.abuseIPDBClient = abuseIPDBClient;
        this.otxClient = otxClient;
    }

    /**
     * Lookup an IP address across all providers in parallel.
     *
     * @param ipAddress the IP to check
     * @return aggregated list of results from all providers
     */
    public Mono<List<ThreatIntelResult>> lookupIp(String ipAddress) {
        log.debug("Starting parallel IP lookup for {}", ipAddress);

        return Flux.merge(
                virusTotalClient.lookupIp(ipAddress),
                abuseIPDBClient.checkIp(ipAddress),
                otxClient.lookupIp(ipAddress)).collectList();
    }

    /**
     * Lookup a file hash across all providers in parallel.
     *
     * @param fileHash SHA-256, SHA-1, or MD5 hash
     * @return aggregated list of results
     */
    public Mono<List<ThreatIntelResult>> lookupFileHash(String fileHash) {
        log.debug("Starting parallel file hash lookup for {}", fileHash);

        return Flux.merge(
                virusTotalClient.lookupFileHash(fileHash),
                otxClient.lookupFileHash(fileHash)).collectList();
    }

    /**
     * Determine if any provider flagged the IP as malicious.
     *
     * @param ipAddress the IP to check
     * @return true if at least one provider reports malicious
     */
    public Mono<Boolean> isIpMalicious(String ipAddress) {
        return lookupIp(ipAddress)
                .map(results -> results.stream().anyMatch(ThreatIntelResult::isMalicious));
    }

    /**
     * Compute a consensus score from multiple provider results.
     *
     * <p>
     * Weighted average: VirusTotal (0.4), AbuseIPDB (0.35), OTX (0.25).
     * </p>
     *
     * @param results the list of results from all providers
     * @return consensus score in [0.0, 1.0]
     */
    public static double consensusScore(List<ThreatIntelResult> results) {
        if (results.isEmpty())
            return 0.0;

        double totalWeight = 0;
        double weightedScore = 0;

        for (ThreatIntelResult result : results) {
            double weight = switch (result.source()) {
                case "virustotal" -> 0.4;
                case "abuseipdb" -> 0.35;
                case "otx" -> 0.25;
                default -> 0.1;
            };

            // Skip unavailable providers
            if (result.details().containsKey("status")
                    && "unavailable".equals(result.details().get("status"))) {
                continue;
            }

            totalWeight += weight;
            weightedScore += weight * result.score();
        }

        return totalWeight > 0 ? weightedScore / totalWeight : 0.0;
    }
}
