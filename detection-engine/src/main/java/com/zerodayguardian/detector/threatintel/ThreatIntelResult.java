package com.zerodayguardian.detector.threatintel;

import java.util.Map;
import java.util.Optional;

/**
 * Unified threat intelligence lookup result from any provider.
 *
 * @param source      the provider name (e.g., "virustotal", "abuseipdb", "otx")
 * @param isMalicious whether the indicator was flagged as malicious
 * @param score       normalized threat score in [0.0, 1.0]
 * @param details     provider-specific response details
 *
 * @author Naveed Gung
 */
public record ThreatIntelResult(
        String source,
        boolean isMalicious,
        double score,
        Map<String, Object> details) {
    /** Factory for a clean (non-malicious) result. */
    public static ThreatIntelResult clean(String source) {
        return new ThreatIntelResult(source, false, 0.0, Map.of());
    }

    /** Factory for a malicious result. */
    public static ThreatIntelResult malicious(String source, double score, Map<String, Object> details) {
        return new ThreatIntelResult(source, true, Math.min(1.0, Math.max(0.0, score)), details);
    }

    /** Factory for a provider-unavailable result. */
    public static ThreatIntelResult unavailable(String source) {
        return new ThreatIntelResult(source, false, 0.0, Map.of("status", "unavailable"));
    }
}
