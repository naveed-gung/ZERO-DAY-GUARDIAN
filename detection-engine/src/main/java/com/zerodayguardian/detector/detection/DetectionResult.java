package com.zerodayguardian.detector.detection;

import com.zerodayguardian.detector.event.SyscallEvent;

/**
 * Result of a detection analysis on a single event.
 *
 * @param detected whether the event triggered a detection
 * @param severity severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
 * @param category attack category identifier
 * @param detail   human-readable explanation of the detection
 * @param score    confidence score in [0.0, 1.0]
 *
 * @author Naveed Gung
 */
public record DetectionResult(
        boolean detected,
        Severity severity,
        String category,
        String detail,
        double score,
        String mitreAttackId) {

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW, INFO
    }

    /** Factory for a clean (non-detection) result. */
    public static DetectionResult clean() {
        return new DetectionResult(false, Severity.INFO, "none", "No threat detected", 0.0, null);
    }

    /** Factory for a positive detection. */
    public static DetectionResult threat(Severity severity, String category, String detail, double score) {
        return new DetectionResult(true, severity, category, detail, Math.min(1.0, Math.max(0.0, score)), null);
    }

    /** Factory for a positive detection with MITRE ATT&CK technique mapping. */
    public static DetectionResult threat(Severity severity, String category, String detail, double score,
            String mitreAttackId) {
        return new DetectionResult(true, severity, category, detail, Math.min(1.0, Math.max(0.0, score)),
                mitreAttackId);
    }
}
