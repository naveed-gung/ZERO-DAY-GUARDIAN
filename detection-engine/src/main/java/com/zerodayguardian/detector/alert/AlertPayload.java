package com.zerodayguardian.detector.alert;

import com.zerodayguardian.detector.detection.DetectionResult;
import com.zerodayguardian.detector.event.SyscallEvent;

import java.time.Instant;
import java.util.Map;

/**
 * Structured alert payload sent to SIEM integrations.
 *
 * @author Naveed Gung
 */
public record AlertPayload(
                String alertId,
                Instant timestamp,
                String severity,
                String category,
                String detail,
                double score,
                String mitreAttackId,
                int pid,
                int uid,
                String comm,
                String filename,
                String containerId,
                String eventType,
                boolean fromContainer,
                boolean privileged,
                Map<String, String> metadata) {
        /**
         * Build an alert payload from an event and detection result.
         */
        public static AlertPayload from(SyscallEvent event, DetectionResult result) {
                String alertId = String.format("ZDG-%d-%s-%d",
                                System.currentTimeMillis(), result.category(), event.pid());

                return new AlertPayload(
                                alertId,
                                Instant.now(),
                                result.severity().name(),
                                result.category(),
                                result.detail(),
                                result.score(),
                                result.mitreAttackId(),
                                event.pid(),
                                event.uid(),
                                event.comm(),
                                event.filename(),
                                event.containerId(),
                                event.eventType().name(),
                                event.isFromContainer(),
                                event.isPrivileged(),
                                Map.of(
                                                "tgid", String.valueOf(event.tgid()),
                                                "gid", String.valueOf(event.gid()),
                                                "cgroup_id", String.valueOf(event.cgroupId())));
        }
}
