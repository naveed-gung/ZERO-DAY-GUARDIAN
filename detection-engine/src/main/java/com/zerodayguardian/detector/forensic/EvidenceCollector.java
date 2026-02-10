package com.zerodayguardian.detector.forensic;

import com.zerodayguardian.detector.detection.DetectionResult;
import com.zerodayguardian.detector.event.SyscallEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Collects and preserves forensic evidence from security incidents.
 *
 * <p>
 * Evidence is written to a structured directory hierarchy for
 * post-incident analysis and compliance requirements.
 * </p>
 *
 * <p>
 * Directory structure:
 * </p>
 * 
 * <pre>
 * {evidence-path}/
 *   {date}/
 *     {alert-id}/
 *       event.json      - Raw event data
 *       detection.json   - Detection metadata
 *       timeline.log     - Chronological event log
 * </pre>
 *
 * @author Naveed Gung
 */
@Component
public class EvidenceCollector {

    private static final Logger log = LoggerFactory.getLogger(EvidenceCollector.class);

    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    @Value("${guardian.forensic.evidence-path:/var/guardian/evidence}")
    private String evidencePath;

    @Value("${guardian.forensic.retention-days:90}")
    private int retentionDays;

    private final MeterRegistry meterRegistry;
    private Counter evidenceCollected;

    public EvidenceCollector(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void init() {
        evidenceCollected = Counter.builder("guardian.forensic.evidence.collected")
                .description("Total evidence artifacts collected")
                .register(meterRegistry);

        Path basePath = Path.of(evidencePath);
        try {
            Files.createDirectories(basePath);
            log.info("Forensic evidence directory: {} (retention={} days)", evidencePath, retentionDays);
        } catch (IOException e) {
            log.error("Failed to create evidence directory {}: {}", evidencePath, e.getMessage());
        }
    }

    /**
     * Collect forensic evidence for a detected threat.
     *
     * @param event  the triggering event
     * @param result the detection result
     */
    public void collect(SyscallEvent event, DetectionResult result) {
        try {
            Instant now = Instant.now();
            String date = DATE_FMT.format(now.atZone(ZoneOffset.UTC));
            String alertId = String.format("ZDG-%d-%s-%d",
                    now.toEpochMilli(), result.category(), event.pid());

            Path incidentDir = Path.of(evidencePath, date, alertId);
            Files.createDirectories(incidentDir);

            // Write raw event data
            writeEventJson(incidentDir, event);

            // Write detection metadata
            writeDetectionJson(incidentDir, result);

            // Append to timeline
            appendTimeline(incidentDir, event, result, now);

            evidenceCollected.increment();
            log.debug("Evidence collected for alert {} at {}", alertId, incidentDir);

        } catch (Exception e) {
            log.error("Evidence collection failed for pid={}: {}", event.pid(), e.getMessage(), e);
        }
    }

    private void writeEventJson(Path dir, SyscallEvent event) throws IOException {
        String json = String.format("""
                {
                  "magic": "0x%08X",
                  "version": %d,
                  "event_type": "%s",
                  "flags": "0x%08X",
                  "timestamp_ns": %d,
                  "pid": %d,
                  "tgid": %d,
                  "uid": %d,
                  "gid": %d,
                  "comm": "%s",
                  "filename": "%s",
                  "cgroup_id": %d,
                  "container_id": "%s",
                  "from_container": %b,
                  "privileged": %b,
                  "host_namespace": %b,
                  "suspicious": %b
                }""",
                event.magic(), event.version(), event.eventType().name(),
                event.flags(), event.timestampNs(), event.pid(), event.tgid(),
                event.uid(), event.gid(), escapeJson(event.comm()),
                escapeJson(event.filename()), event.cgroupId(),
                escapeJson(event.containerId()), event.isFromContainer(),
                event.isPrivileged(), event.isHostNamespace(), event.isSuspicious());

        Files.writeString(dir.resolve("event.json"), json,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private void writeDetectionJson(Path dir, DetectionResult result) throws IOException {
        String json = String.format("""
                {
                  "detected": %b,
                  "severity": "%s",
                  "category": "%s",
                  "detail": "%s",
                  "score": %.4f,
                  "collected_at": "%s"
                }""",
                result.detected(), result.severity(), result.category(),
                escapeJson(result.detail()), result.score(), Instant.now().toString());

        Files.writeString(dir.resolve("detection.json"), json,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private void appendTimeline(Path dir, SyscallEvent event, DetectionResult result, Instant now)
            throws IOException {
        String time = TIME_FMT.format(now.atZone(ZoneOffset.UTC));
        String line = String.format("[%s] %s pid=%d comm=%s container=%s severity=%s detail=%s%n",
                time, event.eventType(), event.pid(), event.comm(),
                event.containerId(), result.severity(), result.detail());

        Files.writeString(dir.resolve("timeline.log"), line,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    private String escapeJson(String value) {
        if (value == null)
            return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
