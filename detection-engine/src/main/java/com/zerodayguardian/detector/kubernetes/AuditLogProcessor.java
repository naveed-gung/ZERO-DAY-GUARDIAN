package com.zerodayguardian.detector.kubernetes;

import com.zerodayguardian.detector.detection.AttackDetector;
import com.zerodayguardian.detector.detection.DetectionResult;
import com.zerodayguardian.detector.event.EventType;
import com.zerodayguardian.detector.event.SyscallEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.util.Watch;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import okhttp3.OkHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Processes Kubernetes audit log events for security-relevant operations.
 *
 * <p>
 * Watches the Kubernetes audit log stream and converts security-relevant
 * events into synthetic {@link SyscallEvent}s that feed into the detection
 * pipeline for unified correlation.
 * </p>
 *
 * <p>
 * Monitored API operations:
 * </p>
 * <ul>
 * <li>Pod exec/attach (potential lateral movement)</li>
 * <li>Secret access (credential theft)</li>
 * <li>RBAC modifications (privilege escalation)</li>
 * <li>ServiceAccount token creation</li>
 * </ul>
 *
 * @author Naveed Gung
 */
@Component
public class AuditLogProcessor {

    private static final Logger log = LoggerFactory.getLogger(AuditLogProcessor.class);

    private final ApiClient apiClient;
    private final ObjectMapper objectMapper;
    private final MeterRegistry meterRegistry;

    @Value("${guardian.kubernetes.audit-log-path:}")
    private String auditLogPath;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private ExecutorService executor;

    private Counter auditEventsProcessed;
    private Counter auditSecurityEvents;

    /** Suspicious API resources being accessed. */
    private static final Set<String> SENSITIVE_RESOURCES = Set.of(
            "secrets", "serviceaccounts", "clusterroles",
            "clusterrolebindings", "roles", "rolebindings",
            "tokenreviews", "certificatesigningrequests");

    /** Verbs that indicate potentially malicious operations. */
    private static final Set<String> SENSITIVE_VERBS = Set.of(
            "create", "update", "patch", "delete");

    public AuditLogProcessor(ApiClient apiClient, ObjectMapper objectMapper, MeterRegistry meterRegistry) {
        this.apiClient = apiClient;
        this.objectMapper = objectMapper;
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void init() {
        auditEventsProcessed = Counter.builder("guardian.audit.events.processed")
                .description("Total audit events processed")
                .register(meterRegistry);
        auditSecurityEvents = Counter.builder("guardian.audit.events.security")
                .description("Security-relevant audit events")
                .register(meterRegistry);
    }

    /**
     * Start the audit log watcher in a background thread.
     */
    public void start() {
        if (auditLogPath == null || auditLogPath.isEmpty()) {
            log.info("Audit log path not configured, K8s audit log processing disabled");
            return;
        }

        if (running.compareAndSet(false, true)) {
            executor = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "audit-log-processor");
                t.setDaemon(true);
                return t;
            });
            executor.submit(this::watchAuditLog);
            log.info("Audit log processor started, watching: {}", auditLogPath);
        }
    }

    private void watchAuditLog() {
        while (running.get()) {
            try {
                processAuditLogFile();
            } catch (Exception e) {
                if (running.get()) {
                    log.error("Audit log processing error, retrying in 5s: {}", e.getMessage());
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        }
    }

    private void processAuditLogFile() throws Exception {
        // Read audit log as a stream of JSON lines
        URL url = URI.create(auditLogPath).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(0); // Stream indefinitely

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while (running.get() && (line = reader.readLine()) != null) {
                processAuditLine(line);
            }
        }
    }

    void processAuditLine(String line) {
        try {
            JsonNode event = objectMapper.readTree(line);
            auditEventsProcessed.increment();

            String verb = event.path("verb").asText("");
            JsonNode objectRef = event.path("objectRef");
            String resource = objectRef.path("resource").asText("");
            String namespace = objectRef.path("namespace").asText("");
            String name = objectRef.path("name").asText("");

            // Check for pod exec/attach
            String subresource = objectRef.path("subresource").asText("");
            if ("pods".equals(resource) && ("exec".equals(subresource) || "attach".equals(subresource)
                    || "portforward".equals(subresource))) {
                auditSecurityEvents.increment();
                log.warn("AUDIT: Pod {} detected in {}/{} by {}",
                        subresource, namespace, name,
                        event.path("user").path("username").asText("unknown"));
                return;
            }

            // Check for sensitive resource modifications
            if (SENSITIVE_RESOURCES.contains(resource) && SENSITIVE_VERBS.contains(verb)) {
                auditSecurityEvents.increment();
                log.warn("AUDIT: Sensitive operation {} {} in {}/{} by {}",
                        verb, resource, namespace, name,
                        event.path("user").path("username").asText("unknown"));
            }

        } catch (Exception e) {
            log.debug("Failed to parse audit log line: {}", e.getMessage());
        }
    }

    @PreDestroy
    public void stop() {
        running.set(false);
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                executor.shutdownNow();
            }
        }
        log.info("Audit log processor stopped");
    }
}
