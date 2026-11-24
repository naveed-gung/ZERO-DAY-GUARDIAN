package com.zerodayguardian.detector.action;

import com.zerodayguardian.detector.detection.DetectionResult;
import com.zerodayguardian.detector.event.SyscallEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * Safety-gated action executor implementing SRS Section 8 requirements.
 *
 * <p>
 * All automated responses pass through the following safety gates:
 * </p>
 * <ol>
 * <li><b>Namespace exclusion:</b> kube-system, kube-public, and
 * admin-configured namespaces
 * are never targeted for automated isolation.</li>
 * <li><b>Approval list:</b> only namespaces in the approved list can receive
 * automated actions.</li>
 * <li><b>Rate limiting:</b> at most N actions per minute to prevent cascading
 * failures.</li>
 * <li><b>Dry-run mode:</b> when enabled, log the action without executing
 * it.</li>
 * <li><b>Severity threshold:</b> only HIGH or CRITICAL detections trigger
 * automated response.</li>
 * </ol>
 *
 * @author Naveed Gung
 */
@Component
public class SafeActionExecutor {

    private static final Logger log = LoggerFactory.getLogger(SafeActionExecutor.class);

    private final PodIsolator podIsolator;
    private final ActionTracker actionTracker;
    private final MeterRegistry meterRegistry;

    @Value("${guardian.action.dry-run:true}")
    private boolean dryRun;

    @Value("${guardian.action.rate-limit-per-minute:10}")
    private int rateLimitPerMinute;

    @Value("#{'${guardian.action.approved-namespaces:}'.split(',')}")
    private List<String> approvedNamespaces;

    @Value("#{'${guardian.action.excluded-namespaces:kube-system,kube-public,kube-node-lease}'.split(',')}")
    private List<String> excludedNamespaces;

    /** System-level namespaces that can never be targeted for automated actions. */
    private static final Set<String> IMMUTABLE_EXCLUSIONS = Set.of(
            "kube-system", "kube-public", "kube-node-lease", "guardian-system");

    @Value("${guardian.node.name:unknown}")
    private String nodeName;

    private Counter actionsExecuted;
    private Counter actionsBlocked;
    private Counter actionsDryRun;

    public SafeActionExecutor(
            PodIsolator podIsolator,
            ActionTracker actionTracker,
            MeterRegistry meterRegistry) {
        this.podIsolator = podIsolator;
        this.actionTracker = actionTracker;
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void init() {
        actionsExecuted = Counter.builder("guardian.action.executed")
                .description("Automated response actions executed")
                .register(meterRegistry);
        actionsBlocked = Counter.builder("guardian.action.blocked")
                .description("Actions blocked by safety gates")
                .register(meterRegistry);
        actionsDryRun = Counter.builder("guardian.action.dry_run")
                .description("Response candidates recorded in observe-only mode")
                .register(meterRegistry);

        log.info("SafeActionExecutor initialized: dryRun={}, rateLimit={}/min, approved={}, excluded={}",
                dryRun, rateLimitPerMinute, approvedNamespaces, excludedNamespaces);
    }

    /**
     * Evaluate and optionally execute an automated response to a threat detection.
     *
     * @param event  the triggering event
     * @param result the detection result
     */
    public void executeResponse(SyscallEvent event, DetectionResult result) {
        // Gate 1: Severity threshold - only HIGH and CRITICAL get automated response
        if (result.severity() != DetectionResult.Severity.CRITICAL
                && result.severity() != DetectionResult.Severity.HIGH) {
            log.debug("Skipping action for sub-threshold severity: {}", result.severity());
            return;
        }

        if (dryRun) {
            actionsDryRun.increment();
            actionTracker.record(event, result, "OBSERVE_ONLY");
            return;
        }

        var namespaces = approvedNamespaces.stream()
                .map(String::trim)
                .filter(namespace -> !namespace.isEmpty())
                .filter(namespace -> !IMMUTABLE_EXCLUSIONS.contains(namespace))
                .filter(namespace -> excludedNamespaces.stream().noneMatch(excluded -> excluded.trim().equals(namespace)))
                .distinct()
                .toList();
        if (namespaces.isEmpty() || !event.isFromContainer()) {
            actionsBlocked.increment();
            actionTracker.record(event, result, "BLOCKED_SCOPE");
            return;
        }
        if (!actionTracker.tryAcquire()) {
            actionsBlocked.increment();
            actionTracker.record(event, result, "RATE_LIMITED");
            return;
        }

        try {
            var target = podIsolator.resolve(event.containerId(), nodeName, namespaces);
            if (target.isEmpty()) {
                actionsBlocked.increment();
                actionTracker.record(event, result, "TARGET_UNRESOLVED");
                return;
            }

            var pod = target.get();
            boolean applied = podIsolator.labelPod(pod);
            if (applied) {
                actionsExecuted.increment();
            }
            log.info("Response target namespace={} pod={} uid={} labelApplied={}",
                    pod.getMetadata().getNamespace(), pod.getMetadata().getName(),
                    pod.getMetadata().getUid(), applied);
            actionTracker.record(event, result, applied ? "LABEL_APPLIED" : "ALREADY_LABELED");
        } catch (io.kubernetes.client.openapi.ApiException e) {
            actionTracker.record(event, result, "KUBERNETES_API_ERROR_" + e.getCode());
            log.warn("Kubernetes response request failed (status={})", e.getCode());
        }
    }
}
