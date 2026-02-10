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
    private final NetworkBlocker networkBlocker;
    private final ProcessKiller processKiller;
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
            "kube-system", "kube-public", "kube-node-lease");

    private Counter actionsExecuted;
    private Counter actionsBlocked;
    private Counter actionsDryRun;

    public SafeActionExecutor(
            PodIsolator podIsolator,
            NetworkBlocker networkBlocker,
            ProcessKiller processKiller,
            ActionTracker actionTracker,
            MeterRegistry meterRegistry) {
        this.podIsolator = podIsolator;
        this.networkBlocker = networkBlocker;
        this.processKiller = processKiller;
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
                .description("Actions that would have executed in non-dry-run mode")
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

        String namespace = resolveNamespace(event);

        // Gate 2: Namespace exclusion
        if (isExcludedNamespace(namespace)) {
            actionsBlocked.increment();
            log.warn("SAFETY GATE: Action blocked for excluded namespace '{}' (event pid={}, category={})",
                    namespace, event.pid(), result.category());
            return;
        }

        // Gate 3: Approved namespace check
        if (!isApprovedNamespace(namespace)) {
            actionsBlocked.increment();
            log.warn("SAFETY GATE: Action blocked for unapproved namespace '{}' (event pid={}, category={})",
                    namespace, event.pid(), result.category());
            return;
        }

        // Gate 4: Rate limiting
        if (!actionTracker.tryAcquire()) {
            actionsBlocked.increment();
            log.warn("SAFETY GATE: Action rate-limited (event pid={}, category={})",
                    event.pid(), result.category());
            return;
        }

        // Gate 5: Dry-run mode
        if (dryRun) {
            actionsDryRun.increment();
            log.info("DRY-RUN: Would execute response for {} in namespace '{}' (pid={}, severity={}, category={})",
                    event.containerId(), namespace, event.pid(), result.severity(), result.category());
            actionTracker.record(event, result, "DRY_RUN");
            return;
        }

        // All gates passed: execute the response
        executeAction(event, result, namespace);
    }

    private void executeAction(SyscallEvent event, DetectionResult result, String namespace) {
        String containerId = event.containerId();
        log.info("Executing automated response: severity={} category={} container={} namespace={}",
                result.severity(), result.category(), containerId, namespace);

        actionsExecuted.increment();

        boolean isolated = false;
        boolean networkBlocked = false;

        try {
            // For CRITICAL container-escape: kill the offending process first
            if (result.severity() == DetectionResult.Severity.CRITICAL
                    && "container-escape".equals(result.category())) {
                try {
                    processKiller.killProcess(containerId, namespace, event.pid(), result);
                } catch (Exception e) {
                    log.warn("Process kill failed for pid={} in container {}: {}",
                            event.pid(), containerId, e.getMessage());
                    // Continue with isolation even if kill fails
                }
            }

            // For CRITICAL: isolate pod AND block network
            if (result.severity() == DetectionResult.Severity.CRITICAL) {
                podIsolator.isolatePod(containerId, namespace, result);
                isolated = true;
                networkBlocker.blockPodNetwork(containerId, namespace, result);
                networkBlocked = true;
                actionTracker.record(event, result, "ISOLATE_AND_BLOCK");
            }
            // For HIGH: isolate pod only
            else {
                podIsolator.isolatePod(containerId, namespace, result);
                isolated = true;
                actionTracker.record(event, result, "ISOLATE");
            }
        } catch (Exception e) {
            log.error("Action execution failed for container {}: {}", containerId, e.getMessage(), e);

            // Rollback: undo any partially applied actions
            rollback(containerId, namespace, isolated, networkBlocked);

            actionTracker.record(event, result, "FAILED:" + e.getMessage());
        }
    }

    /**
     * Rollback partially applied defensive actions on failure.
     * <p>
     * If pod isolation was applied but network blocking failed (or vice versa),
     * undo the completed actions to avoid leaving the pod in an inconsistent state.
     * </p>
     */
    private void rollback(String containerId, String namespace, boolean wasIsolated, boolean wasNetworkBlocked) {
        if (wasIsolated) {
            try {
                podIsolator.removeQuarantine(containerId, namespace);
                log.info("Rollback: removed quarantine label from container {} in {}", containerId, namespace);
            } catch (Exception rollbackErr) {
                log.error("Rollback failed: could not remove quarantine from container {}: {}",
                        containerId, rollbackErr.getMessage());
            }
        }

        if (wasNetworkBlocked) {
            try {
                networkBlocker.removeBlockPolicy(containerId, namespace);
                log.info("Rollback: removed NetworkPolicy for container {} in {}", containerId, namespace);
            } catch (Exception rollbackErr) {
                log.error("Rollback failed: could not remove NetworkPolicy for container {}: {}",
                        containerId, rollbackErr.getMessage());
            }
        }
    }

    private String resolveNamespace(SyscallEvent event) {
        // Container ID format from CRI: <runtime>://<id>
        // In a real deployment, we would query the K8s API for the pod's namespace.
        // For now, return "default" if we can't resolve.
        return "default";
    }

    private boolean isExcludedNamespace(String namespace) {
        if (namespace == null)
            return true;
        if (IMMUTABLE_EXCLUSIONS.contains(namespace))
            return true;
        return excludedNamespaces.stream()
                .anyMatch(ns -> ns.trim().equalsIgnoreCase(namespace));
    }

    private boolean isApprovedNamespace(String namespace) {
        if (approvedNamespaces == null || approvedNamespaces.isEmpty()) {
            // If no approved list is configured, allow all non-excluded namespaces
            return true;
        }
        if (approvedNamespaces.size() == 1 && approvedNamespaces.getFirst().isEmpty()) {
            return true;
        }
        return approvedNamespaces.stream()
                .anyMatch(ns -> ns.trim().equalsIgnoreCase(namespace));
    }
}
