package com.zerodayguardian.detector.detection;

import com.zerodayguardian.detector.detection.AttackDetector.Detector;
import com.zerodayguardian.detector.event.EventType;
import com.zerodayguardian.detector.event.SyscallEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Detects lateral movement patterns within a Kubernetes cluster.
 *
 * <p>
 * Monitors for signs of an attacker pivoting from a compromised container
 * to other cluster resources:
 * </p>
 * <ul>
 * <li>Kubernetes API discovery tools (kubectl, curl to API server)</li>
 * <li>Service account token access</li>
 * <li>Network reconnaissance (nmap, masscan, etc.)</li>
 * <li>SSH/remote execution tools from containers</li>
 * <li>Cloud metadata endpoint access (169.254.169.254)</li>
 * </ul>
 *
 * @author Naveed Gung
 */
@Component
@Order(3)
public class LateralMovementDetector implements Detector {

    private static final Logger log = LoggerFactory.getLogger(LateralMovementDetector.class);

    /** Kubernetes API interaction indicators. */
    private static final Set<String> K8S_TOOLS = Set.of(
            "kubectl", "kubelet", "kubeadm", "helm",
            "kube-proxy", "crictl", "calicoctl");

    /** Network reconnaissance tools. */
    private static final Set<String> RECON_TOOLS = Set.of(
            "nmap", "masscan", "zmap", "netcat", "nc",
            "ncat", "socat", "hping3", "arp-scan");

    /** Remote execution / pivoting tools. */
    private static final Set<String> PIVOT_TOOLS = Set.of(
            "ssh", "sshd", "scp", "sftp",
            "psexec", "proxychains", "chisel",
            "ligolo", "plink");

    /** Service account token paths. */
    private static final Set<String> TOKEN_PATHS = Set.of(
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace");

    /** Track container API access for correlation. */
    private final Map<String, AtomicLong> apiAccessCount = new ConcurrentHashMap<>();

    @Override
    public DetectionResult analyze(SyscallEvent event) {
        if (!event.isFromContainer()) {
            return DetectionResult.clean();
        }

        return switch (event.eventType()) {
            case EXECVE -> analyzeExecve(event);
            case NETWORK -> analyzeNetwork(event);
            default -> DetectionResult.clean();
        };
    }

    private DetectionResult analyzeExecve(SyscallEvent event) {
        String comm = event.comm().toLowerCase();
        String filename = event.filename().toLowerCase();

        // Kubernetes API tools inside a container (MITRE T1613 - Container and Resource
        // Discovery)
        for (String tool : K8S_TOOLS) {
            if (comm.equals(tool) || filename.endsWith("/" + tool)) {
                trackApiAccess(event.containerId());
                return DetectionResult.threat(
                        DetectionResult.Severity.HIGH,
                        "lateral-movement",
                        String.format("Kubernetes tool execution in container: %s executing %s (container=%s, pid=%d)",
                                event.comm(), event.filename(), event.containerId(), event.pid()),
                        0.85,
                        "T1613");
            }
        }

        // Network reconnaissance (MITRE T1046 - Network Service Discovery)
        for (String tool : RECON_TOOLS) {
            if (comm.equals(tool) || filename.endsWith("/" + tool)) {
                return DetectionResult.threat(
                        DetectionResult.Severity.HIGH,
                        "lateral-movement",
                        String.format("Network reconnaissance from container: %s (container=%s, pid=%d)",
                                event.comm(), event.containerId(), event.pid()),
                        0.90,
                        "T1046");
            }
        }

        // Remote execution / pivoting (MITRE T1021 - Remote Services)
        for (String tool : PIVOT_TOOLS) {
            if (comm.equals(tool) || filename.endsWith("/" + tool)) {
                return DetectionResult.threat(
                        DetectionResult.Severity.CRITICAL,
                        "lateral-movement",
                        String.format("Pivot tool execution in container: %s (container=%s, pid=%d)",
                                event.comm(), event.containerId(), event.pid()),
                        0.92,
                        "T1021");
            }
        }

        // Service account token access (MITRE T1528 - Steal Application Access Token)
        for (String tokenPath : TOKEN_PATHS) {
            if (filename.equals(tokenPath)) {
                trackApiAccess(event.containerId());
                return DetectionResult.threat(
                        DetectionResult.Severity.MEDIUM,
                        "lateral-movement",
                        String.format("Service account token read in container: %s accessing %s (pid=%d)",
                                event.comm(), event.filename(), event.pid()),
                        0.70,
                        "T1528");
            }
        }

        // Cloud metadata endpoint probing (MITRE T1552.005 - Cloud Instance Metadata
        // API)
        if (filename.contains("169.254.169.254") || filename.contains("metadata.google.internal")) {
            return DetectionResult.threat(
                    DetectionResult.Severity.HIGH,
                    "lateral-movement",
                    String.format("Cloud metadata endpoint access from container: %s (container=%s, pid=%d)",
                            event.comm(), event.containerId(), event.pid()),
                    0.88,
                    "T1552.005");
        }

        return DetectionResult.clean();
    }

    private DetectionResult analyzeNetwork(SyscallEvent event) {
        // DNS tunneling / suspicious network activity (MITRE T1572 - Protocol
        // Tunneling)
        if (event.isSuspicious()) {
            return DetectionResult.threat(
                    DetectionResult.Severity.HIGH,
                    "lateral-movement",
                    String.format("Suspicious network activity from container %s (pid=%d, comm=%s)",
                            event.containerId(), event.pid(), event.comm()),
                    0.80,
                    "T1572");
        }
        return DetectionResult.clean();
    }

    private void trackApiAccess(String containerId) {
        if (containerId != null && !containerId.isEmpty()) {
            apiAccessCount.computeIfAbsent(containerId, k -> new AtomicLong(0)).incrementAndGet();
        }
    }

    /**
     * Returns the number of K8s API access events for a container.
     */
    public long getApiAccessCount(String containerId) {
        AtomicLong count = apiAccessCount.get(containerId);
        return count != null ? count.get() : 0;
    }

    /** Periodic reset of tracking state. */
    public void resetCounters() {
        apiAccessCount.clear();
    }
}
