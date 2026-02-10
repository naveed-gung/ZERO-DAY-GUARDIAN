package com.zerodayguardian.detector.detection;

import com.zerodayguardian.detector.detection.AttackDetector.Detector;
import com.zerodayguardian.detector.event.EventType;
import com.zerodayguardian.detector.event.SyscallEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Detects container escape attempts.
 *
 * <p>
 * Heuristics based on known CVEs (CVE-2019-5736, CVE-2020-15257,
 * CVE-2022-0185) and common escape patterns:
 * </p>
 * <ul>
 * <li>Execution of sensitive binaries from within a container</li>
 * <li>Namespace manipulation (CLONE_NEWUSER, CLONE_NEWNS) from containers</li>
 * <li>Suspicious mount operations from container context</li>
 * <li>ptrace from container targeting host-namespace processes</li>
 * </ul>
 *
 * @author Naveed Gung
 */
@Component
@Order(1)
public class ContainerEscapeDetector implements Detector {

        private static final Logger log = LoggerFactory.getLogger(ContainerEscapeDetector.class);

        /** Binaries that should never execute inside a container. */
        private static final Set<String> ESCAPE_BINARIES = Set.of(
                        "/proc/self/exe",
                        "runc",
                        "/usr/bin/runc",
                        "/usr/sbin/runc",
                        "/usr/bin/containerd-shim",
                        "/usr/bin/dockerd",
                        "/usr/bin/ctr",
                        "nsenter",
                        "/usr/bin/nsenter",
                        "/usr/sbin/nsenter",
                        "unshare",
                        "/usr/bin/unshare");

        /** Mount targets that indicate escape attempts. */
        private static final Set<String> SUSPICIOUS_MOUNT_TARGETS = Set.of(
                        "/",
                        "/proc",
                        "/sys",
                        "/dev",
                        "/etc",
                        "/var/run/docker.sock",
                        "/run/containerd/containerd.sock");

        @Override
        public DetectionResult analyze(SyscallEvent event) {
                if (!event.isFromContainer()) {
                        return DetectionResult.clean();
                }

                return switch (event.eventType()) {
                        case EXECVE -> analyzeExecve(event);
                        case UNSHARE -> analyzeUnshare(event);
                        case MOUNT -> analyzeMount(event);
                        case PTRACE -> analyzePtrace(event);
                        case INIT_MODULE -> analyzeInitModule(event);
                        default -> DetectionResult.clean();
                };
        }

        private DetectionResult analyzeExecve(SyscallEvent event) {
                String filename = event.filename().toLowerCase();

                // CVE-2019-5736: overwriting host runc binary (MITRE T1611)
                if (filename.contains("/proc/self/exe") || filename.endsWith("/runc")) {
                        return DetectionResult.threat(
                                        DetectionResult.Severity.CRITICAL,
                                        "container-escape",
                                        String.format("Possible CVE-2019-5736: container process %s (pid=%d) executing %s",
                                                        event.comm(), event.pid(), event.filename()),
                                        0.95,
                                        "T1611");
                }

                // Execution of host runtime binaries from container
                for (String binary : ESCAPE_BINARIES) {
                        if (filename.equals(binary) || filename.endsWith("/" + binary)) {
                                return DetectionResult.threat(
                                                DetectionResult.Severity.HIGH,
                                                "container-escape",
                                                String.format("Sensitive binary execution from container: %s by %s (pid=%d)",
                                                                event.filename(), event.comm(), event.pid()),
                                                0.85);
                        }
                }

                // Privileged container executing suspicious tools
                if (event.isPrivileged() && (filename.contains("mount") || filename.contains("fdisk")
                                || filename.contains("mkfs") || filename.contains("debugfs"))) {
                        return DetectionResult.threat(
                                        DetectionResult.Severity.HIGH,
                                        "container-escape",
                                        String.format("Privileged container executing disk tool: %s by %s (pid=%d)",
                                                        event.filename(), event.comm(), event.pid()),
                                        0.80);
                }

                return DetectionResult.clean();
        }

        private DetectionResult analyzeUnshare(SyscallEvent event) {
                // Any namespace manipulation from inside a container is suspicious (MITRE
                // T1611)
                return DetectionResult.threat(
                                DetectionResult.Severity.HIGH,
                                "container-escape",
                                String.format("Namespace manipulation from container: %s (pid=%d, flags=0x%x)",
                                                event.comm(), event.pid(), event.flags()),
                                0.90,
                                "T1611");
        }

        private DetectionResult analyzeMount(SyscallEvent event) {
                String target = event.filename();
                for (String suspicious : SUSPICIOUS_MOUNT_TARGETS) {
                        if (target.equals(suspicious) || target.startsWith(suspicious + "/")) {
                                return DetectionResult.threat(
                                                DetectionResult.Severity.CRITICAL,
                                                "container-escape",
                                                String.format("Container mount to sensitive path: %s by %s (pid=%d)",
                                                                target, event.comm(), event.pid()),
                                                0.92,
                                                "T1611");
                        }
                }

                // Any mount from non-privileged container is notable
                if (!event.isPrivileged()) {
                        return DetectionResult.threat(
                                        DetectionResult.Severity.MEDIUM,
                                        "container-escape",
                                        String.format("Unexpected mount from non-privileged container: %s by %s (pid=%d)",
                                                        target, event.comm(), event.pid()),
                                        0.60);
                }

                return DetectionResult.clean();
        }

        private DetectionResult analyzePtrace(SyscallEvent event) {
                // ptrace from container is always suspicious (MITRE T1055 - Process Injection)
                return DetectionResult.threat(
                                DetectionResult.Severity.HIGH,
                                "container-escape",
                                String.format("ptrace from container context: %s (pid=%d, uid=%d)",
                                                event.comm(), event.pid(), event.uid()),
                                0.85,
                                "T1055");
        }

        /**
         * Kernel module loading from a container is a critical escape vector.
         * A container should never load kernel modules; this indicates an attempt
         * to gain host-level code execution.
         */
        private DetectionResult analyzeInitModule(SyscallEvent event) {
                // MITRE T1611 - Escape to Host via kernel module loading
                return DetectionResult.threat(
                                DetectionResult.Severity.CRITICAL,
                                "container-escape",
                                String.format("Kernel module loading from container: %s (pid=%d, uid=%d)",
                                                event.comm(), event.pid(), event.uid()),
                                0.98,
                                "T1611");
        }
}
