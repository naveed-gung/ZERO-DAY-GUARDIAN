package com.zerodayguardian.detector.detection;

import com.zerodayguardian.detector.detection.AttackDetector.Detector;
import com.zerodayguardian.detector.event.EventType;
import com.zerodayguardian.detector.event.SyscallEvent;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Detects cryptojacking activity in containers.
 *
 * <p>
 * Detection heuristics:
 * </p>
 * <ul>
 * <li>Known cryptocurrency miner binary names</li>
 * <li>Connections to known mining pool ports</li>
 * <li>Execution of mining-related command patterns</li>
 * <li>Rapid process spawning (fork-bomb style miners)</li>
 * </ul>
 *
 * @author Naveed Gung
 */
@Component
@Order(2)
public class CryptojackingDetector implements Detector {

    private static final Logger log = LoggerFactory.getLogger(CryptojackingDetector.class);

    /** Known miner binary names or keywords in filenames. */
    private static final Set<String> MINER_INDICATORS = Set.of(
            "xmrig", "xmr-stak", "minerd", "minergate",
            "cpuminer", "cgminer", "bfgminer", "ethminer",
            "nbminer", "t-rex", "phoenixminer", "lolminer",
            "gminer", "ccminer", "nheqminer", "sgminer",
            "kryptex", "nicehash", "stratum+tcp",
            "randomx", "cryptonight", "kawpow");

    /** Common mining pool ports (Stratum protocol). */
    private static final Set<Integer> MINING_POOL_PORTS = Set.of(
            3333, 4444, 5555, 7777, 8888, 9999,
            14433, 14444, 45560, 45700);

    /** Track exec count per container for fork-bomb detection. */
    private final Map<String, AtomicInteger> execCounters = new ConcurrentHashMap<>();

    /** Threshold: execs per container within the counter window. */
    private static final int RAPID_EXEC_THRESHOLD = 50;

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
        String filename = event.filename().toLowerCase();
        String comm = event.comm().toLowerCase();

        // Direct miner binary detection (MITRE T1496 - Resource Hijacking)
        for (String indicator : MINER_INDICATORS) {
            if (filename.contains(indicator) || comm.contains(indicator)) {
                return DetectionResult.threat(
                        DetectionResult.Severity.CRITICAL,
                        "cryptojacking",
                        String.format("Cryptocurrency miner detected: %s executing %s in container %s (pid=%d)",
                                event.comm(), event.filename(), event.containerId(), event.pid()),
                        0.95,
                        "T1496");
            }
        }

        // Suspicious download-and-execute pattern (common miner dropper)
        if ((comm.equals("curl") || comm.equals("wget")) && event.isSuspicious()) {
            return DetectionResult.threat(
                    DetectionResult.Severity.MEDIUM,
                    "cryptojacking",
                    String.format("Suspicious download in container: %s %s (pid=%d)",
                            event.comm(), event.filename(), event.pid()),
                    0.50);
        }

        // Rapid process spawning per container (miner pools often fork workers)
        if (event.hasContainerId()) {
            AtomicInteger counter = execCounters.computeIfAbsent(
                    event.containerId(), k -> new AtomicInteger(0));
            int count = counter.incrementAndGet();
            if (count == RAPID_EXEC_THRESHOLD) {
                return DetectionResult.threat(
                        DetectionResult.Severity.HIGH,
                        "cryptojacking",
                        String.format("Rapid process spawning in container %s: %d execs detected",
                                event.containerId(), count),
                        0.75);
            }
        }

        return DetectionResult.clean();
    }

    private DetectionResult analyzeNetwork(SyscallEvent event) {
        // Network events with mining pool port indicators (MITRE T1496)
        if (event.isSuspicious()) {
            return DetectionResult.threat(
                    DetectionResult.Severity.HIGH,
                    "cryptojacking",
                    String.format("Connection to suspected mining pool from container %s (pid=%d, comm=%s)",
                            event.containerId(), event.pid(), event.comm()),
                    0.85,
                    "T1496");
        }

        return DetectionResult.clean();
    }

    /**
     * Periodic reset of exec counters (called by scheduled task).
     */
    public void resetCounters() {
        int size = execCounters.size();
        execCounters.clear();
        if (size > 0) {
            log.debug("Reset {} exec counters", size);
        }
    }
}
