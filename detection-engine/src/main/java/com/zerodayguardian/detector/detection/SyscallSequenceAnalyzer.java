package com.zerodayguardian.detector.detection;

import com.zerodayguardian.detector.detection.AttackDetector.Detector;
import com.zerodayguardian.detector.event.EventType;
import com.zerodayguardian.detector.event.SyscallEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding-window syscall sequence analyzer.
 *
 * <p>
 * Maintains per-container event windows and matches against known
 * attack sequences. This is the behavioral correlation layer that
 * catches multi-step attacks individual detectors might miss.
 * </p>
 *
 * <p>
 * Known attack sequences:
 * </p>
 * <ul>
 * <li><b>Classic Escape:</b> UNSHARE -> MOUNT -> EXECVE (namespace escape)</li>
 * <li><b>Miner Deploy:</b> EXECVE(curl/wget) -> EXECVE(chmod) ->
 * EXECVE(miner)</li>
 * <li><b>Recon-Pivot:</b> EXECVE(nmap/scan) -> EXECVE(ssh/nc) -> NETWORK</li>
 * <li><b>Privilege Escalation:</b> PTRACE -> UNSHARE -> EXECVE</li>
 * </ul>
 *
 * @author Naveed Gung
 */
@Component
@Order(4)
public class SyscallSequenceAnalyzer implements Detector {

    private static final Logger log = LoggerFactory.getLogger(SyscallSequenceAnalyzer.class);

    /** Maximum number of events remembered per container. */
    private static final int WINDOW_SIZE = 32;

    /** Maximum age of events in the window (nanoseconds). 60 seconds. */
    private static final long MAX_AGE_NS = 60_000_000_000L;

    /** Per-container sliding windows. */
    private final Map<String, Deque<SyscallEvent>> windows = new ConcurrentHashMap<>();

    /** Predefined attack sequences. */
    private static final List<AttackSequence> SEQUENCES = List.of(
            new AttackSequence(
                    "namespace-escape",
                    DetectionResult.Severity.CRITICAL,
                    0.93,
                    List.of(EventType.UNSHARE, EventType.MOUNT, EventType.EXECVE),
                    "Namespace escape sequence: UNSHARE -> MOUNT -> EXECVE"),
            new AttackSequence(
                    "miner-deployment",
                    DetectionResult.Severity.HIGH,
                    0.88,
                    List.of(EventType.EXECVE, EventType.EXECVE, EventType.EXECVE),
                    "Potential miner deployment: sequential execve chain"),
            new AttackSequence(
                    "recon-pivot",
                    DetectionResult.Severity.HIGH,
                    0.85,
                    List.of(EventType.EXECVE, EventType.EXECVE, EventType.NETWORK),
                    "Reconnaissance followed by pivot: EXECVE -> EXECVE -> NETWORK"),
            new AttackSequence(
                    "privilege-escalation",
                    DetectionResult.Severity.CRITICAL,
                    0.91,
                    List.of(EventType.PTRACE, EventType.UNSHARE, EventType.EXECVE),
                    "Privilege escalation sequence: PTRACE -> UNSHARE -> EXECVE"));

    @Override
    public DetectionResult analyze(SyscallEvent event) {
        if (!event.isFromContainer() || !event.hasContainerId()) {
            return DetectionResult.clean();
        }

        String containerId = event.containerId();
        Deque<SyscallEvent> window = windows.computeIfAbsent(
                containerId, k -> new ArrayDeque<>());

        synchronized (window) {
            // Evict old events
            evictStale(window, event.timestampNs());

            // Add the new event
            window.addLast(event);
            if (window.size() > WINDOW_SIZE) {
                window.removeFirst();
            }

            // Check against all known sequences
            for (AttackSequence seq : SEQUENCES) {
                if (matchesSequence(window, seq)) {
                    log.warn("Attack sequence matched: {} in container {}", seq.category, containerId);
                    return DetectionResult.threat(
                            seq.severity,
                            "sequence:" + seq.category,
                            String.format("%s in container %s (last event: %s pid=%d)",
                                    seq.description, containerId, event.comm(), event.pid()),
                            seq.score);
                }
            }
        }

        return DetectionResult.clean();
    }

    /** Check if the window's recent event types contain the sequence. */
    private boolean matchesSequence(Deque<SyscallEvent> window, AttackSequence seq) {
        if (window.size() < seq.pattern.size()) {
            return false;
        }

        List<EventType> types = window.stream()
                .map(SyscallEvent::eventType)
                .toList();

        List<EventType> pattern = seq.pattern;

        // Subsequence matching: pattern events must appear in order
        int patternIdx = 0;
        for (EventType type : types) {
            if (type == pattern.get(patternIdx)) {
                patternIdx++;
                if (patternIdx == pattern.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    private void evictStale(Deque<SyscallEvent> window, long currentNs) {
        while (!window.isEmpty()) {
            SyscallEvent oldest = window.peekFirst();
            if (oldest != null && (currentNs - oldest.timestampNs()) > MAX_AGE_NS) {
                window.removeFirst();
            } else {
                break;
            }
        }
    }

    /** Periodic cleanup of empty windows to bound memory. */
    public void pruneEmptyWindows() {
        windows.entrySet().removeIf(e -> {
            synchronized (e.getValue()) {
                return e.getValue().isEmpty();
            }
        });
    }

    /** Predefined attack sequence pattern. */
    private record AttackSequence(
            String category,
            DetectionResult.Severity severity,
            double score,
            List<EventType> pattern,
            String description) {
    }
}
