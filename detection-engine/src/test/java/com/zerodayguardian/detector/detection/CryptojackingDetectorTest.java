package com.zerodayguardian.detector.detection;

import com.zerodayguardian.detector.event.EventType;
import com.zerodayguardian.detector.event.SyscallEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptojackingDetectorTest {

    private CryptojackingDetector detector;

    @BeforeEach
    void setUp() {
        detector = new CryptojackingDetector();
    }

    @Test
    void shouldDetectXmrigBinary() {
        SyscallEvent event = testEvent(EventType.EXECVE, "/tmp/xmrig",
                SyscallEvent.FLAG_FROM_CONTAINER, "xmrig");

        DetectionResult result = detector.analyze(event);

        assertTrue(result.detected());
        assertEquals(DetectionResult.Severity.CRITICAL, result.severity());
        assertEquals("cryptojacking", result.category());
    }

    @Test
    void shouldDetectMinerInFilename() {
        SyscallEvent event = testEvent(EventType.EXECVE, "/opt/mining/cpuminer",
                SyscallEvent.FLAG_FROM_CONTAINER, "miner");

        DetectionResult result = detector.analyze(event);

        assertTrue(result.detected());
    }

    @Test
    void shouldDetectSuspiciousNetworkActivity() {
        SyscallEvent event = testEvent(EventType.NETWORK, "",
                SyscallEvent.FLAG_FROM_CONTAINER | SyscallEvent.FLAG_SUSPICIOUS, "pool-worker");

        DetectionResult result = detector.analyze(event);

        assertTrue(result.detected());
        assertEquals(DetectionResult.Severity.HIGH, result.severity());
    }

    @Test
    void shouldIgnoreNormalBinaries() {
        SyscallEvent event = testEvent(EventType.EXECVE, "/usr/bin/ls",
                SyscallEvent.FLAG_FROM_CONTAINER, "ls");

        DetectionResult result = detector.analyze(event);
        assertFalse(result.detected());
    }

    @Test
    void shouldIgnoreHostProcesses() {
        SyscallEvent event = testEvent(EventType.EXECVE, "/tmp/xmrig", 0, "xmrig");

        DetectionResult result = detector.analyze(event);
        assertFalse(result.detected());
    }

    private static SyscallEvent testEvent(EventType type, String filename, int flags, String comm) {
        return new SyscallEvent(
                SyscallEvent.MAGIC, 1, type, flags,
                System.nanoTime(), 1000, 1000, 1000, 1000,
                comm, filename, 1L, "container-abc123");
    }
}
