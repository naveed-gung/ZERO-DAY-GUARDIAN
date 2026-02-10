package com.zerodayguardian.detector.detection;

import com.zerodayguardian.detector.event.EventType;
import com.zerodayguardian.detector.event.SyscallEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ContainerEscapeDetectorTest {

    private ContainerEscapeDetector detector;

    @BeforeEach
    void setUp() {
        detector = new ContainerEscapeDetector();
    }

    @Test
    void shouldDetectRuncExecution() {
        SyscallEvent event = testEvent(EventType.EXECVE, "/proc/self/exe",
                SyscallEvent.FLAG_FROM_CONTAINER, "runc");

        DetectionResult result = detector.analyze(event);

        assertTrue(result.detected());
        assertEquals(DetectionResult.Severity.CRITICAL, result.severity());
        assertEquals("container-escape", result.category());
        assertTrue(result.score() > 0.9);
    }

    @Test
    void shouldDetectNsenterFromContainer() {
        SyscallEvent event = testEvent(EventType.EXECVE, "/usr/bin/nsenter",
                SyscallEvent.FLAG_FROM_CONTAINER, "nsenter");

        DetectionResult result = detector.analyze(event);

        assertTrue(result.detected());
        assertEquals(DetectionResult.Severity.HIGH, result.severity());
    }

    @Test
    void shouldDetectUnshareFromContainer() {
        SyscallEvent event = testEvent(EventType.UNSHARE, "",
                SyscallEvent.FLAG_FROM_CONTAINER, "unshare");

        DetectionResult result = detector.analyze(event);

        assertTrue(result.detected());
        assertEquals(DetectionResult.Severity.HIGH, result.severity());
    }

    @Test
    void shouldDetectSensitiveMountInContainer() {
        SyscallEvent event = testEvent(EventType.MOUNT, "/proc",
                SyscallEvent.FLAG_FROM_CONTAINER, "mount");

        DetectionResult result = detector.analyze(event);

        assertTrue(result.detected());
        assertEquals(DetectionResult.Severity.CRITICAL, result.severity());
    }

    @Test
    void shouldIgnoreHostProcesses() {
        SyscallEvent event = testEvent(EventType.EXECVE, "/usr/bin/runc", 0, "runc");

        DetectionResult result = detector.analyze(event);
        assertFalse(result.detected());
    }

    @Test
    void shouldDetectPtraceFromContainer() {
        SyscallEvent event = testEvent(EventType.PTRACE, "",
                SyscallEvent.FLAG_FROM_CONTAINER, "gdb");

        DetectionResult result = detector.analyze(event);

        assertTrue(result.detected());
        assertEquals(DetectionResult.Severity.HIGH, result.severity());
    }

    private static SyscallEvent testEvent(EventType type, String filename, int flags, String comm) {
        return new SyscallEvent(
                SyscallEvent.MAGIC, 1, type, flags,
                System.nanoTime(), 1000, 1000, 1000, 1000,
                comm, filename, 1L, "container-abc123");
    }
}
