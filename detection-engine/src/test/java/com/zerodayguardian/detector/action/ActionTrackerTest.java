package com.zerodayguardian.detector.action;

import com.zerodayguardian.detector.detection.DetectionResult;
import com.zerodayguardian.detector.event.EventType;
import com.zerodayguardian.detector.event.SyscallEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

class ActionTrackerTest {

    private ActionTracker tracker;

    @BeforeEach
    void setUp() throws Exception {
        tracker = new ActionTracker();
        // Set rate limit since @Value is not processed outside Spring context
        Field field = ActionTracker.class.getDeclaredField("rateLimitPerMinute");
        field.setAccessible(true);
        field.setInt(tracker, 10);
    }

    @Test
    void shouldAcquireWithinRateLimit() {
        for (int i = 0; i < 10; i++) {
            assertTrue(tracker.tryAcquire());
        }
    }

    @Test
    void shouldBlockWhenRateLimitExceeded() {
        // Default rate limit is 10/min
        for (int i = 0; i < 10; i++) {
            assertTrue(tracker.tryAcquire());
        }
        assertFalse(tracker.tryAcquire());
    }

    @Test
    void shouldTrackTotalActions() {
        assertEquals(0, tracker.getTotalActions());

        SyscallEvent event = new SyscallEvent(
                SyscallEvent.MAGIC, 1, EventType.EXECVE, 0,
                System.nanoTime(), 1, 1, 0, 0, "test", "/test", 0, "");
        DetectionResult result = DetectionResult.threat(
                DetectionResult.Severity.HIGH, "test", "test detail", 0.9);

        tracker.record(event, result, "TEST");
        assertEquals(1, tracker.getTotalActions());
    }
}
