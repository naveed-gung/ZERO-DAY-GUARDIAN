package com.zerodayguardian.detector.action;

import com.zerodayguardian.detector.detection.DetectionResult;
import com.zerodayguardian.detector.event.SyscallEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tracks executed actions and enforces rate limiting.
 *
 * <p>
 * Maintains a sliding-window counter of actions per minute to
 * prevent cascading failures from runaway automated responses.
 * </p>
 *
 * @author Naveed Gung
 */
@Component
public class ActionTracker {

    private static final Logger log = LoggerFactory.getLogger(ActionTracker.class);

    @Value("${guardian.action.rate-limit-per-minute:10}")
    private int rateLimitPerMinute;

    /** Timestamps of executed actions within the current window. */
    private final ConcurrentLinkedDeque<Long> actionTimestamps = new ConcurrentLinkedDeque<>();

    /** Total actions executed since startup. */
    private final AtomicInteger totalActions = new AtomicInteger(0);

    /**
     * Attempt to acquire a rate-limit token.
     *
     * @return true if the action is allowed under the rate limit
     */
    public boolean tryAcquire() {
        long now = System.currentTimeMillis();
        long windowStart = now - 60_000L;

        // Evict expired entries
        while (!actionTimestamps.isEmpty()) {
            Long oldest = actionTimestamps.peekFirst();
            if (oldest != null && oldest < windowStart) {
                actionTimestamps.pollFirst();
            } else {
                break;
            }
        }

        if (actionTimestamps.size() >= rateLimitPerMinute) {
            return false;
        }

        actionTimestamps.addLast(now);
        return true;
    }

    /**
     * Record an executed (or dry-run) action for audit logging.
     */
    public void record(SyscallEvent event, DetectionResult result, String outcome) {
        int count = totalActions.incrementAndGet();
        log.info("ACTION_RECORD: #{} outcome={} severity={} category={} pid={} container={} detail={}",
                count, outcome, result.severity(), result.category(),
                event.pid(), event.containerId(), result.detail());
    }

    /** Return total actions since startup. */
    public int getTotalActions() {
        return totalActions.get();
    }

    /** Return current window size (actions in last 60 seconds). */
    public int getCurrentWindowSize() {
        long windowStart = System.currentTimeMillis() - 60_000L;
        return (int) actionTimestamps.stream().filter(ts -> ts >= windowStart).count();
    }
}
