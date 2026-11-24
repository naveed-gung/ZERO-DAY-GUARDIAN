package com.zerodayguardian.detector.action;

import com.zerodayguardian.detector.detection.DetectionResult;
import com.zerodayguardian.detector.event.EventType;
import com.zerodayguardian.detector.event.SyscallEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.*;

class SafeActionExecutorTest {
    private static final String CONTAINER_ID = "a".repeat(64);
    private static final SyscallEvent EVENT = new SyscallEvent(
            SyscallEvent.MAGIC, SyscallEvent.CURRENT_VERSION, EventType.EXECVE,
            SyscallEvent.FLAG_FROM_CONTAINER, 1, 42, 42, 1000, 1000, "fixture", "",
            2, CONTAINER_ID);
    private static final DetectionResult RESULT = DetectionResult.threat(
            DetectionResult.Severity.HIGH, "fixture", "Synthetic alert", 1);

    private final PodIsolator isolator = mock(PodIsolator.class);
    private final ActionTracker tracker = mock(ActionTracker.class);

    @Test
    void observeOnlyDoesNotCallKubernetes() {
        executor(true, List.of("workloads")).executeResponse(EVENT, RESULT);

        verifyNoInteractions(isolator);
        verify(tracker).record(EVENT, RESULT, "OBSERVE_ONLY");
    }

    @Test
    void emptyOrSystemOnlyApprovalDoesNotCallKubernetes() {
        executor(false, List.of("", "guardian-system", "kube-system")).executeResponse(EVENT, RESULT);

        verifyNoInteractions(isolator);
        verify(tracker).record(EVENT, RESULT, "BLOCKED_SCOPE");
    }

    @Test
    void unresolvedIdentityDoesNotPatchAPod() throws Exception {
        when(tracker.tryAcquire()).thenReturn(true);
        when(isolator.resolve(CONTAINER_ID, "node-a", List.of("workloads"))).thenReturn(Optional.empty());

        executor(false, List.of("workloads")).executeResponse(EVENT, RESULT);

        verify(isolator).resolve(CONTAINER_ID, "node-a", List.of("workloads"));
        verifyNoMoreInteractions(isolator);
        verify(tracker).record(EVENT, RESULT, "TARGET_UNRESOLVED");
    }

    private SafeActionExecutor executor(boolean observeOnly, List<String> approved) {
        var executor = new SafeActionExecutor(isolator, tracker, new SimpleMeterRegistry());
        ReflectionTestUtils.setField(executor, "dryRun", observeOnly);
        ReflectionTestUtils.setField(executor, "approvedNamespaces", approved);
        ReflectionTestUtils.setField(executor, "excludedNamespaces", List.of());
        ReflectionTestUtils.setField(executor, "nodeName", "node-a");
        executor.init();
        return executor;
    }
}
