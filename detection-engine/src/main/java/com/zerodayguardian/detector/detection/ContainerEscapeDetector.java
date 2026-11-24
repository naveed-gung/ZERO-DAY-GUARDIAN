package com.zerodayguardian.detector.detection;

import com.zerodayguardian.detector.event.SyscallEvent;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Order(1)
public class ContainerEscapeDetector implements AttackDetector.Detector {
    private final ContainerEscapeRules rules = new ContainerEscapeRules();

    @Override
    public DetectionResult analyze(SyscallEvent event) {
        return rules.analyze(event);
    }
}
