package com.zerodayguardian.detector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Zero-Day Guardian Detection Engine.
 *
 * <p>
 * Spring Boot application that processes eBPF syscall events from the shared
 * ring buffer, detects attack patterns, integrates with threat intelligence
 * APIs,
 * and executes defensive actions via the Kubernetes API.
 * </p>
 *
 * @author Naveed Gung
 */
@SpringBootApplication
@EnableScheduling
public class DetectorApplication {

    public static void main(String[] args) {
        SpringApplication.run(DetectorApplication.class, args);
    }
}
