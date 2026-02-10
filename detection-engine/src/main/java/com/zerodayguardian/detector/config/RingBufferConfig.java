package com.zerodayguardian.detector.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

/**
 * Ring buffer connection configuration.
 *
 * @author Naveed Gung
 */
@Configuration
@ConfigurationProperties(prefix = "guardian.ringbuffer")
@Validated
public class RingBufferConfig {

    private String path = "/shared/ringbuf/events.buf";
    private int pollIntervalMs = 1;
    private int sizeMb = 16;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public int getPollIntervalMs() {
        return pollIntervalMs;
    }

    public void setPollIntervalMs(int pollIntervalMs) {
        this.pollIntervalMs = pollIntervalMs;
    }

    public int getSizeMb() {
        return sizeMb;
    }

    public void setSizeMb(int sizeMb) {
        this.sizeMb = sizeMb;
    }

    public long getSizeBytes() {
        return (long) sizeMb * 1024 * 1024;
    }
}
