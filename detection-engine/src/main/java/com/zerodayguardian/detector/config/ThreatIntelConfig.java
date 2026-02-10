package com.zerodayguardian.detector.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for threat intelligence integrations.
 *
 * <p>
 * All API keys are sourced from environment variables to prevent
 * credential leakage. Rate limits are pre-configured per provider
 * tier to avoid upstream throttling.
 * </p>
 *
 * @author Naveed Gung
 */
@Validated
@ConfigurationProperties(prefix = "guardian.threat-intel")
public class ThreatIntelConfig {

    private VirusTotal virusTotal = new VirusTotal();
    private AbuseIPDB abuseIpDb = new AbuseIPDB();
    private AlienVaultOTX otx = new AlienVaultOTX();

    public VirusTotal getVirusTotal() {
        return virusTotal;
    }

    public void setVirusTotal(VirusTotal virusTotal) {
        this.virusTotal = virusTotal;
    }

    public AbuseIPDB getAbuseIpDb() {
        return abuseIpDb;
    }

    public void setAbuseIpDb(AbuseIPDB abuseIpDb) {
        this.abuseIpDb = abuseIpDb;
    }

    public AlienVaultOTX getOtx() {
        return otx;
    }

    public void setOtx(AlienVaultOTX otx) {
        this.otx = otx;
    }

    public static class VirusTotal {
        @NotBlank
        private String apiKey;
        @NotBlank
        private String baseUrl = "https://www.virustotal.com/api/v3";
        @Min(1)
        private int rateLimitPerMinute = 4;
        @Min(100)
        private int timeoutMs = 5000;

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public int getRateLimitPerMinute() {
            return rateLimitPerMinute;
        }

        public void setRateLimitPerMinute(int rateLimitPerMinute) {
            this.rateLimitPerMinute = rateLimitPerMinute;
        }

        public int getTimeoutMs() {
            return timeoutMs;
        }

        public void setTimeoutMs(int timeoutMs) {
            this.timeoutMs = timeoutMs;
        }
    }

    public static class AbuseIPDB {
        @NotBlank
        private String apiKey;
        @NotBlank
        private String baseUrl = "https://api.abuseipdb.com/api/v2";
        @Min(1)
        private int rateLimitPerDay = 1000;
        @Min(100)
        private int timeoutMs = 5000;

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public int getRateLimitPerDay() {
            return rateLimitPerDay;
        }

        public void setRateLimitPerDay(int rateLimitPerDay) {
            this.rateLimitPerDay = rateLimitPerDay;
        }

        public int getTimeoutMs() {
            return timeoutMs;
        }

        public void setTimeoutMs(int timeoutMs) {
            this.timeoutMs = timeoutMs;
        }
    }

    public static class AlienVaultOTX {
        @NotBlank
        private String apiKey;
        @NotBlank
        private String baseUrl = "https://otx.alienvault.com/api/v1";
        @Min(1)
        private int rateLimitPerHour = 10000;
        @Min(100)
        private int timeoutMs = 5000;

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public int getRateLimitPerHour() {
            return rateLimitPerHour;
        }

        public void setRateLimitPerHour(int rateLimitPerHour) {
            this.rateLimitPerHour = rateLimitPerHour;
        }

        public int getTimeoutMs() {
            return timeoutMs;
        }

        public void setTimeoutMs(int timeoutMs) {
            this.timeoutMs = timeoutMs;
        }
    }
}
