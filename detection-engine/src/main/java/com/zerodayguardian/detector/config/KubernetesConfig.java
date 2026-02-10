package com.zerodayguardian.detector.config;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.util.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Kubernetes client configuration.
 *
 * <p>
 * Auto-detects in-cluster configuration when running inside a pod,
 * falls back to kubeconfig for local development.
 * </p>
 *
 * @author Naveed Gung
 */
@Configuration
public class KubernetesConfig {

    private static final Logger log = LoggerFactory.getLogger(KubernetesConfig.class);

    @Bean
    public ApiClient kubernetesApiClient() throws Exception {
        ApiClient client;
        try {
            client = Config.fromCluster();
            log.info("Kubernetes client configured from in-cluster service account");
        } catch (Exception e) {
            log.warn("In-cluster config not available, falling back to kubeconfig: {}", e.getMessage());
            client = Config.defaultClient();
            log.info("Kubernetes client configured from default kubeconfig");
        }
        client.setReadTimeout(30_000);
        client.setConnectTimeout(10_000);
        io.kubernetes.client.openapi.Configuration.setDefaultApiClient(client);
        return client;
    }
}
