package com.zerodayguardian.detector.action;

import com.zerodayguardian.detector.detection.DetectionResult;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.NetworkingV1Api;
import io.kubernetes.client.openapi.models.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Blocks network traffic to/from a compromised pod by creating
 * a deny-all NetworkPolicy targeting the quarantine label.
 *
 * <p>
 * Creates a {@code NetworkPolicy} that selects pods with the
 * quarantine label and denies all ingress and egress traffic,
 * effectively network-isolating the compromised workload.
 * </p>
 *
 * @author Naveed Gung
 */
@Component
public class NetworkBlocker {

    private static final Logger log = LoggerFactory.getLogger(NetworkBlocker.class);

    private static final String POLICY_PREFIX = "guardian-quarantine-";

    private final NetworkingV1Api networkingApi;

    public NetworkBlocker(ApiClient apiClient) {
        this.networkingApi = new NetworkingV1Api(apiClient);
    }

    /**
     * Create a deny-all NetworkPolicy for the quarantined pod.
     *
     * @param containerId the container ID (used for policy naming)
     * @param namespace   the Kubernetes namespace
     * @param result      the detection result metadata
     */
    public void blockPodNetwork(String containerId, String namespace, DetectionResult result) {
        String policyName = POLICY_PREFIX + sanitizeName(containerId);

        try {
            // Check if a quarantine NetworkPolicy already exists
            try {
                networkingApi.readNamespacedNetworkPolicy(policyName, namespace).execute();
                log.info("Quarantine NetworkPolicy {}/{} already exists", namespace, policyName);
                return;
            } catch (ApiException e) {
                if (e.getCode() != 404) {
                    throw e;
                }
                // 404: policy does not exist yet, proceed to create
            }

            V1NetworkPolicy policy = buildDenyAllPolicy(policyName, namespace, result);
            networkingApi.createNamespacedNetworkPolicy(namespace, policy).execute();

            log.info("Created quarantine NetworkPolicy {}/{}", namespace, policyName);

        } catch (ApiException e) {
            log.error("Failed to create NetworkPolicy {}/{}: {} (code={})",
                    namespace, policyName, e.getResponseBody(), e.getCode(), e);
            throw new RuntimeException("Failed to block pod network", e);
        }
    }

    /**
     * Remove a quarantine NetworkPolicy for the given container (rollback).
     *
     * @param containerId the container ID
     * @param namespace   the Kubernetes namespace
     */
    public void removeBlockPolicy(String containerId, String namespace) {
        String policyName = POLICY_PREFIX + sanitizeName(containerId);
        try {
            networkingApi.deleteNamespacedNetworkPolicy(policyName, namespace).execute();
            log.info("Removed quarantine NetworkPolicy {}/{}", namespace, policyName);
        } catch (ApiException e) {
            if (e.getCode() == 404) {
                log.debug("Quarantine NetworkPolicy {}/{} already absent", namespace, policyName);
            } else {
                log.error("Failed to remove NetworkPolicy {}/{}: {} (code={})",
                        namespace, policyName, e.getResponseBody(), e.getCode(), e);
                throw new RuntimeException("Failed to remove NetworkPolicy", e);
            }
        }
    }

    /**
     * Build a deny-all NetworkPolicy targeting quarantined pods.
     */
    private V1NetworkPolicy buildDenyAllPolicy(String name, String namespace, DetectionResult result) {
        return new V1NetworkPolicy()
                .apiVersion("networking.k8s.io/v1")
                .kind("NetworkPolicy")
                .metadata(new V1ObjectMeta()
                        .name(name)
                        .namespace(namespace)
                        .labels(Map.of(
                                "app.kubernetes.io/managed-by", "zero-day-guardian",
                                "guardian.zerodayguardian.io/policy-type", "quarantine"))
                        .putAnnotationsItem(
                                "guardian.zerodayguardian.io/detection-category",
                                result.category())
                        .putAnnotationsItem(
                                "guardian.zerodayguardian.io/detection-severity",
                                result.severity().name()))
                .spec(new V1NetworkPolicySpec()
                        .podSelector(new V1LabelSelector()
                                .matchLabels(Map.of(
                                        PodIsolator.QUARANTINE_LABEL, "true")))
                        .policyTypes(java.util.List.of("Ingress", "Egress"))
                // Empty ingress/egress = deny all
                );
    }

    /**
     * Sanitize a container ID to be a valid Kubernetes resource name component.
     */
    private String sanitizeName(String containerId) {
        if (containerId == null || containerId.isEmpty()) {
            return "unknown";
        }
        // Take last 12 chars of container ID (like Docker short ID)
        String id = containerId.length() > 12
                ? containerId.substring(containerId.length() - 12)
                : containerId;
        return id.toLowerCase().replaceAll("[^a-z0-9-]", "-");
    }
}
