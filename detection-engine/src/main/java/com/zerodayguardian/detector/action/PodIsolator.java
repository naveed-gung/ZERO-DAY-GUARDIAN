package com.zerodayguardian.detector.action;

import com.zerodayguardian.detector.detection.DetectionResult;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Isolates compromised pods by applying quarantine labels and annotations.
 *
 * <p>
 * Isolation strategy:
 * </p>
 * <ol>
 * <li>Add {@code guardian.zerodayguardian.io/quarantined=true} label to the
 * pod</li>
 * <li>Add annotations with detection details for audit trail</li>
 * <li>A pre-deployed {@code NetworkPolicy} matching the quarantine label
 * blocks all ingress/egress traffic to the pod</li>
 * </ol>
 *
 * <p>
 * This approach avoids pod deletion, preserving forensic state.
 * </p>
 *
 * @author Naveed Gung
 */
@Component
public class PodIsolator {

    private static final Logger log = LoggerFactory.getLogger(PodIsolator.class);

    /** Label applied to quarantined pods. */
    public static final String QUARANTINE_LABEL = "guardian.zerodayguardian.io/quarantined";

    /** Annotation prefix for detection metadata. */
    public static final String ANNOTATION_PREFIX = "guardian.zerodayguardian.io/";

    private final CoreV1Api coreApi;

    public PodIsolator(ApiClient apiClient) {
        this.coreApi = new CoreV1Api(apiClient);
    }

    /**
     * Isolate a pod by container ID.
     *
     * @param containerId the container ID from the event
     * @param namespace   the Kubernetes namespace
     * @param result      the detection result for annotation metadata
     */
    public void isolatePod(String containerId, String namespace, DetectionResult result) {
        try {
            // Find the pod by container ID
            V1Pod pod = findPodByContainerId(containerId, namespace);
            if (pod == null) {
                log.warn("Could not find pod for container {} in namespace {}", containerId, namespace);
                return;
            }

            String podName = pod.getMetadata().getName();
            log.info("Isolating pod {}/{} (container={})", namespace, podName, containerId);

            // Apply quarantine label and detection annotations via JSON merge patch
            String patch = buildQuarantinePatch(result);
            coreApi.patchNamespacedPod(podName, namespace, new io.kubernetes.client.custom.V1Patch(patch))
                    .fieldManager("guardian-detector")
                    .force(true)
                    .execute();

            log.info("Pod {}/{} quarantined successfully", namespace, podName);

        } catch (ApiException e) {
            log.error("Kubernetes API error isolating container {}: {} (code={})",
                    containerId, e.getResponseBody(), e.getCode(), e);
            throw new RuntimeException("Failed to isolate pod", e);
        } catch (Exception e) {
            log.error("Error isolating container {}: {}", containerId, e.getMessage(), e);
            throw new RuntimeException("Failed to isolate pod", e);
        }
    }

    /**
     * Find a pod in the given namespace that contains the specified container ID.
     */
    V1Pod findPodByContainerId(String containerId, String namespace) throws ApiException {
        V1PodList podList = coreApi.listNamespacedPod(
                namespace).execute();

        for (V1Pod pod : podList.getItems()) {
            if (pod.getStatus() != null && pod.getStatus().getContainerStatuses() != null) {
                for (V1ContainerStatus cs : pod.getStatus().getContainerStatuses()) {
                    String cid = cs.getContainerID();
                    if (cid != null && cid.contains(containerId)) {
                        return pod;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Remove quarantine label from a previously isolated pod (rollback).
     *
     * @param containerId the container ID
     * @param namespace   the Kubernetes namespace
     */
    public void removeQuarantine(String containerId, String namespace) {
        try {
            V1Pod pod = findPodByContainerId(containerId, namespace);
            if (pod == null) {
                log.warn("Rollback: could not find pod for container {} in namespace {}", containerId, namespace);
                return;
            }

            String podName = pod.getMetadata().getName();
            log.info("Removing quarantine from pod {}/{}", namespace, podName);

            // JSON merge patch to remove the quarantine label
            String patch = String.format("""
                    {
                      "metadata": {
                        "labels": {
                          "%s": null
                        }
                      }
                    }""", QUARANTINE_LABEL);

            coreApi.patchNamespacedPod(podName, namespace, new io.kubernetes.client.custom.V1Patch(patch))
                    .fieldManager("guardian-detector")
                    .force(true)
                    .execute();

            log.info("Quarantine removed from pod {}/{}", namespace, podName);

        } catch (ApiException e) {
            log.error("Failed to remove quarantine from container {}: {} (code={})",
                    containerId, e.getResponseBody(), e.getCode(), e);
            throw new RuntimeException("Failed to remove quarantine", e);
        } catch (Exception e) {
            log.error("Error removing quarantine from container {}: {}", containerId, e.getMessage(), e);
            throw new RuntimeException("Failed to remove quarantine", e);
        }
    }

    /**
     * Build JSON merge patch to apply quarantine label and annotations.
     */
    private String buildQuarantinePatch(DetectionResult result) {
        long now = System.currentTimeMillis() / 1000;
        return String.format("""
                {
                  "metadata": {
                    "labels": {
                      "%s": "true"
                    },
                    "annotations": {
                      "%sdetection-category": "%s",
                      "%sdetection-severity": "%s",
                      "%sdetection-detail": "%s",
                      "%sdetection-score": "%.2f",
                      "%squarantined-at": "%d"
                    }
                  }
                }""",
                QUARANTINE_LABEL,
                ANNOTATION_PREFIX, result.category(),
                ANNOTATION_PREFIX, result.severity(),
                ANNOTATION_PREFIX, escapeJson(result.detail()),
                ANNOTATION_PREFIX, result.score(),
                ANNOTATION_PREFIX, now);
    }

    private String escapeJson(String value) {
        if (value == null)
            return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
