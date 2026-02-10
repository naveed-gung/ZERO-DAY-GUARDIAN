package com.zerodayguardian.detector.action;

import com.zerodayguardian.detector.detection.DetectionResult;
import io.kubernetes.client.Exec;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1ContainerStatus;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Terminates malicious processes inside containers via
 * {@code kubectl exec kill}.
 *
 * <p>
 * Uses the Kubernetes exec API to send SIGKILL to a specific PID inside a
 * container. This is a last-resort action for CRITICAL detections where the
 * attacking process must be stopped immediately.
 * </p>
 *
 * <p>
 * Safety: only targets a specific PID, does not affect other processes in
 * the container. The pod itself remains running for forensic analysis.
 * </p>
 *
 * @author Naveed Gung
 */
@Component
public class ProcessKiller {

    private static final Logger log = LoggerFactory.getLogger(ProcessKiller.class);

    private final ApiClient apiClient;
    private final CoreV1Api coreApi;

    public ProcessKiller(ApiClient apiClient) {
        this.apiClient = apiClient;
        this.coreApi = new CoreV1Api(apiClient);
    }

    /**
     * Kill a process inside a container by PID.
     *
     * @param containerId the container ID from the event
     * @param namespace   the Kubernetes namespace
     * @param pid         the process ID to kill
     * @param result      the detection result for logging context
     */
    public void killProcess(String containerId, String namespace, int pid, DetectionResult result) {
        try {
            V1Pod pod = findPodByContainerId(containerId, namespace);
            if (pod == null) {
                log.warn("Could not find pod for container {} in namespace {}", containerId, namespace);
                return;
            }

            String podName = pod.getMetadata().getName();
            String containerName = resolveContainerName(pod, containerId);

            log.info("Killing process pid={} in {}/{} container={} (category={}, severity={})",
                    pid, namespace, podName, containerName, result.category(), result.severity());

            Exec exec = new Exec(apiClient);
            Process process = exec.exec(
                    namespace,
                    podName,
                    new String[] { "kill", "-9", String.valueOf(pid) },
                    containerName,
                    false, // stdin
                    false // tty
            );

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                log.info("Successfully killed pid={} in {}/{}", pid, namespace, podName);
            } else {
                log.warn("Kill command exited with code {} for pid={} in {}/{}", exitCode, pid, namespace, podName);
            }

        } catch (ApiException e) {
            log.error("Kubernetes API error killing pid={} in container {}: {} (code={})",
                    pid, containerId, e.getResponseBody(), e.getCode(), e);
            throw new RuntimeException("Failed to kill process", e);
        } catch (Exception e) {
            log.error("Error killing pid={} in container {}: {}", pid, containerId, e.getMessage(), e);
            throw new RuntimeException("Failed to kill process", e);
        }
    }

    /**
     * Find a pod in the given namespace that contains the specified container ID.
     */
    private V1Pod findPodByContainerId(String containerId, String namespace) throws ApiException {
        V1PodList podList = coreApi.listNamespacedPod(namespace).execute();

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
     * Resolve the container name from a pod given a container ID.
     */
    private String resolveContainerName(V1Pod pod, String containerId) {
        if (pod.getStatus() != null && pod.getStatus().getContainerStatuses() != null) {
            for (V1ContainerStatus cs : pod.getStatus().getContainerStatuses()) {
                String cid = cs.getContainerID();
                if (cid != null && cid.contains(containerId)) {
                    return cs.getName();
                }
            }
        }
        // Fallback to first container
        if (pod.getSpec() != null && pod.getSpec().getContainers() != null
                && !pod.getSpec().getContainers().isEmpty()) {
            return pod.getSpec().getContainers().getFirst().getName();
        }
        return null;
    }
}
