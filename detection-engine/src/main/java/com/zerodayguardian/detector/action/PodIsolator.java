package com.zerodayguardian.detector.action;

import io.kubernetes.client.custom.V1Patch;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.JSON;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1ContainerStatus;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.util.PatchUtils;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
public class PodIsolator {
    public static final String QUARANTINE_LABEL = "guardian.zerodayguardian.io/quarantined";

    private final CoreV1Api coreApi;

    public PodIsolator(ApiClient apiClient) {
        this.coreApi = new CoreV1Api(apiClient);
    }

    Optional<V1Pod> resolve(String containerId, String node, List<String> namespaces) throws ApiException {
        if (containerId == null || !containerId.matches("[0-9a-f]{64}")
                || node == null || node.isBlank() || node.equals("unknown")) {
            return Optional.empty();
        }

        V1Pod target = null;
        for (String namespace : namespaces) {
            var pods = coreApi.listNamespacedPod(namespace)
                    .fieldSelector("spec.nodeName=" + node).execute();
            for (V1Pod pod : pods.getItems()) {
                if (!matches(pod, containerId, node, namespace)) {
                    continue;
                }
                if (target != null) {
                    return Optional.empty();
                }
                target = pod;
            }
        }
        return Optional.ofNullable(target);
    }

    private boolean matches(V1Pod pod, String containerId, String node, String namespace) {
        var metadata = pod.getMetadata();
        var spec = pod.getSpec();
        var status = pod.getStatus();
        if (metadata == null || metadata.getUid() == null || metadata.getName() == null
                || metadata.getResourceVersion() == null || metadata.getDeletionTimestamp() != null
                || !namespace.equals(metadata.getNamespace()) || spec == null || !node.equals(spec.getNodeName())
                || Boolean.TRUE.equals(spec.getHostNetwork()) || status == null) {
            return false;
        }
        return hasRunningContainer(status.getContainerStatuses(), containerId)
                || hasRunningContainer(status.getInitContainerStatuses(), containerId)
                || hasRunningContainer(status.getEphemeralContainerStatuses(), containerId);
    }

    private boolean hasRunningContainer(List<V1ContainerStatus> statuses, String containerId) {
        return statuses != null && statuses.stream().anyMatch(status ->
                status.getContainerID() != null && status.getContainerID().endsWith("://" + containerId)
                        && status.getState() != null && status.getState().getRunning() != null);
    }

    boolean labelPod(V1Pod pod) throws ApiException {
        var metadata = pod.getMetadata();
        if (metadata.getLabels() != null && "true".equals(metadata.getLabels().get(QUARANTINE_LABEL))) {
            return false;
        }

        // Require the same resource version so a replacement or changed pod is never patched.
        var patch = new V1Pod().metadata(new V1ObjectMeta()
                .uid(metadata.getUid())
                .resourceVersion(metadata.getResourceVersion())
                .putLabelsItem(QUARANTINE_LABEL, "true"));
        PatchUtils.patch(V1Pod.class,
                () -> coreApi.patchNamespacedPod(metadata.getName(), metadata.getNamespace(),
                        new V1Patch(JSON.serialize(patch))).buildCall(null),
                V1Patch.PATCH_FORMAT_JSON_MERGE_PATCH, coreApi.getApiClient());
        return true;
    }
}
