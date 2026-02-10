package com.zerodayguardian.detector.kubernetes;

import io.kubernetes.client.informer.ResourceEventHandler;
import io.kubernetes.client.informer.SharedIndexInformer;
import io.kubernetes.client.informer.SharedInformerFactory;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodList;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Monitors pod security posture across the cluster.
 *
 * <p>
 * Uses a SharedInformer to watch pod events and flag security violations:
 * </p>
 * <ul>
 * <li>Privileged containers</li>
 * <li>Host PID/Network/IPC namespace sharing</li>
 * <li>Sensitive host path mounts</li>
 * <li>Running as root</li>
 * <li>Capabilities additions</li>
 * </ul>
 *
 * @author Naveed Gung
 */
@Component
public class PodSecurityMonitor {

    private static final Logger log = LoggerFactory.getLogger(PodSecurityMonitor.class);

    private final ApiClient apiClient;
    private final MeterRegistry meterRegistry;

    private SharedInformerFactory informerFactory;
    private Counter securityViolations;

    /** Host paths that should never be mounted in containers. */
    private static final Set<String> DANGEROUS_HOST_PATHS = Set.of(
            "/", "/etc", "/var/run/docker.sock",
            "/run/containerd/containerd.sock",
            "/proc", "/sys", "/dev");

    public PodSecurityMonitor(ApiClient apiClient, MeterRegistry meterRegistry) {
        this.apiClient = apiClient;
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void init() {
        securityViolations = Counter.builder("guardian.pod.security.violations")
                .description("Pod security policy violations detected")
                .register(meterRegistry);
    }

    /**
     * Start the pod security informer.
     */
    public void start() {
        CoreV1Api coreApi = new CoreV1Api(apiClient);
        informerFactory = new SharedInformerFactory(apiClient);

        SharedIndexInformer<V1Pod> podInformer = informerFactory.sharedIndexInformerFor(
                params -> coreApi.listPodForAllNamespaces()
                        .resourceVersion(params.resourceVersion)
                        .timeoutSeconds(params.timeoutSeconds)
                        .watch(params.watch)
                        .buildCall(null),
                V1Pod.class,
                V1PodList.class,
                60_000L);

        podInformer.addEventHandler(new ResourceEventHandler<>() {
            @Override
            public void onAdd(V1Pod pod) {
                auditPod(pod, "CREATED");
            }

            @Override
            public void onUpdate(V1Pod oldPod, V1Pod newPod) {
                auditPod(newPod, "UPDATED");
            }

            @Override
            public void onDelete(V1Pod pod, boolean deletedFinalStateUnknown) {
                // No-op for deletion
            }
        });

        informerFactory.startAllRegisteredInformers();
        log.info("Pod security monitor started");
    }

    /**
     * Audit a pod's security configuration.
     */
    void auditPod(V1Pod pod, String action) {
        if (pod.getSpec() == null || pod.getMetadata() == null)
            return;

        String ns = pod.getMetadata().getNamespace();
        String name = pod.getMetadata().getName();
        var spec = pod.getSpec();

        // Check host namespaces
        if (Boolean.TRUE.equals(spec.getHostPID())) {
            reportViolation(ns, name, "hostPID enabled");
        }
        if (Boolean.TRUE.equals(spec.getHostNetwork())) {
            reportViolation(ns, name, "hostNetwork enabled");
        }
        if (Boolean.TRUE.equals(spec.getHostIPC())) {
            reportViolation(ns, name, "hostIPC enabled");
        }

        // Check each container
        if (spec.getContainers() != null) {
            spec.getContainers().forEach(container -> {
                var sc = container.getSecurityContext();
                if (sc != null) {
                    if (Boolean.TRUE.equals(sc.getPrivileged())) {
                        reportViolation(ns, name,
                                "Privileged container: " + container.getName());
                    }
                    if (sc.getRunAsUser() != null && sc.getRunAsUser() == 0) {
                        reportViolation(ns, name,
                                "Running as root (UID 0): " + container.getName());
                    }
                    if (sc.getCapabilities() != null && sc.getCapabilities().getAdd() != null) {
                        List<String> caps = sc.getCapabilities().getAdd();
                        if (caps.contains("SYS_ADMIN") || caps.contains("ALL") || caps.contains("NET_RAW")) {
                            reportViolation(ns, name,
                                    "Dangerous capabilities added: " + caps + " in " + container.getName());
                        }
                    }
                }
            });
        }

        // Check volume mounts
        if (spec.getVolumes() != null) {
            spec.getVolumes().forEach(volume -> {
                if (volume.getHostPath() != null) {
                    String path = volume.getHostPath().getPath();
                    for (String dangerous : DANGEROUS_HOST_PATHS) {
                        if (path.equals(dangerous) || path.startsWith(dangerous + "/")) {
                            reportViolation(ns, name,
                                    "Dangerous hostPath mount: " + path);
                            break;
                        }
                    }
                }
            });
        }
    }

    private void reportViolation(String namespace, String podName, String detail) {
        securityViolations.increment();
        log.warn("POD SECURITY VIOLATION: {}/{} - {}", namespace, podName, detail);
    }

    @PreDestroy
    public void stop() {
        if (informerFactory != null) {
            informerFactory.stopAllRegisteredInformers();
        }
        log.info("Pod security monitor stopped");
    }
}
