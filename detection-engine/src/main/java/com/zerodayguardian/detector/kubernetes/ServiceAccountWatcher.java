package com.zerodayguardian.detector.kubernetes;

import io.kubernetes.client.informer.ResourceEventHandler;
import io.kubernetes.client.informer.SharedIndexInformer;
import io.kubernetes.client.informer.SharedInformerFactory;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1ObjectReference;
import io.kubernetes.client.openapi.models.V1ServiceAccount;
import io.kubernetes.client.openapi.models.V1ServiceAccountList;
import io.kubernetes.client.openapi.models.V1SecretList;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Watches Kubernetes ServiceAccount changes for potential abuse.
 *
 * <p>
 * Monitors for:
 * </p>
 * <ul>
 * <li>New ServiceAccount creation (may indicate attacker establishing
 * persistence)</li>
 * <li>ServiceAccount token secret modifications</li>
 * <li>ServiceAccounts with automountServiceAccountToken enabled in sensitive
 * namespaces</li>
 * </ul>
 *
 * @author Naveed Gung
 */
@Component
public class ServiceAccountWatcher {

    private static final Logger log = LoggerFactory.getLogger(ServiceAccountWatcher.class);

    private final ApiClient apiClient;
    private final MeterRegistry meterRegistry;

    private SharedInformerFactory informerFactory;
    private CoreV1Api coreApi;
    private Counter saCreated;
    private Counter saModified;

    public ServiceAccountWatcher(ApiClient apiClient, MeterRegistry meterRegistry) {
        this.apiClient = apiClient;
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void init() {
        saCreated = Counter.builder("guardian.k8s.serviceaccount.created")
                .description("New ServiceAccounts created")
                .register(meterRegistry);
        saModified = Counter.builder("guardian.k8s.serviceaccount.modified")
                .description("ServiceAccounts modified")
                .register(meterRegistry);
    }

    /**
     * Start the ServiceAccount informer.
     */
    public void start() {
        coreApi = new CoreV1Api(apiClient);
        informerFactory = new SharedInformerFactory(apiClient);

        SharedIndexInformer<V1ServiceAccount> saInformer = informerFactory.sharedIndexInformerFor(
                params -> coreApi.listServiceAccountForAllNamespaces()
                        .resourceVersion(params.resourceVersion)
                        .timeoutSeconds(params.timeoutSeconds)
                        .watch(params.watch)
                        .buildCall(null),
                V1ServiceAccount.class,
                V1ServiceAccountList.class,
                120_000L);

        saInformer.addEventHandler(new ResourceEventHandler<>() {
            @Override
            public void onAdd(V1ServiceAccount sa) {
                handleCreate(sa);
            }

            @Override
            public void onUpdate(V1ServiceAccount oldSa, V1ServiceAccount newSa) {
                handleUpdate(oldSa, newSa);
            }

            @Override
            public void onDelete(V1ServiceAccount sa, boolean deletedFinalStateUnknown) {
                // Deletion is informational
                if (sa.getMetadata() != null) {
                    log.info("ServiceAccount deleted: {}/{}",
                            sa.getMetadata().getNamespace(), sa.getMetadata().getName());
                }
            }
        });

        informerFactory.startAllRegisteredInformers();
        log.info("ServiceAccount watcher started");
    }

    private void handleCreate(V1ServiceAccount sa) {
        if (sa.getMetadata() == null)
            return;

        String ns = sa.getMetadata().getNamespace();
        String name = sa.getMetadata().getName();

        // Ignore default service account creation
        if ("default".equals(name))
            return;

        saCreated.increment();
        log.info("ServiceAccount created: {}/{}", ns, name);

        // Check for automatic token mount
        if (!Boolean.FALSE.equals(sa.getAutomountServiceAccountToken())) {
            log.warn("SECURITY: New ServiceAccount {}/{} has automountServiceAccountToken enabled", ns, name);
        }

        // Check for secrets
        if (sa.getSecrets() != null && !sa.getSecrets().isEmpty()) {
            log.warn("SECURITY: New ServiceAccount {}/{} created with {} secret references",
                    ns, name, sa.getSecrets().size());
        }
    }

    private void handleUpdate(V1ServiceAccount oldSa, V1ServiceAccount newSa) {
        if (newSa.getMetadata() == null)
            return;

        String ns = newSa.getMetadata().getNamespace();
        String name = newSa.getMetadata().getName();

        saModified.increment();

        // Check for token mount changes
        boolean oldAutoMount = !Boolean.FALSE.equals(
                oldSa.getAutomountServiceAccountToken());
        boolean newAutoMount = !Boolean.FALSE.equals(
                newSa.getAutomountServiceAccountToken());

        if (!oldAutoMount && newAutoMount) {
            log.warn("SECURITY: ServiceAccount {}/{} had automountServiceAccountToken enabled", ns, name);
        }

        // Check for added secrets
        int oldSecretCount = oldSa.getSecrets() != null ? oldSa.getSecrets().size() : 0;
        int newSecretCount = newSa.getSecrets() != null ? newSa.getSecrets().size() : 0;
        if (newSecretCount > oldSecretCount) {
            log.warn("SECURITY: ServiceAccount {}/{} gained {} new secret references",
                    ns, name, newSecretCount - oldSecretCount);
        }
    }

    @PreDestroy
    public void stop() {
        if (informerFactory != null) {
            informerFactory.stopAllRegisteredInformers();
        }
        log.info("ServiceAccount watcher stopped");
    }

    /**
     * Rotate tokens for a compromised ServiceAccount by deleting its token secrets.
     *
     * <p>
     * When a ServiceAccount is identified as compromised (e.g., token used from
     * unexpected container), this method deletes all associated token secrets.
     * Kubernetes will automatically re-create them with new tokens, effectively
     * invalidating any stolen credentials.
     * </p>
     *
     * @param namespace the namespace of the ServiceAccount
     * @param name      the name of the ServiceAccount
     */
    public void rotateToken(String namespace, String name) {
        if (coreApi == null) {
            log.error("Cannot rotate token: ServiceAccountWatcher not started");
            return;
        }

        try {
            // Read the current ServiceAccount to get its secret references
            V1ServiceAccount sa = coreApi.readNamespacedServiceAccount(name, namespace).execute();

            if (sa.getSecrets() == null || sa.getSecrets().isEmpty()) {
                log.info("ServiceAccount {}/{} has no token secrets to rotate", namespace, name);
                return;
            }

            int deleted = 0;
            for (V1ObjectReference secretRef : sa.getSecrets()) {
                String secretName = secretRef.getName();
                if (secretName != null && secretName.contains("token")) {
                    try {
                        coreApi.deleteNamespacedSecret(secretName, namespace).execute();
                        deleted++;
                        log.info("Deleted token secret {}/{} for SA rotation", namespace, secretName);
                    } catch (Exception e) {
                        log.warn("Failed to delete token secret {}/{}: {}", namespace, secretName, e.getMessage());
                    }
                }
            }

            log.info("Token rotation complete for {}/{}: deleted {} secrets", namespace, name, deleted);

        } catch (Exception e) {
            log.error("Failed to rotate token for ServiceAccount {}/{}: {}", namespace, name, e.getMessage(), e);
        }
    }
}
