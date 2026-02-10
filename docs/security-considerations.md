# Security Considerations

## Threat Model

Zero-Day Guardian operates as a security-critical component within the Kubernetes cluster. This document outlines the security measures, assumptions, and risk mitigations built into the system.

## Privilege Requirements

### eBPF Monitor Container

The eBPF monitor requires elevated privileges to attach programs to kernel tracepoints:

| Requirement               | Justification                                          |
| ------------------------- | ------------------------------------------------------ |
| `privileged: true`        | Required for `bpf()` syscall and tracepoint attachment |
| `hostPID: true`           | Access to host process namespace for PID correlation   |
| `runAsUser: 0`            | eBPF program loading requires root                     |
| `/sys/kernel/debug` mount | Access to kernel debug filesystem for tracepoints      |
| `/proc` mount (read-only) | Process metadata resolution (cgroup, cmdline)          |

**Mitigation**: The eBPF monitor binary is statically compiled from auditable Rust source code. The container uses `gcr.io/distroless/cc-debian12` as the base image, minimizing attack surface.

### Detection Engine Container

The detection engine runs with standard privileges and communicates with the Kubernetes API using a dedicated ServiceAccount:

| Permission                | Resource          | Justification                          |
| ------------------------- | ----------------- | -------------------------------------- |
| `get, list, watch, patch` | Pods              | Pod inspection and quarantine labeling |
| `create`                  | Pods/Eviction     | Pod eviction for critical threats      |
| `create, update, delete`  | NetworkPolicies   | Deny-all policy for quarantined pods   |
| `get, list, watch`        | Nodes, Namespaces | Cluster topology awareness             |
| `get`                     | Secrets           | Threat intel API key retrieval         |
| `create, patch`           | Events            | Audit trail for all actions            |

### Operator Container

The operator runs as `nonRoot` with `readOnlyRootFilesystem` and drops all capabilities:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop: [ALL]
```

## Safety Mechanisms (SRS Section 8)

### Five Safety Gates

Every automated response action must pass through all five gates sequentially:

1. **Severity Threshold** - Only HIGH and CRITICAL severity detections trigger automated actions
2. **Namespace Exclusion** - Critical namespaces (kube-system, kube-public, kube-node-lease) are protected from automated isolation
3. **Approval Gate** - CRITICAL severity actions require operator approval (configurable)
4. **Rate Limiting** - Sliding window limits automated actions per minute (default: 10/min)
5. **Dry-Run Mode** - When enabled, all actions are logged without execution

### Fail-Safe Defaults

- Dry-run mode is enabled by default in the dev overlay
- Rate limiting defaults to 10 actions per minute
- The operator namespace (`guardian-system`) is always excluded from automated actions
- Network policies only apply to pods explicitly labeled with `guardian.zerodayguardian.io/quarantine=true`

## Secret Management

### API Keys

All sensitive credentials are stored in Kubernetes Secrets and injected via `secretKeyRef`:

- VirusTotal API key
- AbuseIPDB API key
- AlienVault OTX API key
- Splunk HEC token
- Elasticsearch API key

**Recommendations for production:**

- Use [sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) or [external-secrets-operator](https://external-secrets.io/) for secret management
- Enable Secret encryption at rest in the Kubernetes API server
- Rotate API keys regularly and use short-lived tokens where possible

### RBAC Least Privilege

Each component uses a dedicated ServiceAccount with the minimum required permissions:

- `guardian-monitor` - Pod read/patch, NetworkPolicy CRUD, Event creation
- `guardian-operator` - CRD management, DaemonSet CRUD, leader election

## Container Image Security

### Build Process

- All images use multi-stage Docker builds to minimize final image size
- eBPF monitor uses `gcr.io/distroless/cc-debian12` (no shell, no package manager)
- Detection engine uses `eclipse-temurin:21-jre` (minimal Java runtime)
- Operator uses `gcr.io/distroless/static:nonroot` (completely static, no libc)

### Supply Chain

- CI pipeline runs Trivy vulnerability scanning on all built images
- Images are signed and published to GHCR with content-addressable tags
- Dependencies are pinned to specific versions in all build files

## Network Security

### Internal Communication

The eBPF monitor and detection engine communicate exclusively through a shared memory volume (tmpfs `emptyDir`). No network sockets are used for intra-pod communication, eliminating network-based attack vectors on the data path.

### External Communication

| Destination    | Protocol           | Purpose                      |
| -------------- | ------------------ | ---------------------------- |
| Kubernetes API | HTTPS (in-cluster) | Pod management, audit logs   |
| VirusTotal     | HTTPS              | File hash and IP reputation  |
| AbuseIPDB      | HTTPS              | IP abuse checking            |
| AlienVault OTX | HTTPS              | Multi-indicator threat intel |
| Splunk HEC     | HTTPS              | Alert delivery               |
| Elasticsearch  | HTTPS              | Alert and event indexing     |

All external HTTPS connections use system trust stores. Custom CA certificates can be mounted if required.

## Audit Trail

Every automated action generates:

1. A Kubernetes Event on the target pod
2. An audit log entry via `ActionTracker`
3. A SIEM alert via configured integrations
4. A forensic evidence package (event JSON, detection JSON, timeline log)

The audit trail is immutable once written and can be used for post-incident analysis and compliance reporting.

## Known Limitations

- The eBPF monitor requires a Linux kernel version >= 5.10 for full BPF feature support
- `hostPID: true` provides access to all host processes, which is a broad privilege
- The ring buffer uses fixed-size events (384 bytes), limiting the amount of per-event context
- Container ID resolution depends on cgroup v2 naming conventions
- The detection engine must be restarted to pick up configuration changes (no hot-reload)
