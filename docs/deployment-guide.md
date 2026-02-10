# Deployment Guide

## Prerequisites

- Kubernetes cluster v1.28+ with Linux nodes
- Linux kernel >= 5.10 on worker nodes (for eBPF support)
- `kubectl` configured with cluster admin access
- `kustomize` v5+ installed
- Container runtime with cgroup v2 support

## Quick Start

### 1. Install CRDs

```bash
kubectl apply -f deploy/base/crd/guardianpolicy-crd.yaml
```

### 2. Configure Secrets

Create the secrets file with your actual API keys:

```bash
kubectl create namespace guardian-system

kubectl create secret generic guardian-secrets \
  --namespace guardian-system \
  --from-literal=virustotal-api-key=YOUR_VT_KEY \
  --from-literal=abuseipdb-api-key=YOUR_ABUSEIPDB_KEY \
  --from-literal=otx-api-key=YOUR_OTX_KEY \
  --from-literal=splunk-hec-token=YOUR_SPLUNK_TOKEN \
  --from-literal=elastic-api-key=YOUR_ELASTIC_KEY
```

### 3. Deploy (Development)

```bash
kubectl apply -k deploy/overlays/dev
```

### 4. Deploy (Production)

```bash
kubectl apply -k deploy/overlays/prod
```

### 5. Create a GuardianPolicy

```bash
kubectl apply -f deploy/examples/guardianpolicy-sample.yaml
```

### 6. Verify Deployment

```bash
# Check operator status
kubectl -n guardian-system get deployment guardian-operator

# Check monitor DaemonSet
kubectl -n guardian-system get daemonset

# Check GuardianPolicy status
kubectl -n guardian-system get guardianpolicies

# View logs
kubectl -n guardian-system logs -l app.kubernetes.io/component=operator -f
kubectl -n guardian-system logs -l app.kubernetes.io/component=monitor -c ebpf-monitor -f
kubectl -n guardian-system logs -l app.kubernetes.io/component=monitor -c detection-engine -f
```

## Configuration

### Environment Variables

All configuration is managed through the `guardian-config` ConfigMap and `guardian-secrets` Secret.

#### Ring Buffer

| Variable                               | Default                            | Description                        |
| -------------------------------------- | ---------------------------------- | ---------------------------------- |
| `GUARDIAN_RINGBUFFER_PATH`             | `/var/guardian/ringbuf/events.buf` | Path to shared ring buffer file    |
| `GUARDIAN_RINGBUFFER_SIZE`             | `16777216`                         | Ring buffer size in bytes (16 MiB) |
| `GUARDIAN_RINGBUFFER_POLL_INTERVAL_MS` | `50`                               | Polling interval in milliseconds   |

#### Detection

| Variable                               | Default | Description                       |
| -------------------------------------- | ------- | --------------------------------- |
| `GUARDIAN_DETECTION_CONTAINER_ESCAPE`  | `true`  | Enable container escape detection |
| `GUARDIAN_DETECTION_CRYPTOJACKING`     | `true`  | Enable cryptojacking detection    |
| `GUARDIAN_DETECTION_LATERAL_MOVEMENT`  | `true`  | Enable lateral movement detection |
| `GUARDIAN_DETECTION_SEQUENCE_ANALYSIS` | `true`  | Enable syscall sequence analysis  |

#### Response

| Variable                                       | Default           | Description                            |
| ---------------------------------------------- | ----------------- | -------------------------------------- |
| `GUARDIAN_ACTION_DRY_RUN`                      | `false`           | Log actions without executing          |
| `GUARDIAN_ACTION_RATE_LIMIT_PER_MINUTE`        | `10`              | Max automated actions per minute       |
| `GUARDIAN_ACTION_EXCLUDED_NAMESPACES`          | `kube-system,...` | Protected namespaces (comma-separated) |
| `GUARDIAN_ACTION_MIN_SEVERITY_FOR_AUTO_ACTION` | `HIGH`            | Minimum severity for auto-response     |

#### Threat Intelligence

| Variable                                    | Source | Description            |
| ------------------------------------------- | ------ | ---------------------- |
| `GUARDIAN_THREAT_INTEL_VIRUS_TOTAL_API_KEY` | Secret | VirusTotal API key     |
| `GUARDIAN_THREAT_INTEL_ABUSE_IP_DB_API_KEY` | Secret | AbuseIPDB API key      |
| `GUARDIAN_THREAT_INTEL_OTX_API_KEY`         | Secret | AlienVault OTX API key |

#### SIEM Integration

| Variable                         | Source    | Description                     |
| -------------------------------- | --------- | ------------------------------- |
| `GUARDIAN_SIEM_SPLUNK_HEC_URL`   | ConfigMap | Splunk HEC endpoint URL         |
| `GUARDIAN_SIEM_SPLUNK_HEC_TOKEN` | Secret    | Splunk HEC authentication token |
| `GUARDIAN_SIEM_ELASTIC_URL`      | ConfigMap | Elasticsearch endpoint URL      |
| `GUARDIAN_SIEM_ELASTIC_API_KEY`  | Secret    | Elasticsearch API key           |

### GuardianPolicy Custom Resource

The `GuardianPolicy` CRD provides a declarative interface for configuring monitoring:

```yaml
apiVersion: guardian.zerodayguardian.io/v1alpha1
kind: GuardianPolicy
metadata:
  name: production-policy
  namespace: guardian-system
spec:
  nodeSelector:
    kubernetes.io/os: linux
    node-role.kubernetes.io/worker: ""
  detection:
    containerEscape: true
    cryptojacking: true
    lateralMovement: true
    sequenceAnalysis: true
  response:
    autoIsolate: true
    autoNetworkBlock: true
    dryRun: false
    rateLimitPerMinute: 5
    excludedNamespaces:
      - kube-system
      - kube-public
      - kube-node-lease
      - monitoring
  threatIntel:
    virusTotalSecretRef:
      name: guardian-secrets
      key: virustotal-api-key
  siem:
    splunkHecUrl: "https://splunk.internal:8088/services/collector"
    splunkHecTokenSecretRef:
      name: guardian-secrets
      key: splunk-hec-token
```

## Scaling Considerations

### Node Coverage

The DaemonSet ensures one monitoring pod per node. The operator respects `nodeSelector` from the GuardianPolicy, allowing you to target specific node pools.

### Resource Tuning

| Component        | Dev CPU   | Dev Memory | Prod CPU | Prod Memory |
| ---------------- | --------- | ---------- | -------- | ----------- |
| ebpf-monitor     | 100m-250m | 128-256Mi  | 200m-1   | 256-512Mi   |
| detection-engine | 200m-500m | 256Mi      | 500m-2   | 512Mi-1Gi   |
| operator         | 50m-200m  | 64-128Mi   | 50m-200m | 64-128Mi    |

### Metrics and Monitoring

The detection engine exposes Prometheus metrics on port 8081 at `/actuator/prometheus`:

- `guardian_events_processed_total` - Total events processed
- `guardian_detections_total` - Total threat detections by type
- `guardian_actions_taken_total` - Total automated actions
- `guardian_ring_buffer_usage_ratio` - Ring buffer utilization

## Uninstallation

```bash
# Remove policy (triggers DaemonSet cleanup via finalizer)
kubectl -n guardian-system delete guardianpolicies --all

# Remove all resources
kubectl delete -k deploy/overlays/dev  # or prod

# Remove CRDs
kubectl delete -f deploy/base/crd/guardianpolicy-crd.yaml

# Remove namespace
kubectl delete namespace guardian-system
```

## Troubleshooting

### eBPF programs fail to load

Ensure the kernel supports BPF:

```bash
# Check kernel version (need >= 5.10)
uname -r

# Verify BPF support
ls /sys/kernel/debug/tracing/events/syscalls/
```

### Detection engine cannot read ring buffer

Verify the shared volume is mounted:

```bash
kubectl -n guardian-system exec -it <pod> -c detection-engine -- ls -la /var/guardian/ringbuf/
```

### Operator not reconciling

Check operator logs and leader election:

```bash
kubectl -n guardian-system logs deployment/guardian-operator
kubectl -n guardian-system get leases
```

### High memory usage

Reduce ring buffer size or increase polling frequency:

```yaml
# In configmap
GUARDIAN_RINGBUFFER_SIZE: "8388608" # 8 MiB
GUARDIAN_RINGBUFFER_POLL_INTERVAL_MS: "25" # 25ms
```
