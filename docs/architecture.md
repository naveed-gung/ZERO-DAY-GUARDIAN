# Architecture

## System Overview

Zero-Day Guardian is a Kubernetes-native security monitoring system that operates at three distinct layers:

1. **Kernel Space** - eBPF programs intercept syscalls at the kernel level
2. **User Space** - Detection engine analyzes events and orchestrates responses
3. **Control Plane** - Kubernetes operator manages the lifecycle of monitoring components

## Component Architecture

### eBPF Monitor (Rust / Aya-rs)

The eBPF monitor runs as a privileged container with `hostPID: true` to attach eBPF programs to kernel tracepoints and XDP hooks.

**eBPF Programs:**

| Program         | Type       | Hook Point                   | Purpose                               |
| --------------- | ---------- | ---------------------------- | ------------------------------------- |
| `trace_execve`  | Tracepoint | `syscalls/sys_enter_execve`  | Process execution monitoring          |
| `trace_unshare` | Tracepoint | `syscalls/sys_enter_unshare` | Namespace manipulation detection      |
| `trace_mount`   | Tracepoint | `syscalls/sys_enter_mount`   | Filesystem mount surveillance         |
| `trace_ptrace`  | Tracepoint | `syscalls/sys_enter_ptrace`  | Process debugging/injection detection |
| `xdp_monitor`   | XDP        | Network interface            | Network packet inspection             |

**Data Path:**

eBPF programs populate a fixed-size 384-byte `SyscallEvent` structure and write it to a shared SPSC (Single Producer, Single Consumer) ring buffer backed by a memory-mapped tmpfs volume.

### Detection Engine (Java / Spring Boot)

The detection engine is the analytical core, consuming events from the ring buffer and applying multiple detection strategies:

**Detection Modules:**

- **ContainerEscapeDetector** - CVE-2019-5736, runc exploitation, namespace breakout, sensitive mount detection
- **CryptojackingDetector** - Mining binary identification, mining pool port detection, rapid execution patterns
- **LateralMovementDetector** - Kubernetes tool usage, reconnaissance commands, pivot tools, IMDS access
- **SyscallSequenceAnalyzer** - Sliding-window pattern matching for multi-step attack sequences

**Safety Gates (SRS Section 8 Compliance):**

Every automated action passes through 5 safety gates before execution:

1. Severity threshold check (minimum HIGH for auto-action)
2. Namespace exclusion verification (kube-system, etc.)
3. Approval gate (operator acknowledgment for CRITICAL)
4. Rate limiting (configurable per-minute cap)
5. Dry-run bypass (log-only mode)

### Guardian Operator (Go / Kubebuilder)

The operator manages `GuardianPolicy` custom resources and reconciles the desired state:

- Creates/updates DaemonSets with the correct pod specification
- Manages the lifecycle of monitoring pods across cluster nodes
- Reports status via CRD status subresource and conditions
- Implements finalizer pattern for clean resource deletion

## Data Flow

```
Kernel Syscall
     |
     v
eBPF Program (tracepoint/XDP)
     |
     v
SyscallEvent (384 bytes, #[repr(C)])
     |
     v
SPSC Ring Buffer (16 MiB, tmpfs emptyDir)
     |
     v
RingBufferReader (MappedByteBuffer + VarHandle)
     |
     v
AttackDetector (dispatcher)
     |
     +---> ContainerEscapeDetector
     +---> CryptojackingDetector
     +---> LateralMovementDetector
     +---> SyscallSequenceAnalyzer
     |
     v
DetectionResult
     |
     +---> SafeActionExecutor (5 safety gates)
     |         +---> PodIsolator (quarantine label)
     |         +---> NetworkBlocker (deny-all NetworkPolicy)
     |
     +---> ThreatIntelService (VirusTotal, AbuseIPDB, OTX)
     |
     +---> AlertService
     |         +---> SplunkIntegration (HEC)
     |         +---> ElasticIntegration (date-based indices)
     |
     +---> EvidenceCollector (forensic artifacts)
     |
     +---> GuardianMetrics (Prometheus/Micrometer)
```

## Ring Buffer Protocol

The shared ring buffer uses a lock-free SPSC design:

- **Header**: 64 bytes at offset 0
  - `write_pos` (u64, offset 0): Atomic write position, Release ordering
  - `read_pos` (u64, offset 8): Atomic read position, Acquire ordering
  - `capacity` (u64, offset 16): Total buffer capacity in bytes
  - `event_size` (u64, offset 24): Fixed event size (384 bytes)
  - `magic` (u64, offset 32): Validation magic `0x5A44475F52494E47`
  - Padding to 64 bytes

- **Data Region**: Starts at offset 64, wraps circularly
- **Event Size**: 384 bytes fixed, `#[repr(C)]` layout
- **Volume**: `emptyDir` with `medium: Memory`, 16 MiB capacity (~43,690 events)

## Kubernetes Resource Model

```
GuardianPolicy (CRD)
    |
    |--- reconciles --->  DaemonSet (guardian-monitor-{name})
    |                         |
    |                         +--- Pod
    |                               +--- ebpf-monitor (privileged)
    |                               +--- detection-engine
    |                               +--- [shared volumes]
    |
    |--- manages --->     ClusterRole / ClusterRoleBinding
    |
    |--- references --->  Secret (API keys)
    |
    |--- references --->  ConfigMap (runtime config)
```

## Network Architecture

The detection engine communicates with:

- **Kubernetes API Server** - Pod isolation, NetworkPolicy creation, audit log streaming
- **Threat Intelligence APIs** - VirusTotal, AbuseIPDB, AlienVault OTX (outbound HTTPS)
- **SIEM Platforms** - Splunk HEC, Elasticsearch (outbound HTTPS)
- **Prometheus** - Metrics endpoint on port 8081

No intra-pod networking is required between the eBPF monitor and detection engine; they communicate exclusively via the shared ring buffer memory volume.
