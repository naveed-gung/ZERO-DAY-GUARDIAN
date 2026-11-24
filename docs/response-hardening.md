# Runtime security and response verification

Guardian is headless. Operators use GuardianPolicy status for rollout and response
mode, Prometheus for telemetry, and audit logs for action outcomes.

## Observe-only baseline

The sample policy, Java defaults, and deployment overlays start in observe-only
mode. Treat a privileged sensor and its host mounts as part of the node trust
boundary. The node monitor's default API permissions allow discovery reads. The
operator has a Role scoped to guardian-system.

An upgrade from the former ClusterRoleBinding-based operator may leave that
ClusterRoleBinding behind. Verify the new namespaced RoleBinding first, then
remove the obsolete guardian-operator ClusterRoleBinding and ClusterRole through
your existing deployment workflow. Preserve the guardian-monitor binding, which
is still used for discovery. Use one DaemonSet owner for each set of nodes.

## Optional pod labeling

Keep system namespaces excluded. For an opted-in workload namespace, customize
the namespace-scoped Role and RoleBinding in
[workload-label-rbac.yaml](../deploy/examples/workload-label-rbac.yaml).
Set the policy's approvedNamespaces to that namespace and dryRun to false.

The audit trail uses LABEL_APPLIED to indicate that the Kubernetes API accepted
the label. ALREADY_LABELED indicates a repeated request. TARGET_UNRESOLVED
indicates that there was no unique live container match. KUBERNETES_API_ERROR
indicates an API failure or optimistic concurrency conflict.

For a Cilium cluster, scope [cilium-quarantine.yaml](../deploy/examples/cilium-quarantine.yaml)
to the same opted-in namespace. Cilium deny rules take precedence over allow
rules. The operator and detector do not claim that the dataplane enforced a
label. Generic NetworkPolicy semantics are additive, so use a verified CNI
policy when you need containment against existing allows.

## Release acceptance on a disposable Linux cluster

- Render both overlays and confirm the approved namespace list starts empty,
  write mode is disabled and no cluster-wide Secret read exists.
- Start with an ordinary workload that runs a harmless shell command. Confirm
  Guardian's read metric increases and the sensor logs report whether events
  were dropped. Check the decoder error counter and readiness before evaluating
  detector coverage.
- Replay benign event records in a test environment. Check that absent,
  stale, and ambiguous workloads yield zero API writes, a repeated event yields
  one label, and a pod replacement causes a resource-version conflict.
- With Cilium and two disposable workloads, verify connectivity in both directions
  before labeling. Apply the label to one workload, verify both directions are
  blocked even with an existing allow policy, and confirm the unlabelled peer
  retains its baseline connectivity. Remove the label and verify recovery.
- Publish kernel, container runtime and CNI versions, event counts, event drops,
  CPU/RAM per node, p50/p95 processing latency, and false positives from a normal
  workload corpus. Use the same workload and resource limits for any comparison.
  The sensor uses a monotonic clock. Calculate latency from compatible clock
  sources and use a separate UTC timestamp for audit and SIEM delivery.

## Remaining release gates

A separate responder identity would remove opt-in patch authority from the
privileged node DaemonSet. Keep process termination outside automated response
until that boundary, explicit approval, and process identity checks are tested.
Live Kubernetes behavior, CNI compatibility, failure recovery and load
benchmarks require a Linux test cluster.
