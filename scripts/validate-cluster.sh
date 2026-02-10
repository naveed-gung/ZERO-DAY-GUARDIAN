#!/usr/bin/env bash
# validate-cluster.sh - Validate the cluster environment for Zero-Day Guardian
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[PASS]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail_check() { echo -e "${RED}[FAIL]${NC}  $*"; ERRORS=$((ERRORS + 1)); }

ERRORS=0

info "======================================"
info " Zero-Day Guardian - Cluster Validation"
info "======================================"
echo

# ------------------------------------------------------------------
# Kubernetes Connectivity
# ------------------------------------------------------------------
info "--- Kubernetes Connectivity ---"

if kubectl cluster-info &>/dev/null; then
    ok "Cluster is reachable"
    CONTEXT=$(kubectl config current-context)
    info "  Context: $CONTEXT"
else
    fail_check "Cannot connect to Kubernetes cluster"
fi

# ------------------------------------------------------------------
# Kubernetes Version
# ------------------------------------------------------------------
info ""
info "--- Kubernetes Version ---"

K8S_VERSION=$(kubectl version --short 2>/dev/null | grep "Server" | grep -oP 'v\d+\.\d+' || kubectl version -o json 2>/dev/null | grep -oP '"gitVersion":\s*"v\K\d+\.\d+' | head -1)
if [[ -n "$K8S_VERSION" ]]; then
    MINOR=$(echo "$K8S_VERSION" | grep -oP '\d+$')
    if [[ "$MINOR" -ge 28 ]]; then
        ok "Kubernetes $K8S_VERSION (>= 1.28 required)"
    else
        warn "Kubernetes $K8S_VERSION (1.28+ recommended)"
    fi
else
    warn "Could not determine Kubernetes version"
fi

# ------------------------------------------------------------------
# Node Kernel Version
# ------------------------------------------------------------------
info ""
info "--- Node Kernel Versions ---"

NODES=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kernelVersion}{"\t"}{.status.nodeInfo.operatingSystem}{"\n"}{end}' 2>/dev/null)
if [[ -n "$NODES" ]]; then
    while IFS=$'\t' read -r name kernel os; do
        MAJOR=$(echo "$kernel" | cut -d. -f1)
        MINOR=$(echo "$kernel" | cut -d. -f2)
        if [[ "$os" != "linux" ]]; then
            warn "  $name: $os ($kernel) - Linux required"
        elif [[ "$MAJOR" -gt 5 ]] || { [[ "$MAJOR" -eq 5 ]] && [[ "$MINOR" -ge 10 ]]; }; then
            ok "  $name: $os ($kernel)"
        else
            fail_check "  $name: kernel $kernel < 5.10 (eBPF support insufficient)"
        fi
    done <<< "$NODES"
else
    warn "Could not retrieve node information"
fi

# ------------------------------------------------------------------
# RBAC Permissions
# ------------------------------------------------------------------
info ""
info "--- RBAC Permissions ---"

for resource in "pods" "daemonsets.apps" "networkpolicies.networking.k8s.io" "events" "secrets"; do
    if kubectl auth can-i create "$resource" --all-namespaces &>/dev/null; then
        ok "  Can create $resource"
    else
        fail_check "  Cannot create $resource (cluster-admin required)"
    fi
done

# ------------------------------------------------------------------
# CRD Support
# ------------------------------------------------------------------
info ""
info "--- CRD Support ---"

if kubectl api-resources | grep -q "customresourcedefinitions"; then
    ok "CRD API available"
else
    fail_check "CRD API not available"
fi

# Check if Guardian CRD exists
if kubectl get crd guardianpolicies.guardian.zerodayguardian.io &>/dev/null; then
    ok "GuardianPolicy CRD installed"
else
    warn "GuardianPolicy CRD not installed (run: kubectl apply -f deploy/base/crd/)"
fi

# ------------------------------------------------------------------
# Network Policies
# ------------------------------------------------------------------
info ""
info "--- Network Policy Support ---"

if kubectl api-resources | grep -q "networkpolicies"; then
    ok "NetworkPolicy API available"
    warn "  Note: NetworkPolicy enforcement depends on your CNI plugin"
    warn "  Supported: Calico, Cilium, Weave Net, Antrea"
else
    fail_check "NetworkPolicy API not available"
fi

# ------------------------------------------------------------------
# Guardian Namespace
# ------------------------------------------------------------------
info ""
info "--- Guardian Namespace ---"

if kubectl get namespace guardian-system &>/dev/null; then
    ok "guardian-system namespace exists"

    # Check existing resources
    PODS=$(kubectl -n guardian-system get pods --no-headers 2>/dev/null | wc -l)
    info "  Pods: $PODS"

    DS=$(kubectl -n guardian-system get daemonsets --no-headers 2>/dev/null | wc -l)
    info "  DaemonSets: $DS"

    DEPLOY=$(kubectl -n guardian-system get deployments --no-headers 2>/dev/null | wc -l)
    info "  Deployments: $DEPLOY"
else
    info "guardian-system namespace does not exist (will be created on deploy)"
fi

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo
info "======================================"
if [[ $ERRORS -eq 0 ]]; then
    ok "All validation checks passed"
    info "The cluster is ready for Zero-Day Guardian deployment"
else
    echo -e "${RED}[FAIL]${NC}  $ERRORS check(s) failed - address issues before deploying"
fi
