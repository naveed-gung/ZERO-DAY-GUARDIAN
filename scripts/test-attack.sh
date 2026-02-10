#!/usr/bin/env bash
# test-attack.sh - Simulate attack scenarios to validate detection
#
# WARNING: These simulations create benign but suspicious activity.
# Only run in isolated test/dev clusters.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

NAMESPACE="guardian-test"
TEST_POD="attack-sim"

cleanup() {
    info "Cleaning up test resources..."
    kubectl delete namespace "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null || true
}

trap cleanup EXIT

# ------------------------------------------------------------------
# Setup
# ------------------------------------------------------------------
info "======================================"
info " Zero-Day Guardian - Attack Simulation"
info "======================================"
echo
warn "This script creates benign but suspicious activity for testing."
warn "Only run in isolated development/test clusters."
echo

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
ok "Test namespace created: $NAMESPACE"

# ------------------------------------------------------------------
# Test 1: Container Escape Indicators
# ------------------------------------------------------------------
info ""
info "--- Test 1: Container Escape Indicators ---"
info "Creating pod that exercises escape-like patterns..."

kubectl -n "$NAMESPACE" run "$TEST_POD-escape" \
    --image=busybox:latest \
    --restart=Never \
    --command -- sh -c '
        echo "Simulating container escape indicators..."
        # Attempt to read sensitive paths (will fail but triggers detection)
        cat /proc/1/cgroup 2>/dev/null || true
        ls /var/run/docker.sock 2>/dev/null || true
        ls /run/containerd/containerd.sock 2>/dev/null || true
        echo "Test 1 complete"
        sleep 5
    '

kubectl -n "$NAMESPACE" wait --for=condition=Ready pod/"$TEST_POD-escape" --timeout=30s 2>/dev/null || true
sleep 10
ok "Container escape simulation complete"

# ------------------------------------------------------------------
# Test 2: Cryptojacking Indicators
# ------------------------------------------------------------------
info ""
info "--- Test 2: Cryptojacking Indicators ---"
info "Creating pod with mining-like process names..."

kubectl -n "$NAMESPACE" run "$TEST_POD-crypto" \
    --image=busybox:latest \
    --restart=Never \
    --command -- sh -c '
        echo "Simulating cryptojacking indicators..."
        # Create files with suspicious names (not actual miners)
        touch /tmp/xmrig-sim
        touch /tmp/minerd-sim
        # CPU-intensive but harmless calculation
        i=0; while [ $i -lt 100 ]; do echo "$i * $i" | bc 2>/dev/null || true; i=$((i+1)); done
        echo "Test 2 complete"
        sleep 5
    '

kubectl -n "$NAMESPACE" wait --for=condition=Ready pod/"$TEST_POD-crypto" --timeout=30s 2>/dev/null || true
sleep 10
ok "Cryptojacking simulation complete"

# ------------------------------------------------------------------
# Test 3: Lateral Movement Indicators
# ------------------------------------------------------------------
info ""
info "--- Test 3: Lateral Movement Indicators ---"
info "Creating pod with reconnaissance-like activity..."

kubectl -n "$NAMESPACE" run "$TEST_POD-lateral" \
    --image=busybox:latest \
    --restart=Never \
    --command -- sh -c '
        echo "Simulating lateral movement indicators..."
        # Service account token access attempt
        cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 10 || true
        # DNS resolution (legitimate but part of recon pattern)
        nslookup kubernetes.default.svc.cluster.local 2>/dev/null || true
        # Internal network scanning simulation
        echo "Would scan: 10.0.0.0/24" > /dev/null
        echo "Test 3 complete"
        sleep 5
    '

kubectl -n "$NAMESPACE" wait --for=condition=Ready pod/"$TEST_POD-lateral" --timeout=30s 2>/dev/null || true
sleep 10
ok "Lateral movement simulation complete"

# ------------------------------------------------------------------
# Verification
# ------------------------------------------------------------------
info ""
info "--- Verification ---"
info "Checking for Guardian detections..."
echo

# Check pod quarantine labels
QUARANTINED=$(kubectl -n "$NAMESPACE" get pods -l guardian.zerodayguardian.io/quarantine=true --no-headers 2>/dev/null | wc -l)
info "Quarantined pods: $QUARANTINED"

# Check NetworkPolicies
NETPOLS=$(kubectl -n "$NAMESPACE" get networkpolicies --no-headers 2>/dev/null | wc -l)
info "NetworkPolicies created: $NETPOLS"

# Check Guardian events
info ""
info "Guardian events in test namespace:"
kubectl -n "$NAMESPACE" get events --field-selector reason=GuardianDetection 2>/dev/null || info "No detection events found (may need Guardian to be running)"

# Check detection engine logs
info ""
info "Recent detection engine logs:"
kubectl -n guardian-system logs -l app.kubernetes.io/component=monitor \
    -c detection-engine --tail=20 2>/dev/null || info "Cannot access detection engine logs"

echo
info "======================================"
ok "Attack simulation testing complete"
info "Review detection engine logs for detailed analysis"
