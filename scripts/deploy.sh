#!/usr/bin/env bash
# deploy.sh - Deploy Zero-Day Guardian to a Kubernetes cluster
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
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

OVERLAY="${1:-dev}"

if [[ "$OVERLAY" != "dev" && "$OVERLAY" != "prod" ]]; then
    fail "Usage: $0 [dev|prod]"
fi

# ------------------------------------------------------------------
# Preflight
# ------------------------------------------------------------------
info "Preflight checks..."

command -v kubectl &>/dev/null || fail "kubectl not found"
command -v kustomize &>/dev/null || fail "kustomize not found"

kubectl cluster-info &>/dev/null || fail "Cannot connect to Kubernetes cluster"
ok "Cluster connection verified"

CURRENT_CONTEXT=$(kubectl config current-context)
info "Deploying to context: $CURRENT_CONTEXT"
info "Overlay: $OVERLAY"

if [[ "$OVERLAY" == "prod" ]]; then
    echo
    warn "PRODUCTION DEPLOYMENT"
    read -rp "Are you sure you want to deploy to production? (yes/no): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        info "Deployment cancelled"
        exit 0
    fi
fi

# ------------------------------------------------------------------
# Deploy
# ------------------------------------------------------------------
echo
info "Step 1: Install CRDs..."
kubectl apply -f "$PROJECT_ROOT/deploy/base/crd/guardianpolicy-crd.yaml"
ok "CRDs installed"

echo
info "Step 2: Apply $OVERLAY overlay..."
kustomize build "$PROJECT_ROOT/deploy/overlays/$OVERLAY" | kubectl apply -f -
ok "Resources applied"

echo
info "Step 3: Wait for operator rollout..."
kubectl -n guardian-system rollout status deployment/guardian-operator --timeout=120s
ok "Operator is ready"

echo
info "Step 4: Verify components..."
echo
kubectl -n guardian-system get pods -o wide
echo
kubectl -n guardian-system get guardianpolicies 2>/dev/null || info "No GuardianPolicy resources found yet"
echo

ok "Deployment complete ($OVERLAY overlay)"
info ""
info "Next steps:"
info "  1. Create secrets: kubectl create secret generic guardian-secrets ..."
info "  2. Apply a policy: kubectl apply -f deploy/examples/guardianpolicy-sample.yaml"
info "  3. Monitor logs:   kubectl -n guardian-system logs -l app.kubernetes.io/component=monitor -f"
