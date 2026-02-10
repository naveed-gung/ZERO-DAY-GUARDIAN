#!/usr/bin/env bash
# build-all.sh - Build all Zero-Day Guardian components
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

ERRORS=0

# ------------------------------------------------------------------
# Rust eBPF Monitor
# ------------------------------------------------------------------
build_rust() {
    info "Building Rust eBPF Monitor..."
    cd "$PROJECT_ROOT/ebpf-monitor"

    if ! command -v cargo &>/dev/null; then
        warn "Rust toolchain not found, skipping eBPF monitor build"
        return
    fi

    # Build eBPF programs
    if cargo xtask build-ebpf 2>/dev/null; then
        ok "eBPF programs compiled"
    else
        warn "eBPF build requires bpf-linker and nightly toolchain"
    fi

    # Build userspace
    if cargo build --release 2>&1; then
        ok "Rust userspace binary built"
    else
        warn "Rust build failed (may need nightly toolchain)"
        ERRORS=$((ERRORS + 1))
    fi

    # Run tests
    if cargo test --workspace --exclude zero-day-guardian-ebpf 2>&1; then
        ok "Rust tests passed"
    else
        warn "Rust tests failed"
        ERRORS=$((ERRORS + 1))
    fi

    cd "$PROJECT_ROOT"
}

# ------------------------------------------------------------------
# Java Detection Engine
# ------------------------------------------------------------------
build_java() {
    info "Building Java Detection Engine..."
    cd "$PROJECT_ROOT/detection-engine"

    if ! command -v java &>/dev/null; then
        warn "Java not found, skipping detection engine build"
        return
    fi

    JAVA_VERSION=$(java -version 2>&1 | head -1 | cut -d'"' -f2 | cut -d'.' -f1)
    if [[ "$JAVA_VERSION" -lt 21 ]]; then
        warn "Java 21+ required, found Java $JAVA_VERSION"
        return
    fi

    if [[ -f "./gradlew" ]]; then
        chmod +x ./gradlew
        if ./gradlew build 2>&1; then
            ok "Java detection engine built and tested"
        else
            warn "Java build failed"
            ERRORS=$((ERRORS + 1))
        fi
    else
        warn "Gradle wrapper not found, skipping Java build"
    fi

    cd "$PROJECT_ROOT"
}

# ------------------------------------------------------------------
# Go Kubernetes Operator
# ------------------------------------------------------------------
build_go() {
    info "Building Go Kubernetes Operator..."
    cd "$PROJECT_ROOT/guardian-operator"

    if ! command -v go &>/dev/null; then
        warn "Go not found, skipping operator build"
        return
    fi

    GO_VERSION=$(go version | grep -oP '1\.\d+' | head -1)
    if [[ "${GO_VERSION#1.}" -lt 22 ]]; then
        warn "Go 1.22+ required, found Go $GO_VERSION"
        return
    fi

    if go build -o bin/manager ./cmd/main.go 2>&1; then
        ok "Go operator binary built"
    else
        warn "Go build failed"
        ERRORS=$((ERRORS + 1))
    fi

    if go test ./... 2>&1; then
        ok "Go tests passed"
    else
        warn "Go tests failed"
        ERRORS=$((ERRORS + 1))
    fi

    cd "$PROJECT_ROOT"
}

# ------------------------------------------------------------------
# Docker Images
# ------------------------------------------------------------------
build_docker() {
    info "Building Docker images..."

    if ! command -v docker &>/dev/null; then
        warn "Docker not found, skipping image builds"
        return
    fi

    local REGISTRY="${REGISTRY:-ghcr.io/naveed-gung/zero-day-guardian}"
    local TAG="${TAG:-dev}"

    for component in ebpf-monitor detection-engine guardian-operator; do
        local context="$PROJECT_ROOT/$component"
        if [[ -f "$context/Dockerfile" ]]; then
            info "  Building $component..."
            if docker build -t "$REGISTRY/$component:$TAG" "$context" 2>&1; then
                ok "  $component:$TAG built"
            else
                warn "  $component Docker build failed"
                ERRORS=$((ERRORS + 1))
            fi
        fi
    done
}

# ------------------------------------------------------------------
# Manifest Validation
# ------------------------------------------------------------------
validate_manifests() {
    info "Validating Kubernetes manifests..."

    if ! command -v kustomize &>/dev/null; then
        warn "kustomize not found, skipping manifest validation"
        return
    fi

    for overlay in dev prod; do
        if kustomize build "$PROJECT_ROOT/deploy/overlays/$overlay" > /dev/null 2>&1; then
            ok "  $overlay overlay validates"
        else
            warn "  $overlay overlay validation failed"
            ERRORS=$((ERRORS + 1))
        fi
    done
}

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
main() {
    info "======================================"
    info " Zero-Day Guardian - Full Build"
    info "======================================"
    echo

    build_rust
    echo
    build_java
    echo
    build_go
    echo

    if [[ "${DOCKER:-false}" == "true" ]]; then
        build_docker
        echo
    fi

    validate_manifests
    echo

    info "======================================"
    if [[ $ERRORS -eq 0 ]]; then
        ok "All builds completed successfully"
    else
        fail "$ERRORS build step(s) failed"
    fi
}

main "$@"
