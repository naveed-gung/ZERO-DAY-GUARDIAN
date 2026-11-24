# ============================================================================
# Zero-Day Guardian -- eBPF Monitor Container Image
#
# Multi-stage build:
#   Stage 1: Rust nightly + bpf-linker, compile eBPF and userspace
#   Stage 2: Minimal runtime with static binary
#
# Author: Naveed Gung
# License: Apache-2.0
# ============================================================================

# --- Stage 1: Build ---
FROM rust:bookworm AS builder

RUN rustup toolchain install nightly --profile minimal --component rust-src
RUN rustup default nightly

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libelf-dev \
    musl-tools \
    zstd \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install bpf-linker for eBPF compilation
COPY install-bpf-linker.sh /tmp/install-bpf-linker.sh
RUN bash /tmp/install-bpf-linker.sh /usr/local/bin

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY ebpf-monitor-common ebpf-monitor-common
COPY ebpf-monitor-ebpf ebpf-monitor-ebpf
COPY ebpf-monitor ebpf-monitor

# Build the eBPF programs and userspace loader
# Use musl for a fully static binary
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl -p ebpf-monitor

# --- Stage 2: Runtime ---
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="Zero-Day Guardian eBPF Monitor"
LABEL org.opencontainers.image.description="eBPF-based syscall and network monitoring agent"
LABEL org.opencontainers.image.authors="Naveed Gung"
LABEL org.opencontainers.image.source="https://github.com/naveed-gung/zero-day-guardian"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/ebpf-monitor /app/ebpf-loader

# Ring buffer mount point
VOLUME ["/shared/ringbuf"]

USER 65532:65532

ENTRYPOINT ["/app/ebpf-loader"]
