//! Configuration for the eBPF monitor userspace loader.
//!
//! All values are read from environment variables with sensible defaults.
//!
//! Author: Naveed Gung

use clap::Parser;

/// Command-line and environment-based configuration for the eBPF monitor.
#[derive(Parser, Debug, Clone)]
#[command(name = "ebpf-monitor", about = "Zero-Day Guardian eBPF Node Agent")]
pub struct Config {
    /// Path to the shared ring buffer file (tmpfs mount).
    #[arg(long, env = "RING_BUFFER_PATH", default_value = "/shared/ringbuf/events.buf")]
    pub ring_buffer_path: String,

    /// Size of the ring buffer data region in MiB (must be a power of 2).
    #[arg(long, env = "RING_BUFFER_SIZE_MB", default_value_t = 16)]
    pub ring_buffer_size_mb: u64,

    /// Network interface name for the XDP program.
    #[arg(long, env = "XDP_INTERFACE", default_value = "eth0")]
    pub xdp_interface: String,

    /// Kubernetes node name (injected via downward API).
    #[arg(long, env = "NODE_NAME", default_value = "unknown")]
    pub node_name: String,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, env = "LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Whether to enable the XDP network monitoring program.
    #[arg(long, env = "ENABLE_XDP", default_value_t = true)]
    pub enable_xdp: bool,
}

impl Config {
    /// Ring buffer data region size in bytes.
    pub fn ring_buffer_size_bytes(&self) -> u64 {
        self.ring_buffer_size_mb * 1024 * 1024
    }

    /// Validate that ring buffer size is a power of 2.
    pub fn validate(&self) -> anyhow::Result<()> {
        let size = self.ring_buffer_size_bytes();
        if size == 0 || (size & (size - 1)) != 0 {
            anyhow::bail!(
                "Ring buffer size must be a power of 2, got {} MiB",
                self.ring_buffer_size_mb
            );
        }
        Ok(())
    }
}
