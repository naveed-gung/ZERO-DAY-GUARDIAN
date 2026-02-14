//! Zero-Day Guardian — eBPF Node Agent Userspace Loader
//!
//! This binary loads eBPF programs into the kernel, attaches them to
//! tracepoints and XDP hooks, reads events from PerfEventArrays, and
//! writes them to the shared ring buffer for the Java detection engine.
//!
//! Author: Naveed Gung
//! License: Apache-2.0

mod config;
mod container;
mod ringbuf_writer;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{TracePoint, Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::Ebpf;
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{error, info, warn};
use tokio::sync::Mutex;
use tokio::task;

use config::Config;
use container::ContainerResolver;
use ebpf_monitor_common::{SyscallEvent, EVENT_SIZE};
use ringbuf_writer::RingBufWriter;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();
    config.validate()?;

    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&config.log_level))
        .format_timestamp_millis()
        .init();

    info!("=== Zero-Day Guardian eBPF Node Agent ===");
    info!("Node: {}", config.node_name);
    info!(
        "Ring buffer: {} ({} MiB)",
        config.ring_buffer_path, config.ring_buffer_size_mb
    );
    info!(
        "XDP interface: {} (enabled: {})",
        config.xdp_interface, config.enable_xdp
    );

    // Initialize the shared ring buffer writer
    let ring_buf = Arc::new(Mutex::new(
        RingBufWriter::new(
            Path::new(&config.ring_buffer_path),
            config.ring_buffer_size_bytes(),
        )
        .context("Failed to initialize ring buffer")?,
    ));

    // Initialize the container resolver
    let resolver = ContainerResolver::new();

    // Load the compiled eBPF object
    info!("Loading eBPF programs...");
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-monitor"
    )))
    .context("Failed to load eBPF programs")?;

    // Initialize eBPF logging (forwards aya-log-ebpf messages to the log crate)
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!(
            "Failed to initialize eBPF logger: {}. eBPF log messages will be lost.",
            e
        );
    }

    // ------------------------------------------------------------------
    // Attach tracepoints
    // ------------------------------------------------------------------

    // sys_enter_execve
    let program: &mut TracePoint = ebpf
        .program_mut("trace_execve")
        .context("trace_execve program not found")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;
    info!("Attached: tracepoint/syscalls/sys_enter_execve");

    // sys_enter_unshare
    let program: &mut TracePoint = ebpf
        .program_mut("trace_unshare")
        .context("trace_unshare program not found")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_unshare")?;
    info!("Attached: tracepoint/syscalls/sys_enter_unshare");

    // sys_enter_mount
    let program: &mut TracePoint = ebpf
        .program_mut("trace_mount")
        .context("trace_mount program not found")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_mount")?;
    info!("Attached: tracepoint/syscalls/sys_enter_mount");

    // sys_enter_ptrace
    let program: &mut TracePoint = ebpf
        .program_mut("trace_ptrace")
        .context("trace_ptrace program not found")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_ptrace")?;
    info!("Attached: tracepoint/syscalls/sys_enter_ptrace");

    // XDP network monitor (optional)
    if config.enable_xdp {
        let program: &mut Xdp = ebpf
            .program_mut("xdp_monitor")
            .context("xdp_monitor program not found")?
            .try_into()?;
        program.load()?;
        program
            .attach(&config.xdp_interface, XdpFlags::default())
            .with_context(|| {
                format!(
                    "Failed to attach XDP to interface '{}'. \
                 Ensure the interface exists and the program has NET_ADMIN capability.",
                    config.xdp_interface
                )
            })?;
        info!("Attached: XDP on interface {}", config.xdp_interface);
    }

    // ------------------------------------------------------------------
    // Spawn per-CPU event readers for each PerfEventArray
    // ------------------------------------------------------------------

    let cpus = online_cpus()
        .map_err(|(msg, err)| anyhow::anyhow!("{}: {}", msg, err))?;
    info!("Online CPUs: {}", cpus.len());

    let map_names = [
        "EXECVE_EVENTS",
        "UNSHARE_EVENTS",
        "MOUNT_EVENTS",
        "PTRACE_EVENTS",
        "NETWORK_EVENTS",
    ];

    for map_name in &map_names {
        let mut perf_array = AsyncPerfEventArray::try_from(
            ebpf.take_map(map_name)
                .with_context(|| format!("Map {} not found", map_name))?,
        )?;

        let ring_buf = ring_buf.clone();
        let resolver = resolver.clone();
        let map_label = map_name.to_string();

        for cpu_id in &cpus {
            let mut buf = perf_array.open(*cpu_id, Some(256)).with_context(|| {
                format!(
                    "Failed to open perf buffer for CPU {} ({})",
                    cpu_id, map_name
                )
            })?;

            let ring_buf = ring_buf.clone();
            let resolver = resolver.clone();
            let label = map_label.clone();

            task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(EVENT_SIZE * 2))
                    .collect::<Vec<_>>();

                loop {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(events) => events,
                        Err(e) => {
                            error!("Error reading perf events from {}: {}", label, e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };

                    for i in 0..events.read {
                        let buf = &buffers[i];
                        if buf.len() < EVENT_SIZE {
                            warn!("{}: Event too small ({} bytes)", label, buf.len());
                            continue;
                        }

                        // Re-interpret as SyscallEvent (use read_unaligned for safety)
                        let event: SyscallEvent =
                            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const SyscallEvent) };

                        // Validate magic
                        if !event.is_valid() {
                            warn!("{}: Invalid event (bad magic or version)", label);
                            continue;
                        }

                        // Enrich event with container ID if not already set
                        let mut enriched = event;
                        if enriched.container_id[0] == 0 && enriched.cgroup_id > 1 {
                            if let Some(container_id) =
                                resolver.resolve(enriched.cgroup_id, enriched.pid)
                            {
                                let id_bytes = container_id.as_bytes();
                                let len = id_bytes.len().min(64);
                                enriched.container_id[..len].copy_from_slice(&id_bytes[..len]);
                            }
                        }

                        // Write to ring buffer
                        let mut rb = ring_buf.lock().await;
                        rb.write(&enriched);
                    }

                    if events.lost > 0 {
                        warn!("{}: Lost {} perf events", label, events.lost);
                    }
                }
            });
        }
    }

    info!("All eBPF programs loaded and event readers started.");
    info!("Zero-Day Guardian node agent is now monitoring.");

    // Periodic maintenance tasks
    let resolver_for_maintenance = resolver.clone();
    let ring_buf_for_stats = ring_buf.clone();

    task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            resolver_for_maintenance.evict_stale();

            let rb = ring_buf_for_stats.lock().await;
            info!(
                "Stats: events_written={}, events_dropped={}",
                rb.events_written(),
                rb.events_dropped()
            );
        }
    });

    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .context("Failed to listen for ctrl+c")?;
    info!("Received shutdown signal. Cleaning up...");

    // Flush ring buffer before exit
    let rb = ring_buf.lock().await;
    rb.flush()?;

    info!("Zero-Day Guardian node agent stopped.");
    Ok(())
}
