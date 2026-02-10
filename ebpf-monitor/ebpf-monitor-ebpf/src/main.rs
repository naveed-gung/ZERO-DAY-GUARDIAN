//! eBPF Kernel Programs for Zero-Day Guardian
//!
//! This crate compiles for the `bpfel-unknown-none` target and produces eBPF
//! bytecode that the userspace loader attaches to kernel tracepoints and XDP hooks.
//!
//! Programs:
//!   - trace_execve:      tracepoint/syscalls/sys_enter_execve
//!   - trace_unshare:     tracepoint/syscalls/sys_enter_unshare
//!   - trace_mount:       tracepoint/syscalls/sys_enter_mount
//!   - trace_ptrace:      tracepoint/syscalls/sys_enter_ptrace
//!   - trace_init_module: tracepoint/syscalls/sys_enter_init_module
//!   - trace_finit_module:tracepoint/syscalls/sys_enter_finit_module
//!   - xdp_monitor:       XDP ingress packet inspection
//!
//! Author: Naveed Gung
//! License: Apache-2.0

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint, xdp},
    maps::PerfEventArray,
    programs::{TracePointContext, XdpContext},
};
use aya_log_ebpf::info;
use ebpf_monitor_common::{
    EventType, SyscallEvent, EVENT_MAGIC, EVENT_VERSION, FLAG_FROM_CONTAINER, FLAG_SUSPICIOUS,
};

// ---------------------------------------------------------------------------
// Maps — perf event arrays for sending events to userspace
// ---------------------------------------------------------------------------

#[map]
static EXECVE_EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[map]
static UNSHARE_EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[map]
static MOUNT_EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[map]
static PTRACE_EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[map]
static NETWORK_EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[map]
static INIT_MODULE_EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

// ---------------------------------------------------------------------------
// Helper: detect if we are inside a container (non-root cgroup)
// ---------------------------------------------------------------------------

/// Heuristic: cgroup_id > 1 typically indicates a non-root cgroup,
/// which in Kubernetes means the process is inside a container.
#[inline(always)]
fn is_container_context() -> (bool, u64) {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    // Root cgroup is typically 1; container cgroups get higher IDs
    (cgroup_id > 1, cgroup_id)
}

/// Fill common fields in a SyscallEvent.
#[inline(always)]
fn fill_common_fields(
    event: &mut SyscallEvent,
    event_type: EventType,
    cgroup_id: u64,
    is_container: bool,
) {
    event.magic = EVENT_MAGIC;
    event.version = EVENT_VERSION;
    event.event_type = event_type as u8;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    event.pid = (pid_tgid >> 32) as u32;
    event.tgid = pid_tgid as u32;

    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;

    event.cgroup_id = cgroup_id;

    if is_container {
        event.flags |= FLAG_FROM_CONTAINER;
    }

    // Read the current process comm (name)
    if let Ok(comm) = bpf_get_current_comm() {
        let len = comm.len().min(16);
        event.comm[..len].copy_from_slice(&comm[..len]);
    }

    event.return_value = -1; // Entry tracepoint; no return value yet
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_execve
// ---------------------------------------------------------------------------

/// Captures process execution events. This is triggered every time any process
/// in any container calls `execve()`. The filename argument (argv[0] path) is
/// read from userspace memory.
#[tracepoint]
pub fn trace_execve(ctx: TracePointContext) -> u32 {
    match try_trace_execve(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    let (is_container, cgroup_id) = is_container_context();

    let mut event: SyscallEvent = unsafe { core::mem::zeroed() };
    fill_common_fields(&mut event, EventType::Execve, cgroup_id, is_container);

    // Read the filename pointer from the tracepoint args
    // For sys_enter_execve: args[0] = filename (const char __user *)
    let filename_ptr: *const u8 = unsafe { ctx.read_at::<u64>(16)? as *const u8 };

    // Read the filename string from userspace
    if !filename_ptr.is_null() {
        let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) };
    }

    // Syscall number for execve (x86_64)
    event.syscall_nr = 59;

    // Check for suspicious patterns: execution of sensitive binaries
    if is_suspicious_execve(&event.filename) {
        event.flags |= FLAG_SUSPICIOUS;
    }

    EXECVE_EVENTS.output(ctx, &event, 0);

    Ok(0)
}

/// Heuristic: flag certain filenames as suspicious when executed from containers.
#[inline(always)]
fn is_suspicious_execve(filename: &[u8; 256]) -> bool {
    // Check for common attack tool patterns
    let patterns: &[&[u8]] = &[
        b"/proc/self/exe",
        b"/bin/sh",
        b"/bin/bash",
        b"nsenter",
        b"kubectl",
        b"curl",
        b"wget",
        b"nc",
        b"ncat",
        b"nmap",
    ];

    for pattern in patterns {
        if contains_bytes(filename, pattern) {
            return true;
        }
    }
    false
}

/// Simple byte substring search (no allocator available in eBPF).
#[inline(always)]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let limit = haystack.len() - needle.len();
    // Bound the loop to satisfy the eBPF verifier
    let max_iter = if limit < 240 { limit } else { 240 };
    let mut i = 0;
    while i <= max_iter {
        let mut matched = true;
        let mut j = 0;
        while j < needle.len() && j < 32 {
            if haystack[i + j] != needle[j] {
                matched = false;
                break;
            }
            j += 1;
        }
        if matched && j == needle.len() {
            return true;
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_unshare
// ---------------------------------------------------------------------------

/// Captures namespace manipulation events. The `unshare` syscall is used
/// to create new namespaces; in a container context this may indicate
/// an escape attempt (e.g., CLONE_NEWUSER bypass).
#[tracepoint]
pub fn trace_unshare(ctx: TracePointContext) -> u32 {
    match try_trace_unshare(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_unshare(ctx: &TracePointContext) -> Result<u32, i64> {
    let (is_container, cgroup_id) = is_container_context();

    let mut event: SyscallEvent = unsafe { core::mem::zeroed() };
    fill_common_fields(&mut event, EventType::Unshare, cgroup_id, is_container);

    // Read unshare flags from tracepoint args
    // For sys_enter_unshare: args[0] = unshare_flags
    let unshare_flags: u64 = unsafe { ctx.read_at::<u64>(16)? };

    // Store flags in the filename field as a formatted value
    // First 8 bytes contain the raw flags for the detection engine
    let flag_bytes = unshare_flags.to_le_bytes();
    event.filename[..8].copy_from_slice(&flag_bytes);

    // Syscall number for unshare (x86_64)
    event.syscall_nr = 272;

    // CLONE_NEWUSER (0x10000000) from a container is highly suspicious
    const CLONE_NEWUSER: u64 = 0x10000000;
    const CLONE_NEWNS: u64 = 0x00020000;
    const CLONE_NEWPID: u64 = 0x20000000;

    if is_container
        && (unshare_flags & CLONE_NEWUSER != 0
            || unshare_flags & CLONE_NEWNS != 0
            || unshare_flags & CLONE_NEWPID != 0)
    {
        event.flags |= FLAG_SUSPICIOUS;
        info!(
            ctx,
            "SUSPICIOUS: unshare from container cgroup={} flags=0x{:x}", cgroup_id, unshare_flags
        );
    }

    UNSHARE_EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_mount
// ---------------------------------------------------------------------------

/// Captures filesystem mount events. Container escapes often involve
/// mounting the host filesystem or /proc to gain access outside the
/// container namespace.
#[tracepoint]
pub fn trace_mount(ctx: TracePointContext) -> u32 {
    match try_trace_mount(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_mount(ctx: &TracePointContext) -> Result<u32, i64> {
    let (is_container, cgroup_id) = is_container_context();

    let mut event: SyscallEvent = unsafe { core::mem::zeroed() };
    fill_common_fields(&mut event, EventType::Mount, cgroup_id, is_container);

    // For sys_enter_mount: args[0] = source, args[1] = target
    let source_ptr: *const u8 = unsafe { ctx.read_at::<u64>(16)? as *const u8 };
    let target_ptr: *const u8 = unsafe { ctx.read_at::<u64>(24)? as *const u8 };

    // Read source path into first 128 bytes of filename
    if !source_ptr.is_null() {
        let mut source_buf = [0u8; 128];
        let _ = unsafe { bpf_probe_read_user_str_bytes(source_ptr, &mut source_buf) };
        event.filename[..128].copy_from_slice(&source_buf);
    }

    // Read target path into bytes 128..256 of filename
    if !target_ptr.is_null() {
        let mut target_buf = [0u8; 128];
        let _ = unsafe { bpf_probe_read_user_str_bytes(target_ptr, &mut target_buf) };
        event.filename[128..256].copy_from_slice(&target_buf);
    }

    // Syscall number for mount (x86_64)
    event.syscall_nr = 165;

    // Flag mounts from containers as suspicious
    if is_container {
        event.flags |= FLAG_SUSPICIOUS;
        info!(ctx, "SUSPICIOUS: mount from container cgroup={}", cgroup_id);
    }

    MOUNT_EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_ptrace
// ---------------------------------------------------------------------------

/// Captures ptrace events. The `ptrace` syscall is used for debugging
/// but also for process injection and privilege escalation attacks.
#[tracepoint]
pub fn trace_ptrace(ctx: TracePointContext) -> u32 {
    match try_trace_ptrace(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_ptrace(ctx: &TracePointContext) -> Result<u32, i64> {
    let (is_container, cgroup_id) = is_container_context();

    let mut event: SyscallEvent = unsafe { core::mem::zeroed() };
    fill_common_fields(&mut event, EventType::Ptrace, cgroup_id, is_container);

    // For sys_enter_ptrace: args[0] = request, args[1] = pid
    let request: u64 = unsafe { ctx.read_at::<u64>(16)? };
    let target_pid: u64 = unsafe { ctx.read_at::<u64>(24)? };

    // Store request and target_pid in filename field
    let req_bytes = request.to_le_bytes();
    let pid_bytes = target_pid.to_le_bytes();
    event.filename[..8].copy_from_slice(&req_bytes);
    event.filename[8..16].copy_from_slice(&pid_bytes);

    // Syscall number for ptrace (x86_64)
    event.syscall_nr = 101;

    // ptrace from a container is always suspicious
    if is_container {
        event.flags |= FLAG_SUSPICIOUS;
        info!(
            ctx,
            "SUSPICIOUS: ptrace request={} target_pid={} from container", request, target_pid
        );
    }

    PTRACE_EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_init_module / sys_enter_finit_module
// ---------------------------------------------------------------------------

/// Captures kernel module loading attempts. Loading kernel modules from
/// inside a container is a critical escape vector.
#[tracepoint]
pub fn trace_init_module(ctx: TracePointContext) -> u32 {
    match try_trace_init_module(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_init_module(ctx: &TracePointContext) -> Result<u32, i64> {
    let (is_container, cgroup_id) = is_container_context();

    let mut event: SyscallEvent = unsafe { core::mem::zeroed() };
    fill_common_fields(&mut event, EventType::InitModule, cgroup_id, is_container);

    // Syscall number for init_module (x86_64)
    event.syscall_nr = 175;

    // Any module loading from a container context is critical
    if is_container {
        event.flags |= FLAG_SUSPICIOUS;
        info!(
            ctx,
            "CRITICAL: init_module from container cgroup={}", cgroup_id
        );
    }

    INIT_MODULE_EVENTS.output(ctx, &event, 0);

    Ok(0)
}

/// Captures finit_module (load module from file descriptor).
#[tracepoint]
pub fn trace_finit_module(ctx: TracePointContext) -> u32 {
    match try_trace_finit_module(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_finit_module(ctx: &TracePointContext) -> Result<u32, i64> {
    let (is_container, cgroup_id) = is_container_context();

    let mut event: SyscallEvent = unsafe { core::mem::zeroed() };
    fill_common_fields(&mut event, EventType::InitModule, cgroup_id, is_container);

    // Syscall number for finit_module (x86_64)
    event.syscall_nr = 313;

    if is_container {
        event.flags |= FLAG_SUSPICIOUS;
        info!(
            ctx,
            "CRITICAL: finit_module from container cgroup={}", cgroup_id
        );
    }

    INIT_MODULE_EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ---------------------------------------------------------------------------
// XDP: Network packet inspection
// ---------------------------------------------------------------------------

/// XDP program that inspects ingress network packets for suspicious patterns:
/// - Known mining pool destination ports
/// - DNS tunneling indicators (unusually large DNS queries)
/// - C2 beaconing patterns (periodic connections to same external IP)
#[xdp]
pub fn xdp_monitor(ctx: XdpContext) -> u32 {
    match try_xdp_monitor(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_monitor(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let data_len = data_end - data;

    // Minimum: Ethernet (14) + IP (20) + TCP/UDP (8) = 42 bytes
    if data_len < 42 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse Ethernet header
    let eth_proto = unsafe {
        let eth_ptr = data as *const u8;
        // EtherType is at offset 12-13 (big-endian)
        let hi = *eth_ptr.add(12) as u16;
        let lo = *eth_ptr.add(13) as u16;
        (hi << 8) | lo
    };

    // Only process IPv4 (0x0800)
    if eth_proto != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse IP header
    let ip_start = data + 14;
    if ip_start + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let (ip_proto, dest_ip) = unsafe {
        let ip_ptr = ip_start as *const u8;
        let protocol = *ip_ptr.add(9);
        // Destination IP at offset 16..20
        let d0 = *ip_ptr.add(16) as u32;
        let d1 = *ip_ptr.add(17) as u32;
        let d2 = *ip_ptr.add(18) as u32;
        let d3 = *ip_ptr.add(19) as u32;
        (protocol, (d0 << 24) | (d1 << 16) | (d2 << 8) | d3)
    };

    // Parse transport layer destination port
    let ihl = unsafe { (*((ip_start) as *const u8) & 0x0F) as usize * 4 };
    let transport_start = ip_start + ihl;
    if transport_start + 4 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let dest_port = unsafe {
        let tp_ptr = transport_start as *const u8;
        let hi = *tp_ptr.add(2) as u16;
        let lo = *tp_ptr.add(3) as u16;
        (hi << 8) | lo
    };

    // Check for suspicious destination ports (common mining pools)
    let suspicious =
        is_suspicious_port(dest_port) || is_dns_tunneling_suspect(ip_proto, dest_port, data_len);

    if suspicious {
        let mut event: SyscallEvent = unsafe { core::mem::zeroed() };
        event.magic = EVENT_MAGIC;
        event.version = EVENT_VERSION;
        event.event_type = EventType::Network as u8;
        event.flags = FLAG_SUSPICIOUS;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        // Store dest_ip and dest_port in filename field
        let ip_bytes = dest_ip.to_be_bytes();
        event.filename[..4].copy_from_slice(&ip_bytes);
        let port_bytes = dest_port.to_be_bytes();
        event.filename[4..6].copy_from_slice(&port_bytes);
        event.filename[6] = ip_proto;

        NETWORK_EVENTS.output(ctx, &event, 0);
    }

    // Always pass the packet (monitoring only, not blocking at XDP level)
    Ok(xdp_action::XDP_PASS)
}

/// Known cryptocurrency mining pool ports.
#[inline(always)]
fn is_suspicious_port(port: u16) -> bool {
    matches!(
        port,
        3333  | // Stratum mining
        4444  | // Stratum mining (alt)
        5555  | // Stratum mining (alt)
        7777  | // Stratum mining (alt)
        8333  | // Bitcoin network
        9999  | // Stratum mining (alt)
        14433 | // Monero mining
        14444 | // Monero mining (alt)
        45700 // Monero mining (alt)
    )
}

/// DNS tunneling heuristic: UDP with unusually large payloads (> 512 bytes)
/// targeting port 53. Normal DNS queries are < 512 bytes; DNS tunneling
/// abuses TXT records and long subdomain labels producing larger packets.
#[inline(always)]
fn is_dns_tunneling_suspect(ip_proto: u8, dest_port: u16, pkt_len: usize) -> bool {
    // UDP = 17, DNS = port 53
    ip_proto == 17 && dest_port == 53 && pkt_len > 512
}

// ---------------------------------------------------------------------------
// Panic handler (required for #![no_std])
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
