//! Shared types between eBPF kernel programs and userspace loader.
//!
//! These types are `#[repr(C)]` to ensure consistent memory layout across
//! the BPF target and the host target. The `SyscallEvent` struct is the
//! primary data structure transmitted through the shared ring buffer.
//!
//! Author: Naveed Gung
//! License: Apache-2.0

#![no_std]

/// Magic sentinel value for event integrity validation.
pub const EVENT_MAGIC: u32 = 0xDEAD_BEEF;

/// Current binary format version.
pub const EVENT_VERSION: u8 = 1;

/// Total size of a single event record in bytes.
pub const EVENT_SIZE: usize = 384;

/// Default ring buffer data region size: 16 MiB.
pub const DEFAULT_RING_BUFFER_SIZE: u64 = 16 * 1024 * 1024;

/// Ring buffer header size in bytes (one cache line).
pub const RING_BUFFER_HEADER_SIZE: u64 = 64;

// ---------------------------------------------------------------------------
// Event Flags
// ---------------------------------------------------------------------------

/// Event originated from within a container cgroup.
pub const FLAG_FROM_CONTAINER: u16 = 1 << 0;
/// Process has elevated privileges.
pub const FLAG_PRIVILEGED_CTX: u16 = 1 << 1;
/// Process is in the host namespace.
pub const FLAG_HOST_NAMESPACE: u16 = 1 << 2;
/// Pre-flagged as suspicious by the eBPF program.
pub const FLAG_SUSPICIOUS: u16 = 1 << 3;

// ---------------------------------------------------------------------------
// EventType enum
// ---------------------------------------------------------------------------

/// Discriminant for the type of captured event.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventType {
    /// Process execution via `execve` syscall.
    Execve = 0x01,
    /// Namespace operation via `unshare` syscall.
    Unshare = 0x02,
    /// Filesystem mount via `mount` syscall.
    Mount = 0x03,
    /// Process tracing via `ptrace` syscall.
    Ptrace = 0x04,
    /// Network event captured by XDP program.
    Network = 0x05,
    /// Kubernetes audit log event (injected by detection engine).
    Audit = 0x06,
    /// Kernel module loading via `init_module` / `finit_module`.
    InitModule = 0x07,
}

impl EventType {
    /// Convert a raw `u8` to an `EventType`, returning `None` for unknown values.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Execve),
            0x02 => Some(Self::Unshare),
            0x03 => Some(Self::Mount),
            0x04 => Some(Self::Ptrace),
            0x05 => Some(Self::Network),
            0x06 => Some(Self::Audit),
            0x07 => Some(Self::InitModule),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// SyscallEvent — the primary event record
// ---------------------------------------------------------------------------

/// Fixed-size 384-byte event record transmitted through the shared ring buffer.
///
/// All multi-byte integers are little-endian. String fields are null-padded.
/// This struct is `#[repr(C)]` to guarantee identical layout in both the eBPF
/// (BPF target) context and the userspace (x86_64) context.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SyscallEvent {
    /// Integrity sentinel — must be `EVENT_MAGIC` (0xDEADBEEF).
    pub magic: u32,
    /// Binary format version — must be `EVENT_VERSION`.
    pub version: u8,
    /// Event type discriminant (see `EventType`).
    pub event_type: u8,
    /// Bitflags: `FLAG_FROM_CONTAINER`, `FLAG_PRIVILEGED_CTX`, etc.
    pub flags: u16,
    /// Timestamp in nanoseconds from `CLOCK_MONOTONIC`.
    pub timestamp_ns: u64,
    /// Process ID.
    pub pid: u32,
    /// Thread Group ID.
    pub tgid: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Process name (comm), null-padded to 16 bytes.
    pub comm: [u8; 16],
    /// Filename or path associated with the syscall, null-padded to 256 bytes.
    pub filename: [u8; 256],
    /// Container cgroup ID (0 if not in a container).
    pub cgroup_id: u64,
    /// Container ID string, null-padded to 64 bytes.
    pub container_id: [u8; 64],
    /// Syscall number (e.g., `__NR_execve`).
    pub syscall_nr: u32,
    /// Syscall return value (-1 if captured on entry, before return).
    pub return_value: i32,
}

// Compile-time size assertion.
const _: () = {
    if core::mem::size_of::<SyscallEvent>() != EVENT_SIZE {
        panic!("SyscallEvent size mismatch: expected 384 bytes");
    }
};

impl SyscallEvent {
    /// Create a zeroed event with magic and version pre-filled.
    pub fn new(event_type: EventType) -> Self {
        let mut event = unsafe { core::mem::zeroed::<Self>() };
        event.magic = EVENT_MAGIC;
        event.version = EVENT_VERSION;
        event.event_type = event_type as u8;
        event.return_value = -1;
        event
    }

    /// Validate the magic sentinel and version.
    pub fn is_valid(&self) -> bool {
        self.magic == EVENT_MAGIC && self.version <= EVENT_VERSION
    }

    /// Read the `comm` field as a byte slice up to the first null.
    pub fn comm_str(&self) -> &[u8] {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        &self.comm[..len]
    }

    /// Read the `filename` field as a byte slice up to the first null.
    pub fn filename_str(&self) -> &[u8] {
        let len = self.filename.iter().position(|&b| b == 0).unwrap_or(256);
        &self.filename[..len]
    }

    /// Read the `container_id` field as a byte slice up to the first null.
    pub fn container_id_str(&self) -> &[u8] {
        let len = self.container_id.iter().position(|&b| b == 0).unwrap_or(64);
        &self.container_id[..len]
    }

    /// Check if the `FROM_CONTAINER` flag is set.
    pub fn is_from_container(&self) -> bool {
        self.flags & FLAG_FROM_CONTAINER != 0
    }

    /// Check if the `SUSPICIOUS` flag is set.
    pub fn is_suspicious(&self) -> bool {
        self.flags & FLAG_SUSPICIOUS != 0
    }
}

// ---------------------------------------------------------------------------
// RingBufferHeader
// ---------------------------------------------------------------------------

/// Header at the start of the shared ring buffer file.
///
/// Both the write_pos and read_pos are byte offsets into the data region
/// that wrap around using `pos & (capacity - 1)`. They are monotonically
/// increasing; the actual index is derived by masking.
#[repr(C)]
pub struct RingBufferHeader {
    /// Current write position (byte offset, monotonically increasing).
    /// Written by producer (Rust), read by consumer (Java).
    pub write_pos: u64,
    /// Current read position (byte offset, monotonically increasing).
    /// Written by consumer (Java), read by producer (Rust).
    pub read_pos: u64,
    /// Capacity of the data region in bytes. Must be a power of 2.
    pub capacity: u64,
    /// Reserved flags for future use.
    pub flags: u64,
    /// Padding to fill the header to exactly 64 bytes.
    pub _padding: [u8; 32],
}

const _: () = {
    if core::mem::size_of::<RingBufferHeader>() != 64 {
        panic!("RingBufferHeader size mismatch: expected 64 bytes");
    }
};

// ---------------------------------------------------------------------------
// Aya Pod trait implementation (userspace only)
// ---------------------------------------------------------------------------

#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallEvent {}
