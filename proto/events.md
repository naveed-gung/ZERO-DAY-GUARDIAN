# Shared Event Binary Format Specification

**Version**: 1.0
**Author**: Naveed Gung

---

## Overview

This document defines the binary event format used for inter-process communication between
the Rust eBPF userspace loader and the Java detection engine. Events are transmitted via a
shared memory-mapped SPSC (Single Producer, Single Consumer) ring buffer backed by a
Kubernetes `emptyDir` volume with `medium: Memory` (tmpfs).

---

## Ring Buffer File Layout

The ring buffer file is memory-mapped by both the Rust writer and Java reader.

```
Offset    Size     Field            Description
──────────────────────────────────────────────────────────────────
0x0000    8 bytes  write_pos        Atomic u64 - writer's current position (Release/Acquire)
0x0008    8 bytes  read_pos         Atomic u64 - reader's current position (Release/Acquire)
0x0010    8 bytes  capacity         u64 - data region size in bytes (power of 2)
0x0018    8 bytes  flags            u64 - reserved for future use
0x0020    32 bytes _padding         Align header to 64-byte cache line boundary
──────────────────────────────────────────────────────────────────
0x0040    N bytes  data[]           Ring of SyscallEvent records
```

**Header**: 64 bytes (one cache line), aligned to prevent false sharing.

**Data region**: Default 16 MiB (16,777,216 bytes), must be a power of 2.
Position masking: `actual_offset = pos & (capacity - 1)`.

**Capacity**: 16 MiB / 384 bytes per event = 43,690 events.

---

## SyscallEvent Record Layout

Each event is a fixed-size 384-byte record. All multi-byte integers are little-endian.
All string fields are null-padded (not null-terminated; use first null or field width).

```
Offset    Size      Type          Field           Description
──────────────────────────────────────────────────────────────────────────
0x0000    4 bytes   u32           magic           Integrity sentinel: 0xDEADBEEF
0x0004    1 byte    u8            version         Format version (currently 1)
0x0005    1 byte    u8            event_type      See EventType enum below
0x0006    2 bytes   u16           flags           Bitflags (see Flags section)
0x0008    8 bytes   u64           timestamp_ns    CLOCK_MONOTONIC nanoseconds
0x0010    4 bytes   u32           pid             Process ID
0x0014    4 bytes   u32           tgid            Thread Group ID
0x0018    4 bytes   u32           uid             User ID
0x001C    4 bytes   u32           gid             Group ID
0x0020    16 bytes  [u8; 16]      comm            Process name (null-padded)
0x0030    256 bytes [u8; 256]     filename        Filename/path (null-padded)
0x0130    8 bytes   u64           cgroup_id       Container cgroup ID
0x0138    64 bytes  [u8; 64]      container_id    Container ID (null-padded)
0x0178    4 bytes   u32           syscall_nr      Syscall number
0x017C    4 bytes   i32           return_value    Syscall return value (-1 if not yet returned)
──────────────────────────────────────────────────────────────────────────
Total: 384 bytes (0x0180) -- aligned to cache-line multiple
```

---

## EventType Enum

```
Value   Name        Description
────────────────────────────────────────────
0x01    EXECVE      Process execution (execve syscall)
0x02    UNSHARE     Namespace operation (unshare syscall)
0x03    MOUNT       Filesystem mount (mount syscall)
0x04    PTRACE      Process trace/debug (ptrace syscall)
0x05    NETWORK     Network event from XDP program
0x06    AUDIT       Kubernetes audit log event
```

---

## Flags Bitfield

```
Bit     Name                Description
────────────────────────────────────────────
0       FROM_CONTAINER      Event originated from within a container
1       PRIVILEGED_CTX      Process has elevated privileges
2       HOST_NAMESPACE      Process is in the host namespace
3       SUSPICIOUS          Pre-flagged as suspicious by eBPF program
4-15    RESERVED            Reserved for future use
```

---

## Synchronization Protocol

### Writer (Rust)

1. Read `read_pos` with `Acquire` ordering
2. Check available space: `write_pos - read_pos < capacity`
3. If full: increment drop counter, skip event (backpressure)
4. Write event bytes to `data[write_pos & (capacity - 1)]`
5. Memory fence (Release)
6. Increment `write_pos` with `Release` ordering

### Reader (Java)

1. Read `write_pos` with `Acquire` ordering (via `VarHandle.getAcquire`)
2. If `write_pos == read_pos`: no new events, spin with `Thread.onSpinWait()`
3. Read event bytes from `data[read_pos & (capacity - 1)]`
4. Validate `magic == 0xDEADBEEF`
5. Deserialize event fields
6. Increment `read_pos` with `Release` ordering (via `VarHandle.setRelease`)

### Backpressure

- Writer never blocks; it drops events when the buffer is full
- A `guardian_ring_buffer_drops_total` metric tracks dropped events
- Reader should process events faster than the writer produces them

---

## Cross-Language Implementation Notes

### Rust Side

```rust
#[repr(C)]
pub struct SyscallEvent {
    pub magic: u32,           // 0xDEADBEEF
    pub version: u8,          // 1
    pub event_type: u8,       // EventType enum
    pub flags: u16,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub cgroup_id: u64,
    pub container_id: [u8; 64],
    pub syscall_nr: u32,
    pub return_value: i32,
}
// static_assert: size_of::<SyscallEvent>() == 384
```

### Java Side

```java
// Read from MappedByteBuffer at offset
int magic = buffer.getInt(offset);           // 4 bytes
byte version = buffer.get(offset + 4);       // 1 byte
byte eventType = buffer.get(offset + 5);     // 1 byte
short flags = buffer.getShort(offset + 6);   // 2 bytes
long timestampNs = buffer.getLong(offset + 8); // 8 bytes
// ... etc
```

Both sides must use the same byte order (`ByteOrder.LITTLE_ENDIAN` in Java).

---

## Versioning

The `version` field allows forward-compatible schema evolution. Readers must:

- Accept any event with `version <= CURRENT_VERSION`
- Reject events with `version > CURRENT_VERSION` (log warning, skip)
- The `magic` field (`0xDEADBEEF`) detects corrupt or misaligned reads
