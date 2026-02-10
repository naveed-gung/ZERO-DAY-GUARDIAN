//! Shared ring buffer writer for inter-process event communication.
//!
//! The ring buffer is a memory-mapped file on tmpfs (Kubernetes emptyDir
//! with medium: Memory). The Rust eBPF userspace loader writes events;
//! the Java detection engine reads them.
//!
//! Design: Single Producer Single Consumer (SPSC) lock-free ring buffer.
//!   - Writer (this module): atomically increments write_pos
//!   - Reader (Java): atomically increments read_pos
//!   - No locks, no mutexes. Synchronization via atomic Release/Acquire.
//!
//! Author: Naveed Gung

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use memmap2::MmapMut;

use ebpf_monitor_common::{RingBufferHeader, SyscallEvent, EVENT_SIZE, RING_BUFFER_HEADER_SIZE};

/// SPSC ring buffer writer backed by a memory-mapped file.
pub struct RingBufWriter {
    /// Memory-mapped region covering the entire ring buffer file.
    mmap: MmapMut,
    /// Capacity of the data region in bytes (power of 2).
    capacity: u64,
    /// Mask for fast modulo: `capacity - 1`.
    mask: u64,
    /// Counter for dropped events due to backpressure.
    drops: u64,
    /// Total events written.
    written: u64,
}

impl RingBufWriter {
    /// Create or open the ring buffer file and initialize the header.
    ///
    /// # Arguments
    /// - `path`: Path to the ring buffer file (should be on tmpfs)
    /// - `data_capacity`: Size of the data region in bytes (must be power of 2)
    pub fn new(path: &Path, data_capacity: u64) -> Result<Self> {
        // Validate power of 2
        if data_capacity == 0 || (data_capacity & (data_capacity - 1)) != 0 {
            anyhow::bail!("data_capacity must be a power of 2, got {}", data_capacity);
        }

        let total_size = RING_BUFFER_HEADER_SIZE + data_capacity;

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }

        // Create or open the file
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("Failed to open ring buffer file {:?}", path))?;

        // Set the file size
        file.set_len(total_size)
            .with_context(|| format!("Failed to set ring buffer file size to {}", total_size))?;

        // Memory-map the file
        let mut mmap = unsafe {
            MmapMut::map_mut(&file).with_context(|| "Failed to memory-map ring buffer file")?
        };

        // Initialize the header
        let header_ptr = mmap.as_mut_ptr() as *mut RingBufferHeader;
        unsafe {
            let header = &mut *header_ptr;
            // Only initialize if the capacity field is zero (fresh file)
            if header.capacity == 0 {
                header.write_pos = 0;
                header.read_pos = 0;
                header.capacity = data_capacity;
                header.flags = 0;
                header._padding = [0u8; 32];
                info!(
                    "Initialized ring buffer: capacity={} bytes ({} events)",
                    data_capacity,
                    data_capacity / EVENT_SIZE as u64
                );
            } else {
                info!(
                    "Reusing existing ring buffer: capacity={} bytes, write_pos={}, read_pos={}",
                    header.capacity, header.write_pos, header.read_pos
                );
            }
        }

        // Flush the initialized header to the backing file
        mmap.flush()
            .with_context(|| "Failed to flush ring buffer header")?;

        Ok(Self {
            mmap,
            capacity: data_capacity,
            mask: data_capacity - 1,
            drops: 0,
            written: 0,
        })
    }

    /// Write an event to the ring buffer.
    ///
    /// Returns `true` if the event was written, `false` if dropped due to
    /// the buffer being full (backpressure).
    pub fn write(&mut self, event: &SyscallEvent) -> bool {
        let header_ptr = self.mmap.as_ptr() as *const RingBufferHeader;

        // Read positions atomically
        let write_pos = unsafe {
            let wp = &(*header_ptr).write_pos as *const u64 as *const AtomicU64;
            (*wp).load(Ordering::Relaxed)
        };
        let read_pos = unsafe {
            let rp = &(*header_ptr).read_pos as *const u64 as *const AtomicU64;
            (*rp).load(Ordering::Acquire)
        };

        // Check if buffer is full
        let used = write_pos.wrapping_sub(read_pos);
        if used + EVENT_SIZE as u64 > self.capacity {
            self.drops += 1;
            if self.drops % 1000 == 1 {
                warn!(
                    "Ring buffer full: dropped {} events (write_pos={}, read_pos={}, used={})",
                    self.drops, write_pos, read_pos, used
                );
            }
            return false;
        }

        // Calculate the write offset within the data region
        let data_offset = RING_BUFFER_HEADER_SIZE + (write_pos & self.mask);
        let data_offset = data_offset as usize;

        // Write the event bytes
        let event_bytes = unsafe {
            std::slice::from_raw_parts(event as *const SyscallEvent as *const u8, EVENT_SIZE)
        };

        // Handle wraparound: if the event spans the end of the data region,
        // we need to split the write
        let end_offset = (write_pos & self.mask) as usize + EVENT_SIZE;
        if end_offset <= self.capacity as usize {
            // Normal case: event fits contiguously
            self.mmap[data_offset..data_offset + EVENT_SIZE].copy_from_slice(event_bytes);
        } else {
            // Wraparound: split into two copies
            let first_part = self.capacity as usize - (write_pos & self.mask) as usize;
            let header_off = RING_BUFFER_HEADER_SIZE as usize;
            self.mmap[data_offset..data_offset + first_part]
                .copy_from_slice(&event_bytes[..first_part]);
            self.mmap[header_off..header_off + (EVENT_SIZE - first_part)]
                .copy_from_slice(&event_bytes[first_part..]);
        }

        // Update write_pos atomically with Release ordering
        let new_write_pos = write_pos + EVENT_SIZE as u64;
        unsafe {
            let header_mut = self.mmap.as_ptr() as *const RingBufferHeader;
            let wp = &(*header_mut).write_pos as *const u64 as *const AtomicU64;
            (*wp).store(new_write_pos, Ordering::Release);
        }

        self.written += 1;
        if self.written % 10_000 == 0 {
            debug!(
                "Ring buffer stats: written={}, drops={}, utilization={:.1}%",
                self.written,
                self.drops,
                (used as f64 / self.capacity as f64) * 100.0
            );
        }

        true
    }

    /// Get the total number of events written.
    pub fn events_written(&self) -> u64 {
        self.written
    }

    /// Get the total number of events dropped.
    pub fn events_dropped(&self) -> u64 {
        self.drops
    }

    /// Flush the memory-mapped region to ensure data visibility.
    pub fn flush(&self) -> Result<()> {
        self.mmap
            .flush()
            .with_context(|| "Failed to flush ring buffer")
    }
}

impl Drop for RingBufWriter {
    fn drop(&mut self) {
        info!(
            "Ring buffer writer shutting down: written={}, drops={}",
            self.written, self.drops
        );
        if let Err(e) = self.flush() {
            error!("Failed to flush ring buffer on shutdown: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_monitor_common::{EventType, EVENT_MAGIC, EVENT_VERSION};
    use std::path::PathBuf;

    fn temp_path() -> PathBuf {
        let dir = std::env::temp_dir().join("zdg-test");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("ringbuf-{}.bin", std::process::id()))
    }

    #[test]
    fn test_create_ring_buffer() {
        let path = temp_path();
        let writer = RingBufWriter::new(&path, 4096);
        assert!(writer.is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_write_event() {
        let path = temp_path();
        let mut writer = RingBufWriter::new(&path, 4096).unwrap();

        let mut event = SyscallEvent::new(EventType::Execve);
        event.pid = 1234;
        event.comm[..4].copy_from_slice(b"test");

        assert!(writer.write(&event));
        assert_eq!(writer.events_written(), 1);
        assert_eq!(writer.events_dropped(), 0);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_backpressure() {
        let path = temp_path();
        // Tiny buffer: can hold EVENT_SIZE * 10 events at most
        let capacity = (EVENT_SIZE * 10).next_power_of_two() as u64;
        let mut writer = RingBufWriter::new(&path, capacity).unwrap();

        let event = SyscallEvent::new(EventType::Execve);

        // Fill the buffer
        let max_events = capacity as usize / EVENT_SIZE;
        for _ in 0..max_events {
            writer.write(&event);
        }

        // Next write should be dropped (reader hasn't advanced read_pos)
        let result = writer.write(&event);
        assert!(!result);
        assert!(writer.events_dropped() > 0);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_invalid_capacity() {
        let path = temp_path();
        let result = RingBufWriter::new(&path, 1000); // Not power of 2
        assert!(result.is_err());
        std::fs::remove_file(&path).ok();
    }
}
