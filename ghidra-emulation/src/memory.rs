//! Emulated memory: segmented memory model with permissions, fault
//! handling, and write tracking.
//!
//! [`EmulatedMemory`] provides a collection of [`MemorySegment`]s, each
//! representing a contiguous region of memory with access permissions.
//! Reads and writes are routed to the correct segment based on the target
//! address.
//!
//! This module also provides:
//! - [`MemoryFaultHandler`] -- trait for intercepting unmapped or invalid
//!   memory accesses (ported from Ghidra's `MemoryFaultHandler`).
//! - [`MemoryWriteTracker`] -- records all writes for later analysis
//!   (ported from Ghidra's `MemoryWriteTracker`).

use ghidra_core::addr::Address;
use ghidra_core::program::program::MemoryPermissions;


// ---------------------------------------------------------------------------
// MemoryFaultHandler
// ---------------------------------------------------------------------------

/// A callback invoked when a memory fault occurs during emulation.
///
/// Ported from Ghidra's `MemoryFaultHandler` interface. The handler can
/// choose to fix the fault (e.g., map new memory) or propagate the error.
pub trait MemoryFaultHandler: std::fmt::Debug {
    /// Called when an unmapped address is read.
    ///
    /// Return `Ok(true)` if the fault was handled and the read should be
    /// retried, `Ok(false)` to propagate the error.
    fn handle_read_fault(&self, addr: u64, size: usize) -> Result<bool, MemoryError>;

    /// Called when an unmapped address is written.
    ///
    /// Return `Ok(true)` if the fault was handled and the write should be
    /// retried, `Ok(false)` to propagate the error.
    fn handle_write_fault(&self, addr: u64, size: usize) -> Result<bool, MemoryError>;

    /// Called when a permission violation occurs.
    ///
    /// Return `Ok(true)` if the fault was handled, `Ok(false)` to
    /// propagate the error.
    fn handle_permission_fault(
        &self,
        addr: u64,
        required: &'static str,
    ) -> Result<bool, MemoryError>;
}

// ---------------------------------------------------------------------------
// MemoryWriteTracker
// ---------------------------------------------------------------------------

/// Tracks all memory writes made during emulation.
///
/// Ported from Ghidra's `MemoryWriteTracker`, this records the address,
/// old data, and new data for every write. Useful for implementing memory
/// watchpoints, diff-based analysis, and rollback.
#[derive(Debug, Clone, Default)]
pub struct MemoryWriteTracker {
    /// Log of all writes: (address, old_data, new_data).
    pub log: Vec<MemoryWriteEntry>,
    /// Whether tracking is currently enabled.
    enabled: bool,
}

/// A single tracked memory write.
#[derive(Debug, Clone)]
pub struct MemoryWriteEntry {
    /// The address written to.
    pub address: u64,
    /// The data that was previously at this location.
    pub old_data: Vec<u8>,
    /// The new data that was written.
    pub new_data: Vec<u8>,
}

impl MemoryWriteTracker {
    /// Create a new tracker (disabled by default).
    pub fn new() -> Self {
        Self {
            log: Vec::new(),
            enabled: false,
        }
    }

    /// Enable write tracking.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable write tracking.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Returns true if tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record a write (if tracking is enabled).
    pub fn record(&mut self, address: u64, old_data: Vec<u8>, new_data: Vec<u8>) {
        if self.enabled {
            self.log.push(MemoryWriteEntry {
                address,
                old_data,
                new_data,
            });
        }
    }

    /// Clear the write log.
    pub fn clear(&mut self) {
        self.log.clear();
    }

    /// Return the total number of tracked writes.
    pub fn len(&self) -> usize {
        self.log.len()
    }

    /// Returns true if no writes have been tracked.
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }
}

// ---------------------------------------------------------------------------
// EmulatedMemory
// ---------------------------------------------------------------------------

/// A collection of memory segments forming the emulated address space.
///
/// Memory accesses are routed to the segment that contains the target
/// address. If no segment covers the address, the access fails with an
/// error. An optional fault handler and write tracker can be attached.
#[derive(Debug)]
pub struct EmulatedMemory {
    /// Memory segments in order of allocation.
    pub segments: Vec<MemorySegment>,
    /// Optional fault handler for unmapped / permission faults.
    pub fault_handler: Option<Box<dyn MemoryFaultHandler>>,
    /// Write tracker for recording all writes.
    pub write_tracker: MemoryWriteTracker,
}

impl Clone for EmulatedMemory {
    fn clone(&self) -> Self {
        Self {
            segments: self.segments.clone(),
            fault_handler: None, // Cannot clone trait objects
            write_tracker: self.write_tracker.clone(),
        }
    }
}

impl Default for EmulatedMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl EmulatedMemory {
    /// Create an empty memory.
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
            fault_handler: None,
            write_tracker: MemoryWriteTracker::new(),
        }
    }

    /// Create an empty memory with a fault handler.
    pub fn with_fault_handler(handler: Box<dyn MemoryFaultHandler>) -> Self {
        Self {
            segments: Vec::new(),
            fault_handler: Some(handler),
            write_tracker: MemoryWriteTracker::new(),
        }
    }

    /// Set the fault handler.
    pub fn set_fault_handler(&mut self, handler: Box<dyn MemoryFaultHandler>) {
        self.fault_handler = Some(handler);
    }

    /// Add a memory segment.
    pub fn add_segment(&mut self, segment: MemorySegment) {
        self.segments.push(segment);
    }

    /// Remove a segment by start address.
    pub fn remove_segment(&mut self, start: u64) -> Option<MemorySegment> {
        if let Some(idx) = self.segments.iter().position(|s| s.start == start) {
            Some(self.segments.remove(idx))
        } else {
            None
        }
    }

    /// Find the segment that contains the given address, returning its index
    /// and the byte offset within the segment.
    fn find_segment(&self, addr: u64) -> Option<(usize, usize)> {
        for (idx, seg) in self.segments.iter().enumerate() {
            let end = seg.start + seg.data.len() as u64;
            if addr >= seg.start && addr < end {
                let offset = (addr - seg.start) as usize;
                return Some((idx, offset));
            }
        }
        None
    }

    /// Read `size` bytes from the given address.
    ///
    /// Returns an error if the address is not covered by any segment, or if
    /// the segment does not have read permission. If a fault handler is
    /// installed and the address is unmapped, the handler gets a chance to
    /// fix the fault before the error is propagated.
    pub fn read(&self, addr: Address, size: usize) -> Result<Vec<u8>, MemoryError> {
        let result = self.read_inner(addr.offset, size);
        match result {
            Err(MemoryError::Unmapped { addr: a }) => {
                if let Some(ref handler) = self.fault_handler {
                    if handler.handle_read_fault(a.offset, size)? {
                        // Fault was handled; retry
                        return self.read_inner(a.offset, size);
                    }
                }
                Err(MemoryError::Unmapped { addr: a })
            }
            other => other,
        }
    }

    fn read_inner(&self, offset: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let (seg_idx, seg_offset) = self
            .find_segment(offset)
            .ok_or(MemoryError::Unmapped {
                addr: Address::new(offset),
            })?;

        let segment = &self.segments[seg_idx];

        if !segment.permissions.readable() {
            return Err(MemoryError::PermissionDenied {
                addr: Address::new(offset),
                required: "read",
            });
        }

        let end = seg_offset.saturating_add(size).min(segment.data.len());
        let actual_size = end.saturating_sub(seg_offset);

        if actual_size < size {
            // Partial read: pad with zeros
            let mut result = vec![0u8; size];
            result[..actual_size].copy_from_slice(&segment.data[seg_offset..end]);
            Ok(result)
        } else {
            Ok(segment.data[seg_offset..seg_offset + size].to_vec())
        }
    }

    /// Write `data` to the given address.
    ///
    /// Returns an error if the address is not covered by any segment, or if
    /// the segment does not have write permission. If a fault handler is
    /// installed, it gets a chance to fix the fault before the error is
    /// propagated. If the write tracker is enabled, the write is recorded.
    pub fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemoryError> {
        let result = self.try_write(addr.offset, data);
        match result {
            Err(MemoryError::Unmapped { addr: a }) => {
                if let Some(ref handler) = self.fault_handler {
                    if handler.handle_write_fault(a.offset, data.len())? {
                        // Fault was handled; retry
                        return self.try_write(addr.offset, data);
                    }
                }
                Err(MemoryError::Unmapped { addr: a })
            }
            Err(MemoryError::PermissionDenied {
                addr: a,
                required: r,
            }) => {
                if let Some(ref handler) = self.fault_handler {
                    if handler.handle_permission_fault(a.offset, r)? {
                        return self.try_write(addr.offset, data);
                    }
                }
                Err(MemoryError::PermissionDenied {
                    addr: a,
                    required: r,
                })
            }
            other => other,
        }
    }

    fn try_write(&mut self, offset: u64, data: &[u8]) -> Result<(), MemoryError> {
        let (seg_idx, seg_offset) = self
            .find_segment(offset)
            .ok_or(MemoryError::Unmapped {
                addr: Address::new(offset),
            })?;

        let segment = &mut self.segments[seg_idx];

        if !segment.permissions.writable() {
            return Err(MemoryError::PermissionDenied {
                addr: Address::new(offset),
                required: "write",
            });
        }

        let end = seg_offset.saturating_add(data.len()).min(segment.data.len());
        let actual_len = end.saturating_sub(seg_offset);

        // Track the write
        if self.write_tracker.is_enabled() {
            let old_data = segment.data[seg_offset..end].to_vec();
            self.write_tracker
                .record(offset, old_data, data[..actual_len].to_vec());
        }

        segment.data[seg_offset..end].copy_from_slice(&data[..actual_len]);
        Ok(())
    }

    /// Check whether an address is mapped (covered by any segment).
    pub fn is_mapped(&self, addr: Address) -> bool {
        self.find_segment(addr.offset).is_some()
    }

    /// Return the total number of bytes across all segments.
    pub fn total_size(&self) -> usize {
        self.segments.iter().map(|s| s.data.len()).sum()
    }

    /// Find the segment that contains the given address (if any).
    pub fn get_segment(&self, addr: Address) -> Option<&MemorySegment> {
        self.find_segment(addr.offset)
            .map(|(idx, _)| &self.segments[idx])
    }

    /// Find the segment that contains the given address (mutable).
    pub fn get_segment_mut(&mut self, addr: Address) -> Option<&mut MemorySegment> {
        if self.find_segment(addr.offset).is_some() {
            let offset = addr.offset;
            self.segments.iter_mut().find(|s| s.contains(offset))
        } else {
            None
        }
    }

    /// Clear all segments and the write tracker.
    pub fn clear(&mut self) {
        self.segments.clear();
        self.write_tracker.clear();
    }
}

/// A contiguous region of emulated memory with access permissions.
#[derive(Debug, Clone)]
pub struct MemorySegment {
    /// Starting address of this segment.
    pub start: u64,
    /// Raw bytes of the segment.
    pub data: Vec<u8>,
    /// Access permissions for this segment.
    pub permissions: MemoryPermissions,
    /// Optional human-readable name (e.g., `".text"`, `".data"`, `"stack"`).
    pub name: String,
}

impl MemorySegment {
    /// Create a new memory segment.
    ///
    /// The segment data is initialized to zero.
    pub fn new(start: u64, size: usize, permissions: MemoryPermissions) -> Self {
        Self {
            start,
            data: vec![0u8; size],
            permissions,
            name: String::new(),
        }
    }

    /// Create a new memory segment with pre-existing data.
    pub fn with_data(start: u64, data: Vec<u8>, permissions: MemoryPermissions) -> Self {
        Self {
            start,
            data,
            permissions,
            name: String::new(),
        }
    }

    /// Create a named memory segment.
    pub fn with_name(
        start: u64,
        size: usize,
        permissions: MemoryPermissions,
        name: impl Into<String>,
    ) -> Self {
        Self {
            start,
            data: vec![0u8; size],
            permissions,
            name: name.into(),
        }
    }

    /// The end address (exclusive) of this segment.
    pub fn end(&self) -> u64 {
        self.start + self.data.len() as u64
    }

    /// Returns true if the given address falls within this segment.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    /// Returns the size of the segment in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Set all bytes in the segment to zero.
    pub fn zero(&mut self) {
        self.data.iter_mut().for_each(|b| *b = 0);
    }
}

/// Extension trait to add helper methods to [`MemoryPermissions`].
trait MemoryPermissionsExt {
    fn readable(&self) -> bool;
    fn writable(&self) -> bool;
    fn _executable(&self) -> bool;
}

impl MemoryPermissionsExt for MemoryPermissions {
    fn readable(&self) -> bool {
        matches!(
            self,
            MemoryPermissions::R
                | MemoryPermissions::RX
                | MemoryPermissions::RW
                | MemoryPermissions::RWX
        )
    }

    fn writable(&self) -> bool {
        matches!(self, MemoryPermissions::RW | MemoryPermissions::RWX)
    }

    fn _executable(&self) -> bool {
        matches!(self, MemoryPermissions::RX | MemoryPermissions::RWX)
    }
}

/// Errors that can occur during memory operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MemoryError {
    /// The address is not covered by any memory segment.
    #[error("unmapped memory at {addr}")]
    Unmapped { addr: Address },
    /// The segment does not have the required permission.
    #[error("permission denied at {addr}: {required} not allowed")]
    PermissionDenied {
        addr: Address,
        required: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_segment_read_write() {
        let mut mem = EmulatedMemory::new();
        mem.add_segment(MemorySegment::new(0x1000, 0x100, MemoryPermissions::RW));

        mem.write(make_addr(0x1000), &[0x41, 0x42, 0x43, 0x44])
            .unwrap();

        let data = mem.read(make_addr(0x1000), 4).unwrap();
        assert_eq!(data, vec![0x41, 0x42, 0x43, 0x44]);
    }

    #[test]
    fn test_unmapped_read_fails() {
        let mem = EmulatedMemory::new();
        let result = mem.read(make_addr(0x5000), 4);
        assert!(result.is_err());
        match result.unwrap_err() {
            MemoryError::Unmapped { addr } => assert_eq!(addr.offset, 0x5000),
            _ => panic!("expected Unmapped error"),
        }
    }

    #[test]
    fn test_read_only_segment_denies_write() {
        let mut mem = EmulatedMemory::new();
        mem.add_segment(MemorySegment::new(0x1000, 0x100, MemoryPermissions::R));

        let result = mem.write(make_addr(0x1000), &[0x41]);
        assert!(result.is_err());
        match result.unwrap_err() {
            MemoryError::PermissionDenied { .. } => {}
            _ => panic!("expected PermissionDenied error"),
        }
    }

    #[test]
    fn test_is_mapped() {
        let mut mem = EmulatedMemory::new();
        mem.add_segment(MemorySegment::new(0x1000, 0x100, MemoryPermissions::RW));

        assert!(mem.is_mapped(make_addr(0x1000)));
        assert!(mem.is_mapped(make_addr(0x10FF)));
        assert!(!mem.is_mapped(make_addr(0x1100)));
        assert!(!mem.is_mapped(make_addr(0x0)));
    }

    #[test]
    fn test_named_segment() {
        let seg = MemorySegment::with_name(0x1000, 0x100, MemoryPermissions::RX, ".text");
        assert_eq!(seg.name, ".text");
        assert_eq!(seg.size(), 0x100);
        assert_eq!(seg.end(), 0x1100);
    }

    #[test]
    fn test_remove_segment() {
        let mut mem = EmulatedMemory::new();
        mem.add_segment(MemorySegment::new(0x1000, 0x100, MemoryPermissions::RW));
        mem.add_segment(MemorySegment::new(0x2000, 0x100, MemoryPermissions::R));

        assert!(mem.is_mapped(make_addr(0x1000)));
        let removed = mem.remove_segment(0x1000);
        assert!(removed.is_some());
        assert!(!mem.is_mapped(make_addr(0x1000)));
        assert!(mem.is_mapped(make_addr(0x2000)));
    }

    #[test]
    fn test_write_tracker() {
        let mut mem = EmulatedMemory::new();
        mem.add_segment(MemorySegment::new(0x1000, 0x100, MemoryPermissions::RW));
        mem.write_tracker.enable();

        mem.write(make_addr(0x1000), &[0x41, 0x42]).unwrap();
        mem.write(make_addr(0x1002), &[0x43, 0x44]).unwrap();

        assert_eq!(mem.write_tracker.len(), 2);
        assert_eq!(mem.write_tracker.log[0].address, 0x1000);
        assert_eq!(mem.write_tracker.log[0].new_data, vec![0x41, 0x42]);
        assert_eq!(mem.write_tracker.log[1].address, 0x1002);
    }

    #[test]
    fn test_write_tracker_disabled() {
        let mut mem = EmulatedMemory::new();
        mem.add_segment(MemorySegment::new(0x1000, 0x100, MemoryPermissions::RW));

        mem.write(make_addr(0x1000), &[0x41]).unwrap();
        assert!(mem.write_tracker.is_empty());
    }

    #[test]
    fn test_get_segment() {
        let mut mem = EmulatedMemory::new();
        mem.add_segment(MemorySegment::with_name(
            0x1000,
            0x100,
            MemoryPermissions::RW,
            ".data",
        ));

        let seg = mem.get_segment(make_addr(0x1050)).unwrap();
        assert_eq!(seg.name, ".data");
    }

    #[test]
    fn test_segment_zero() {
        let mut seg = MemorySegment::with_data(0x1000, vec![0xFF; 4], MemoryPermissions::RW);
        seg.zero();
        assert_eq!(seg.data, vec![0, 0, 0, 0]);
    }
}
