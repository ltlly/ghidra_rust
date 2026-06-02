//! Emulated memory: segmented memory model with permissions.
//!
//! [`EmulatedMemory`] provides a collection of [`MemorySegment`]s, each
//! representing a contiguous region of memory with access permissions.
//! Reads and writes are routed to the correct segment based on the target
//! address.

use ghidra_core::addr::Address;
use ghidra_core::program::program::MemoryPermissions;

/// A collection of memory segments forming the emulated address space.
///
/// Memory accesses are routed to the segment that contains the target
/// address. If no segment covers the address, the access fails with an
/// error.
#[derive(Debug, Clone, Default)]
pub struct EmulatedMemory {
    /// Memory segments in order of allocation.
    pub segments: Vec<MemorySegment>,
}

impl EmulatedMemory {
    /// Create an empty memory.
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Add a memory segment.
    pub fn add_segment(&mut self, segment: MemorySegment) {
        self.segments.push(segment);
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
    /// the segment does not have read permission.
    pub fn read(&self, addr: Address, size: usize) -> Result<Vec<u8>, MemoryError> {
        let (seg_idx, offset) = self
            .find_segment(addr.offset)
            .ok_or(MemoryError::Unmapped { addr })?;

        let segment = &self.segments[seg_idx];

        if !segment.permissions.readable() {
            return Err(MemoryError::PermissionDenied {
                addr,
                required: "read",
            });
        }

        let end = offset.saturating_add(size).min(segment.data.len());
        let actual_size = end.saturating_sub(offset);

        if actual_size < size {
            // Partial read: pad with zeros
            let mut result = vec![0u8; size];
            result[..actual_size].copy_from_slice(&segment.data[offset..end]);
            Ok(result)
        } else {
            Ok(segment.data[offset..offset + size].to_vec())
        }
    }

    /// Write `data` to the given address.
    ///
    /// Returns an error if the address is not covered by any segment, or if
    /// the segment does not have write permission.
    pub fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemoryError> {
        let (seg_idx, offset) = self
            .find_segment(addr.offset)
            .ok_or(MemoryError::Unmapped { addr })?;

        let segment = &mut self.segments[seg_idx];

        if !segment.permissions.writable() {
            return Err(MemoryError::PermissionDenied {
                addr,
                required: "write",
            });
        }

        let end = offset.saturating_add(data.len()).min(segment.data.len());
        let actual_len = end.saturating_sub(offset);
        segment.data[offset..end].copy_from_slice(&data[..actual_len]);

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

    /// Clear all segments.
    pub fn clear(&mut self) {
        self.segments.clear();
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
        }
    }

    /// Create a new memory segment with pre-existing data.
    pub fn with_data(start: u64, data: Vec<u8>, permissions: MemoryPermissions) -> Self {
        Self {
            start,
            data,
            permissions,
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
}

/// Extension trait to add helper methods to [`MemoryPermissions`].
trait MemoryPermissionsExt {
    fn readable(&self) -> bool;
    fn writable(&self) -> bool;
    fn executable(&self) -> bool;
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

    fn executable(&self) -> bool {
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
}
