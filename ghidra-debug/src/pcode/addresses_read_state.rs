//! AddressesReadTracePcodeExecutorStatePiece ported from Java.
//!
//! Tracks which addresses were read during pcode execution over trace state.
//! This is used for dependency analysis and for determining which memory
//! regions an emulated program accessed.

use std::collections::{BTreeMap, BTreeSet};

/// Tracks memory reads during pcode execution against trace state.
///
/// Ported from `AddressesReadTracePcodeExecutorStatePiece`. When pcode
/// execution reads from an address space, the read offset and size are
/// recorded here. This is used by the emulation integration to determine
/// which trace memory regions were accessed during a given step.
#[derive(Debug, Clone, Default)]
pub struct AddressesReadStatePiece {
    /// Maps (space_name, offset) -> set of byte lengths read
    reads: BTreeMap<String, BTreeMap<u64, BTreeSet<usize>>>,
    /// Total number of read operations recorded
    read_count: u64,
}

impl AddressesReadStatePiece {
    /// Create a new empty addresses-read tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a read of `size` bytes at the given address space and offset.
    pub fn record_read(&mut self, space: &str, offset: u64, size: usize) {
        let space_entry = self.reads.entry(space.to_string()).or_default();
        space_entry.entry(offset).or_default().insert(size);
        self.read_count += 1;
    }

    /// Check if any bytes were read at the given offset in the space.
    pub fn was_read(&self, space: &str, offset: u64) -> bool {
        self.reads
            .get(space)
            .map(|m| m.contains_key(&offset))
            .unwrap_or(false)
    }

    /// Get all offsets read in the given address space.
    pub fn read_offsets(&self, space: &str) -> Vec<u64> {
        self.reads
            .get(space)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Get all address spaces that had reads.
    pub fn spaces(&self) -> Vec<&str> {
        self.reads.keys().map(|s| s.as_str()).collect()
    }

    /// Get the total number of read operations.
    pub fn read_count(&self) -> u64 {
        self.read_count
    }

    /// Check if this piece has any recorded reads.
    pub fn is_empty(&self) -> bool {
        self.reads.is_empty()
    }

    /// Clear all recorded reads.
    pub fn clear(&mut self) {
        self.reads.clear();
        self.read_count = 0;
    }

    /// Merge reads from another piece into this one.
    pub fn merge_from(&mut self, other: &AddressesReadStatePiece) {
        for (space, offsets) in &other.reads {
            let space_entry = self.reads.entry(space.clone()).or_default();
            for (offset, sizes) in offsets {
                let offset_entry = space_entry.entry(*offset).or_default();
                for size in sizes {
                    offset_entry.insert(*size);
                }
            }
        }
        self.read_count += other.read_count;
    }

    /// Compute the address set of all read ranges as TraceAddressSnapRanges.
    pub fn to_address_ranges(&self) -> Vec<(String, Vec<(u64, usize)>)> {
        self.reads
            .iter()
            .map(|(space, offsets)| {
                let ranges: Vec<(u64, usize)> = offsets
                    .iter()
                    .flat_map(|(offset, sizes)| {
                        sizes.iter().map(|size| (*offset, *size))
                    })
                    .collect();
                (space.clone(), ranges)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_query() {
        let mut piece = AddressesReadStatePiece::new();
        piece.record_read("ram", 0x1000, 4);
        piece.record_read("ram", 0x1004, 4);
        piece.record_read("register", 0x0, 8);

        assert!(piece.was_read("ram", 0x1000));
        assert!(piece.was_read("ram", 0x1004));
        assert!(piece.was_read("register", 0x0));
        assert!(!piece.was_read("ram", 0x2000));
        assert_eq!(piece.read_count(), 3);
    }

    #[test]
    fn test_read_offsets() {
        let mut piece = AddressesReadStatePiece::new();
        piece.record_read("ram", 0x1000, 4);
        piece.record_read("ram", 0x1004, 4);
        piece.record_read("ram", 0x1000, 8); // same offset, different size

        let offsets = piece.read_offsets("ram");
        assert_eq!(offsets.len(), 2);
        assert!(offsets.contains(&0x1000));
        assert!(offsets.contains(&0x1004));
    }

    #[test]
    fn test_merge() {
        let mut piece1 = AddressesReadStatePiece::new();
        piece1.record_read("ram", 0x1000, 4);

        let mut piece2 = AddressesReadStatePiece::new();
        piece2.record_read("ram", 0x2000, 4);
        piece2.record_read("register", 0x0, 8);

        piece1.merge_from(&piece2);
        assert_eq!(piece1.read_count(), 3);
        assert!(piece1.was_read("ram", 0x2000));
        assert!(piece1.was_read("register", 0x0));
    }

    #[test]
    fn test_spaces() {
        let mut piece = AddressesReadStatePiece::new();
        piece.record_read("ram", 0x1000, 4);
        piece.record_read("register", 0x0, 8);
        piece.record_read("stack", 0x0, 8);

        let spaces = piece.spaces();
        assert_eq!(spaces.len(), 3);
    }

    #[test]
    fn test_clear() {
        let mut piece = AddressesReadStatePiece::new();
        piece.record_read("ram", 0x1000, 4);
        assert!(!piece.is_empty());

        piece.clear();
        assert!(piece.is_empty());
        assert_eq!(piece.read_count(), 0);
    }
}
