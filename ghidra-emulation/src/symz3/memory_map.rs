//! Symbolic memory map.
//!
//! Ported from `SymZ3MemoryMap.java` in the SymbolicSummaryZ3 extension.
//!
//! Provides a higher-level view of the symbolic memory state, including
//! region tracking and symbolic memory initialization.

use super::model::SymValueZ3;
use super::state::{SpaceKind, SymZ3State};
use std::collections::BTreeMap;

/// A memory region descriptor.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Start address.
    pub start: u64,
    /// Size in bytes.
    pub size: u64,
    /// Region name / description.
    pub name: String,
    /// Whether the region is readable.
    pub readable: bool,
    /// Whether the region is writable.
    pub writable: bool,
}

impl MemoryRegion {
    /// Create a new memory region.
    pub fn new(start: u64, size: u64, name: impl Into<String>) -> Self {
        Self {
            start,
            size,
            name: name.into(),
            readable: true,
            writable: true,
        }
    }

    /// The end address (exclusive).
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    /// Whether `address` falls within this region.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address < self.end()
    }
}

/// Symbolic memory map.
///
/// Tracks memory regions and their symbolic contents.
#[derive(Debug, Clone, Default)]
pub struct SymZ3MemoryMap {
    /// Memory regions, sorted by start address.
    regions: BTreeMap<u64, MemoryRegion>,
}

impl SymZ3MemoryMap {
    /// Create an empty memory map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a memory region.
    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.insert(region.start, region);
    }

    /// Find the region containing the given address.
    pub fn find_region(&self, address: u64) -> Option<&MemoryRegion> {
        // Find the region with the largest start <= address
        self.regions
            .range(..=address)
            .next_back()
            .map(|(_, r)| r)
            .filter(|r| r.contains(address))
    }

    /// Number of regions.
    pub fn num_regions(&self) -> usize {
        self.regions.len()
    }

    /// Initialize memory in a symbolic state with a concrete byte value.
    pub fn init_concrete(
        &self,
        state: &mut SymZ3State,
        address: u64,
        bytes: &[u8],
    ) {
        for (i, &b) in bytes.iter().enumerate() {
            state.set_value(
                SpaceKind::Memory,
                address + i as u64,
                1,
                SymValueZ3::from_bitvec(format!("bv{b}")),
            );
        }
    }

    /// Initialize memory in a symbolic state with symbolic bytes.
    pub fn init_symbolic(
        &self,
        state: &mut SymZ3State,
        address: u64,
        size: u32,
        prefix: &str,
    ) {
        for i in 0..size {
            state.set_value(
                SpaceKind::Memory,
                address + i as u64,
                1,
                SymValueZ3::from_bitvec(format!("{prefix}_{i}")),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_region() {
        let r = MemoryRegion::new(0x1000, 0x100, ".text");
        assert!(r.contains(0x1000));
        assert!(r.contains(0x10FF));
        assert!(!r.contains(0x1100));
        assert!(!r.contains(0x0FFF));
    }

    #[test]
    fn test_memory_map_find_region() {
        let mut map = SymZ3MemoryMap::new();
        map.add_region(MemoryRegion::new(0x1000, 0x100, ".text"));
        map.add_region(MemoryRegion::new(0x2000, 0x100, ".data"));

        let r = map.find_region(0x1050).unwrap();
        assert_eq!(r.name, ".text");

        assert!(map.find_region(0x3000).is_none());
    }

    #[test]
    fn test_init_concrete() {
        let map = SymZ3MemoryMap::new();
        let mut state = SymZ3State::new();
        map.init_concrete(&mut state, 0x1000, &[0x48, 0x89, 0xE5]);
        assert_eq!(state.total_entries(), 3);
    }

    #[test]
    fn test_init_symbolic() {
        let map = SymZ3MemoryMap::new();
        let mut state = SymZ3State::new();
        map.init_symbolic(&mut state, 0x1000, 4, "mem");
        assert_eq!(state.total_entries(), 4);
    }
}
