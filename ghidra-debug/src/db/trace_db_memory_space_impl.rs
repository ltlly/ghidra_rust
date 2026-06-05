//! Full memory space implementation for the trace database.
//!
//! Ported from Ghidra's `DBTraceMemorySpace` in
//! `ghidra.trace.database.memory`. Implements copy-on-write memory
//! storage with block-level granularity and state tracking.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::model::{Lifespan, TraceMemoryState};

/// Block size for memory storage (4 KB, matching Ghidra).
pub const BLOCK_SHIFT: u32 = 12;
/// Block size in bytes.
pub const BLOCK_SIZE: u64 = 1 << BLOCK_SHIFT;
/// Block alignment mask.
pub const BLOCK_MASK: u64 = !((1u64 << BLOCK_SHIFT) - 1);

/// State block size for memory state tracking (256 bytes).
pub const STATE_BLOCK_SHIFT: u32 = 8;
/// State block size.
pub const STATE_BLOCK_SIZE: u64 = 1 << STATE_BLOCK_SHIFT;

/// A memory block entry storing a chunk of bytes.
///
/// Ported from Ghidra's `DBTraceMemoryBlockEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceMemoryBlockEntry {
    /// The block base address (aligned to BLOCK_SIZE).
    pub base_offset: u64,
    /// The snap at which this block was written.
    pub snap: i64,
    /// The raw bytes (up to BLOCK_SIZE).
    pub bytes: Vec<u8>,
    /// Whether this block is compressed.
    pub compressed: bool,
}

impl DbTraceMemoryBlockEntry {
    /// Create a new block entry.
    pub fn new(base_offset: u64, snap: i64, bytes: Vec<u8>) -> Self {
        Self {
            base_offset,
            snap,
            bytes,
            compressed: false,
        }
    }

    /// Get the base address of this block.
    pub fn base(&self) -> u64 {
        self.base_offset & BLOCK_MASK
    }

    /// Get the byte at a specific offset within this block.
    pub fn byte_at(&self, offset: u64) -> Option<u8> {
        let idx = (offset - self.base()) as usize;
        self.bytes.get(idx).copied()
    }

    /// Get the size of this block.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
}

/// A memory buffer entry for reading memory at a specific point.
///
/// Ported from Ghidra's `DBTraceMemoryBufferEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceMemoryBufferEntry {
    /// The address offset.
    pub offset: u64,
    /// The snap.
    pub snap: i64,
    /// The bytes at this location.
    pub bytes: Vec<u8>,
}

/// A memory region entry.
///
/// Ported from Ghidra's `DBTraceMemoryRegion`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceMemoryRegion {
    /// Region path (unique name).
    pub path: String,
    /// The address space.
    pub space: String,
    /// Start offset.
    pub min_offset: u64,
    /// End offset.
    pub max_offset: u64,
    /// The lifespan.
    pub min_snap: i64,
    pub max_snap: i64,
    /// Memory flags.
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub volatile: bool,
    /// Display name.
    pub name: String,
}

impl DbTraceMemoryRegion {
    /// Create a new memory region.
    pub fn new(
        path: impl Into<String>,
        space: impl Into<String>,
        min_offset: u64,
        max_offset: u64,
        min_snap: i64,
        max_snap: i64,
        readable: bool,
        writable: bool,
        executable: bool,
        name: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            space: space.into(),
            min_offset,
            max_offset,
            min_snap,
            max_snap,
            readable,
            writable,
            executable,
            volatile: false,
            name: name.into(),
        }
    }

    /// Get the address range as (min, max).
    pub fn range(&self) -> (u64, u64) {
        (self.min_offset, self.max_offset)
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }

    /// Whether the region is active at a given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    /// Whether the region contains the given offset.
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.min_offset && offset <= self.max_offset
    }
}

/// A memory state entry for a specific address range and time.
///
/// Ported from Ghidra's `DBTraceMemoryStateEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceMemoryStateEntry {
    /// Address space.
    pub space: String,
    /// Start offset.
    pub min_offset: u64,
    /// End offset.
    pub max_offset: u64,
    /// Snap range.
    pub min_snap: i64,
    pub max_snap: i64,
    /// The memory state.
    pub state: TraceMemoryState,
}

impl DbTraceMemoryStateEntry {
    /// Create a new state entry.
    pub fn new(
        space: impl Into<String>,
        min_offset: u64,
        max_offset: u64,
        min_snap: i64,
        max_snap: i64,
        state: TraceMemoryState,
    ) -> Self {
        Self {
            space: space.into(),
            min_offset,
            max_offset,
            min_snap,
            max_snap,
            state,
        }
    }

    /// Whether this entry covers the given address at the given snap.
    pub fn covers(&self, offset: u64, snap: i64) -> bool {
        offset >= self.min_offset
            && offset <= self.max_offset
            && snap >= self.min_snap
            && snap <= self.max_snap
    }
}

/// The full memory space implementation for a single address space.
///
/// Ported from Ghidra's `DBTraceMemorySpace`. Uses copy-on-write
/// semantics with block-level granularity.
#[derive(Debug)]
pub struct DbTraceMemorySpaceImpl {
    /// The address space name.
    pub space: String,
    /// Memory blocks indexed by (block_base, snap).
    blocks: BTreeMap<(u64, i64), DbTraceMemoryBlockEntry>,
    /// Memory regions active in this space.
    regions: Vec<DbTraceMemoryRegion>,
    /// State entries.
    states: Vec<DbTraceMemoryStateEntry>,
}

impl DbTraceMemorySpaceImpl {
    /// Create a new memory space.
    pub fn new(space: impl Into<String>) -> Self {
        Self {
            space: space.into(),
            blocks: BTreeMap::new(),
            regions: Vec::new(),
            states: Vec::new(),
        }
    }

    /// Write bytes at an offset and snap.
    pub fn write_bytes(&mut self, offset: u64, snap: i64, data: &[u8]) {
        let block_base = offset & BLOCK_MASK;
        let block_offset = (offset - block_base) as usize;

        // For simplicity, create/update a single block
        let entry = self
            .blocks
            .entry((block_base, snap))
            .or_insert_with(|| DbTraceMemoryBlockEntry::new(block_base, snap, vec![0u8; BLOCK_SIZE as usize]));

        let end = (block_offset + data.len()).min(BLOCK_SIZE as usize);
        let copy_len = end - block_offset;
        if entry.bytes.len() < end {
            entry.bytes.resize(end, 0);
        }
        entry.bytes[block_offset..block_offset + copy_len].copy_from_slice(&data[..copy_len]);
    }

    /// Read bytes at an offset and snap (using most-recent write).
    pub fn read_bytes(&self, offset: u64, snap: i64, len: usize) -> Vec<Option<u8>> {
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let addr = offset + i as u64;
            result.push(self.read_byte(addr, snap));
        }
        result
    }

    /// Read a single byte at an offset and snap.
    pub fn read_byte(&self, offset: u64, snap: i64) -> Option<u8> {
        let block_base = offset & BLOCK_MASK;
        let block_offset = (offset - block_base) as usize;

        // Find the most recent block at or before this snap
        self.blocks
            .range(..=(block_base, snap))
            .rev()
            .find(|((base, _), _)| *base == block_base)
            .and_then(|(_, entry)| entry.bytes.get(block_offset).copied())
    }

    /// Set the memory state for an address range.
    pub fn set_state(&mut self, space: &str, min_offset: u64, max_offset: u64, min_snap: i64, max_snap: i64, state: TraceMemoryState) {
        self.states.push(DbTraceMemoryStateEntry::new(
            space, min_offset, max_offset, min_snap, max_snap, state,
        ));
    }

    /// Get the memory state at a specific address and snap.
    pub fn get_state(&self, offset: u64, snap: i64) -> TraceMemoryState {
        self.states
            .iter()
            .rev()
            .find(|s| s.covers(offset, snap))
            .map(|s| s.state)
            .unwrap_or(TraceMemoryState::Unknown)
    }

    /// Add a memory region.
    pub fn add_region(&mut self, region: DbTraceMemoryRegion) {
        self.regions.push(region);
    }

    /// Get regions active at a given snap.
    pub fn get_regions_at(&self, snap: i64) -> Vec<&DbTraceMemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.is_active_at(snap))
            .collect()
    }

    /// Get the region containing the given offset at the given snap.
    pub fn get_region_at(&self, offset: u64, snap: i64) -> Option<&DbTraceMemoryRegion> {
        self.regions
            .iter()
            .find(|r| r.is_active_at(snap) && r.contains_offset(offset))
    }

    /// Clear all data in this space.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.regions.clear();
        self.states.clear();
    }

    /// Get the number of blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_constants() {
        assert_eq!(BLOCK_SIZE, 4096);
        assert_eq!(BLOCK_MASK, !0xFFF);
    }

    #[test]
    fn test_memory_block_entry() {
        let entry = DbTraceMemoryBlockEntry::new(0x1000, 0, vec![1, 2, 3, 4]);
        assert_eq!(entry.base(), 0x1000);
        assert_eq!(entry.byte_at(0x1000), Some(1));
        assert_eq!(entry.byte_at(0x1002), Some(3));
        assert_eq!(entry.size(), 4);
    }

    #[test]
    fn test_memory_region() {
        let region = DbTraceMemoryRegion::new(
            ".text", "ram", 0x1000, 0x2000, 0, 100,
            true, false, true, ".text",
        );
        assert!(region.is_active_at(50));
        assert!(!region.is_active_at(150));
        assert!(region.contains_offset(0x1500));
        assert!(!region.contains_offset(0x2500));
    }

    #[test]
    fn test_memory_space_write_read() {
        let mut space = DbTraceMemorySpaceImpl::new("ram");
        space.write_bytes(0x1000, 0, &[0xAA, 0xBB, 0xCC]);
        let bytes = space.read_bytes(0x1000, 0, 3);
        assert_eq!(bytes, vec![Some(0xAA), Some(0xBB), Some(0xCC)]);
    }

    #[test]
    fn test_memory_space_snap_isolation() {
        let mut space = DbTraceMemorySpaceImpl::new("ram");
        space.write_bytes(0x1000, 0, &[0xAA]);
        space.write_bytes(0x1000, 50, &[0xBB]);
        assert_eq!(space.read_byte(0x1000, 0), Some(0xAA));
        assert_eq!(space.read_byte(0x1000, 50), Some(0xBB));
        assert_eq!(space.read_byte(0x1000, 75), Some(0xBB));
    }

    #[test]
    fn test_memory_space_state() {
        let mut space = DbTraceMemorySpaceImpl::new("ram");
        space.set_state("ram", 0x1000, 0x2000, 0, 100, TraceMemoryState::Known);
        assert_eq!(space.get_state(0x1500, 50), TraceMemoryState::Known);
        assert_eq!(space.get_state(0x1500, 150), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_memory_space_regions() {
        let mut space = DbTraceMemorySpaceImpl::new("ram");
        space.add_region(DbTraceMemoryRegion::new(
            ".text", "ram", 0x1000, 0x2000, 0, 100,
            true, false, true, ".text",
        ));
        space.add_region(DbTraceMemoryRegion::new(
            ".data", "ram", 0x3000, 0x4000, 0, 100,
            true, true, false, ".data",
        ));
        let regions = space.get_regions_at(50);
        assert_eq!(regions.len(), 2);
        let region = space.get_region_at(0x1500, 50);
        assert!(region.is_some());
        assert_eq!(region.unwrap().name, ".text");
    }
}
