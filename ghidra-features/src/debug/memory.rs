//! Memory model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.memory` — includes [`TraceMemoryState`],
//! [`TraceMemoryRegion`], [`TraceMemoryFlag`], and a basic in-memory
//! representation of trace memory.

use std::collections::BTreeMap;
use std::fmt;

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// TraceMemoryState
// ---------------------------------------------------------------------------

/// The observation state of a memory byte at a snapshot.
///
/// Ported from `ghidra.trace.model.memory.TraceMemoryState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceMemoryState {
    /// The value was not observed at the snapshot.
    Unknown,
    /// The value was observed at the snapshot.
    Known,
    /// The value could not be observed at the snapshot.
    Error,
}

impl TraceMemoryState {
    /// Returns `true` if this state is implied by a `None` value in storage.
    ///
    /// `Unknown` is the default/implied state; `Known` and `Error` must be stored.
    pub fn implied_by_null(&self) -> bool {
        *self == TraceMemoryState::Unknown
    }

    /// Returns `true` if this state indicates a known value (truncation boundary).
    pub fn truncates(&self) -> bool {
        *self == TraceMemoryState::Known
    }

    /// Given an optional state, returns the implied state (default `Unknown`).
    pub fn or_implied(s: Option<TraceMemoryState>) -> TraceMemoryState {
        s.unwrap_or(TraceMemoryState::Unknown)
    }
}

impl fmt::Display for TraceMemoryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceMemoryState::Unknown => write!(f, "Unknown"),
            TraceMemoryState::Known => write!(f, "Known"),
            TraceMemoryState::Error => write!(f, "Error"),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceMemoryFlag
// ---------------------------------------------------------------------------

/// Flags associated with a memory region in a trace.
///
/// Ported from `ghidra.trace.model.memory.TraceMemoryFlag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceMemoryFlag {
    /// The region is readable.
    Read,
    /// The region is writable.
    Write,
    /// The region is executable.
    Execute,
    /// The region is volatile (may change between reads).
    Volatile,
}

// ---------------------------------------------------------------------------
// TraceMemoryRegion
// ---------------------------------------------------------------------------

/// A named region of memory in a trace.
///
/// Ported from `ghidra.trace.model.memory.TraceMemoryRegion`.
#[derive(Debug, Clone)]
pub struct TraceMemoryRegion {
    /// Unique key for this region.
    key: u64,
    /// Time-varying names: (snap_from, name).
    names: BTreeMap<i64, String>,
    /// Time-varying start addresses: (snap_from, address).
    start_addresses: BTreeMap<i64, u64>,
    /// Time-varying end addresses: (snap_from, address).
    end_addresses: BTreeMap<i64, u64>,
    /// Time-varying flags: (snap_from, flags).
    flags: BTreeMap<i64, Vec<TraceMemoryFlag>>,
    /// The lifespan of this region.
    pub lifespan: Lifespan,
    /// Whether the region has been deleted.
    deleted: bool,
}

impl TraceMemoryRegion {
    /// Create a new memory region.
    pub fn new(
        key: u64,
        snap: i64,
        name: impl Into<String>,
        start_address: u64,
        end_address: u64,
    ) -> Self {
        let mut names = BTreeMap::new();
        names.insert(snap, name.into());
        let mut starts = BTreeMap::new();
        starts.insert(snap, start_address);
        let mut ends = BTreeMap::new();
        ends.insert(snap, end_address);
        Self {
            key,
            names,
            start_addresses: starts,
            end_addresses: ends,
            flags: BTreeMap::new(),
            lifespan: Lifespan::now_on(snap),
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Get the region name at the given snapshot.
    pub fn get_name(&self, snap: i64) -> Option<&str> {
        self.names.range(..=snap).next_back().map(|(_, n)| n.as_str())
    }

    /// Set the region name effective from the given snapshot.
    pub fn set_name(&mut self, snap: i64, name: impl Into<String>) {
        self.names.insert(snap, name.into());
    }

    /// Get the start address at the given snapshot.
    pub fn get_start_address(&self, snap: i64) -> Option<u64> {
        self.start_addresses
            .range(..=snap)
            .next_back()
            .map(|(_, a)| *a)
    }

    /// Get the end address at the given snapshot.
    pub fn get_end_address(&self, snap: i64) -> Option<u64> {
        self.end_addresses
            .range(..=snap)
            .next_back()
            .map(|(_, a)| *a)
    }

    /// Set the address range effective from the given snapshot.
    pub fn set_range(&mut self, snap: i64, start: u64, end: u64) {
        self.start_addresses.insert(snap, start);
        self.end_addresses.insert(snap, end);
    }

    /// Get the length (in bytes) at the given snapshot.
    pub fn get_length(&self, snap: i64) -> Option<u64> {
        let start = self.get_start_address(snap)?;
        let end = self.get_end_address(snap)?;
        Some(end.wrapping_sub(start).wrapping_add(1))
    }

    /// Get the flags at the given snapshot.
    pub fn get_flags(&self, snap: i64) -> Option<&[TraceMemoryFlag]> {
        self.flags
            .range(..=snap)
            .next_back()
            .map(|(_, f)| f.as_slice())
    }

    /// Set the flags effective from the given snapshot.
    pub fn set_flags(&mut self, snap: i64, flags: Vec<TraceMemoryFlag>) {
        self.flags.insert(snap, flags);
    }

    /// Check if the region contains the given address at the snapshot.
    pub fn contains_address(&self, address: u64, snap: i64) -> bool {
        if let (Some(start), Some(end)) = (self.get_start_address(snap), self.get_end_address(snap))
        {
            start <= address && address <= end
        } else {
            false
        }
    }

    /// Remove this region from the given snap onward.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap - 1);
    }

    /// Delete this region.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }
}

// ---------------------------------------------------------------------------
// TraceMemoryBlock
// ---------------------------------------------------------------------------

/// An actual block of bytes in trace memory at a given snapshot.
///
/// This is a simplified in-memory representation. The real Ghidra
/// implementation uses database-backed storage.
#[derive(Debug, Clone)]
pub struct TraceMemoryBlock {
    /// The base address of this block.
    pub base_address: u64,
    /// The bytes of the block at the current snapshot.
    bytes: Vec<u8>,
    /// The state of each byte (known, unknown, error).
    states: Vec<TraceMemoryState>,
}

impl TraceMemoryBlock {
    /// Create a new memory block with all bytes in the given state.
    pub fn new(base_address: u64, size: usize, state: TraceMemoryState) -> Self {
        Self {
            base_address,
            bytes: vec![0u8; size],
            states: vec![state; size],
        }
    }

    /// Create a known memory block from existing bytes.
    pub fn from_bytes(base_address: u64, data: &[u8]) -> Self {
        Self {
            base_address,
            bytes: data.to_vec(),
            states: vec![TraceMemoryState::Known; data.len()],
        }
    }

    /// Returns the size of this block in bytes.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    /// Returns the end address (inclusive).
    pub fn end_address(&self) -> u64 {
        self.base_address + self.size() as u64 - 1
    }

    /// Read a single byte at the given address offset from base.
    pub fn get_byte(&self, offset: usize) -> Option<(u8, TraceMemoryState)> {
        if offset < self.bytes.len() {
            Some((self.bytes[offset], self.states[offset]))
        } else {
            None
        }
    }

    /// Write a single byte at the given address offset from base.
    pub fn set_byte(&mut self, offset: usize, value: u8, state: TraceMemoryState) {
        if offset < self.bytes.len() {
            self.bytes[offset] = value;
            self.states[offset] = state;
        }
    }

    /// Read bytes at the given address. Returns (data, states).
    pub fn get_bytes(&self, address: u64, len: usize) -> Option<(&[u8], &[TraceMemoryState])> {
        let offset = address.checked_sub(self.base_address)? as usize;
        if offset + len <= self.bytes.len() {
            Some((&self.bytes[offset..offset + len], &self.states[offset..offset + len]))
        } else {
            None
        }
    }

    /// Write bytes at the given address.
    pub fn put_bytes(&mut self, address: u64, data: &[u8]) -> bool {
        let offset = match address.checked_sub(self.base_address) {
            Some(o) => o as usize,
            None => return false,
        };
        if offset + data.len() > self.bytes.len() {
            return false;
        }
        for (i, &b) in data.iter().enumerate() {
            self.bytes[offset + i] = b;
            self.states[offset + i] = TraceMemoryState::Known;
        }
        true
    }

    /// Check if this block contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base_address && address <= self.end_address()
    }

    /// Check if this block overlaps with an address range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.base_address <= end && start <= self.end_address()
    }

    /// Get the state of a byte at the given offset.
    pub fn get_state(&self, offset: usize) -> TraceMemoryState {
        self.states
            .get(offset)
            .copied()
            .unwrap_or(TraceMemoryState::Unknown)
    }

    /// Mark all bytes in a range as the given state.
    pub fn set_state_range(&mut self, offset: usize, len: usize, state: TraceMemoryState) {
        for i in offset..(offset + len).min(self.states.len()) {
            self.states[i] = state;
        }
    }
}

// ---------------------------------------------------------------------------
// TraceMemoryManager
// ---------------------------------------------------------------------------

/// A simplified in-memory trace memory manager.
///
/// Manages a set of memory blocks and memory regions. The real Ghidra
/// implementation is database-backed; this is a simplified version for
/// headless/CLI usage.
#[derive(Debug)]
pub struct TraceMemoryManager {
    /// Memory blocks indexed by base address.
    blocks: BTreeMap<u64, TraceMemoryBlock>,
    /// Memory regions indexed by key.
    regions: BTreeMap<u64, TraceMemoryRegion>,
    next_region_key: u64,
}

impl TraceMemoryManager {
    /// Create a new empty memory manager.
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            regions: BTreeMap::new(),
            next_region_key: 1,
        }
    }

    /// Add a memory block. If a block at that base address exists, it is replaced.
    pub fn add_block(&mut self, block: TraceMemoryBlock) {
        self.blocks.insert(block.base_address, block);
    }

    /// Remove the block at the given base address.
    pub fn remove_block(&mut self, base_address: u64) -> Option<TraceMemoryBlock> {
        self.blocks.remove(&base_address)
    }

    /// Get the block containing the given address.
    pub fn get_block_for_address(&self, address: u64) -> Option<&TraceMemoryBlock> {
        // Find the block whose base_address is <= address and whose end_address >= address.
        self.blocks
            .range(..=address)
            .next_back()
            .filter(|(_, block)| block.contains(address))
            .map(|(_, block)| block)
    }

    /// Get a mutable reference to the block containing the given address.
    pub fn get_block_for_address_mut(&mut self, address: u64) -> Option<&mut TraceMemoryBlock> {
        let base = self
            .blocks
            .range(..=address)
            .next_back()
            .filter(|(_, block)| block.contains(address))
            .map(|(k, _)| *k)?;
        self.blocks.get_mut(&base)
    }

    /// Read bytes from trace memory.
    pub fn get_bytes(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        let block = self.get_block_for_address(address)?;
        let (data, _states) = block.get_bytes(address, len)?;
        Some(data.to_vec())
    }

    /// Write bytes to trace memory.
    ///
    /// Returns the number of bytes actually written.
    pub fn put_bytes(&mut self, address: u64, data: &[u8]) -> usize {
        if let Some(block) = self.get_block_for_address_mut(address) {
            if block.put_bytes(address, data) {
                return data.len();
            }
        }
        0
    }

    /// Iterate over all blocks.
    pub fn blocks(&self) -> impl Iterator<Item = &TraceMemoryBlock> {
        self.blocks.values()
    }

    /// Add a new memory region.
    pub fn add_region(
        &mut self,
        snap: i64,
        name: impl Into<String>,
        start_address: u64,
        end_address: u64,
    ) -> u64 {
        let key = self.next_region_key;
        self.next_region_key += 1;
        self.regions.insert(
            key,
            TraceMemoryRegion::new(key, snap, name, start_address, end_address),
        );
        key
    }

    /// Get a region by key.
    pub fn get_region(&self, key: u64) -> Option<&TraceMemoryRegion> {
        self.regions.get(&key)
    }

    /// Get a mutable region by key.
    pub fn get_region_mut(&mut self, key: u64) -> Option<&mut TraceMemoryRegion> {
        self.regions.get_mut(&key)
    }

    /// Get all regions valid at the given snapshot.
    pub fn get_regions_at_snap(&self, snap: i64) -> Vec<&TraceMemoryRegion> {
        self.regions
            .values()
            .filter(|r| r.is_valid(snap))
            .collect()
    }

    /// Iterate over all regions.
    pub fn regions(&self) -> impl Iterator<Item = &TraceMemoryRegion> {
        self.regions.values()
    }
}

impl Default for TraceMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_state() {
        assert!(TraceMemoryState::Unknown.implied_by_null());
        assert!(!TraceMemoryState::Known.implied_by_null());
        assert!(!TraceMemoryState::Error.implied_by_null());
        assert!(TraceMemoryState::Known.truncates());
        assert!(!TraceMemoryState::Unknown.truncates());

        assert_eq!(
            TraceMemoryState::or_implied(None),
            TraceMemoryState::Unknown
        );
        assert_eq!(
            TraceMemoryState::or_implied(Some(TraceMemoryState::Known)),
            TraceMemoryState::Known
        );
    }

    #[test]
    fn test_memory_region_basic() {
        let region = TraceMemoryRegion::new(1, 0, ".text", 0x400000, 0x400FFF);
        assert_eq!(region.key(), 1);
        assert_eq!(region.get_name(0), Some(".text"));
        assert_eq!(region.get_start_address(0), Some(0x400000));
        assert_eq!(region.get_end_address(0), Some(0x400FFF));
        assert_eq!(region.get_length(0), Some(0x1000));
        assert!(region.contains_address(0x400500, 0));
        assert!(!region.contains_address(0x3FFFFF, 0));
        assert!(!region.contains_address(0x401000, 0));
        assert!(region.is_valid(0));
    }

    #[test]
    fn test_memory_region_name_history() {
        let mut region = TraceMemoryRegion::new(1, 0, ".text", 0x400000, 0x400FFF);
        region.set_name(10, ".text_segment");

        assert_eq!(region.get_name(0), Some(".text"));
        assert_eq!(region.get_name(10), Some(".text_segment"));
    }

    #[test]
    fn test_memory_block() {
        let mut block = TraceMemoryBlock::from_bytes(0x1000, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(block.size(), 4);
        assert_eq!(block.end_address(), 0x1003);
        assert!(block.contains(0x1000));
        assert!(block.contains(0x1003));
        assert!(!block.contains(0x1004));
        assert!(!block.contains(0x0FFF));

        let (data, states) = block.get_bytes(0x1001, 2).unwrap();
        assert_eq!(data, &[0xBB, 0xCC]);
        assert_eq!(states, &[TraceMemoryState::Known, TraceMemoryState::Known]);

        block.put_bytes(0x1002, &[0xEE, 0xFF]);
        let (data2, _) = block.get_bytes(0x1002, 2).unwrap();
        assert_eq!(data2, &[0xEE, 0xFF]);
    }

    #[test]
    fn test_memory_block_out_of_bounds() {
        let block = TraceMemoryBlock::new(0x1000, 4, TraceMemoryState::Unknown);
        assert!(block.get_bytes(0x2000, 1).is_none());
        assert!(block.get_bytes(0x0FFF, 1).is_none());
        assert!(block.get_bytes(0x1003, 2).is_none());
    }

    #[test]
    fn test_memory_block_state() {
        let mut block = TraceMemoryBlock::new(0x1000, 4, TraceMemoryState::Unknown);
        block.set_state_range(1, 2, TraceMemoryState::Known);
        assert_eq!(block.get_state(0), TraceMemoryState::Unknown);
        assert_eq!(block.get_state(1), TraceMemoryState::Known);
        assert_eq!(block.get_state(2), TraceMemoryState::Known);
        assert_eq!(block.get_state(3), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_memory_manager_blocks() {
        let mut mgr = TraceMemoryManager::new();
        mgr.add_block(TraceMemoryBlock::from_bytes(0x1000, &[1, 2, 3, 4]));
        mgr.add_block(TraceMemoryBlock::from_bytes(0x2000, &[5, 6]));

        let bytes = mgr.get_bytes(0x1001, 2).unwrap();
        assert_eq!(bytes, vec![2, 3]);

        let bytes2 = mgr.get_bytes(0x2000, 2).unwrap();
        assert_eq!(bytes2, vec![5, 6]);

        let written = mgr.put_bytes(0x1000, &[0xAA, 0xBB]);
        assert_eq!(written, 2);

        let bytes3 = mgr.get_bytes(0x1000, 2).unwrap();
        assert_eq!(bytes3, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_memory_manager_regions() {
        let mut mgr = TraceMemoryManager::new();
        let r1 = mgr.add_region(0, ".text", 0x400000, 0x400FFF);
        let r2 = mgr.add_region(0, ".data", 0x600000, 0x600FFF);

        assert_eq!(mgr.regions().count(), 2);

        let region = mgr.get_region(r1).unwrap();
        assert_eq!(region.get_name(0), Some(".text"));

        let at_snap = mgr.get_regions_at_snap(0);
        assert_eq!(at_snap.len(), 2);

        let region_mut = mgr.get_region_mut(r2).unwrap();
        region_mut.remove(10);
        assert!(!mgr.get_region(r2).unwrap().is_valid(10));
    }
}
