//! Memory operations abstraction for trace data.
//!
//! Ported from Ghidra's `ghidra.trace.model.memory.TraceMemoryOperations`.
//!
//! Provides the interface for reading and writing memory state in a trace,
//! including byte-level access, state queries, and register value access.
//! This is the core trait used by emulation, disassembly, and GUI code
//! to interact with trace memory.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// TraceMemoryState
// ---------------------------------------------------------------------------

// Re-export TraceMemoryState from the model::memory module for convenience.
// The canonical definition is in `crate::model::memory`.
pub use crate::model::memory::TraceMemoryState;

/// Extension methods for `TraceMemoryState`.
pub trait TraceMemoryStateExt {
    /// Whether the state indicates the byte value is available.
    fn is_known(&self) -> bool;
    /// Whether the state indicates the byte value is unavailable.
    fn is_unknown(&self) -> bool;
    /// Whether the state indicates an error condition.
    fn is_error(&self) -> bool;
}

impl TraceMemoryStateExt for TraceMemoryState {
    fn is_known(&self) -> bool {
        matches!(self, Self::Known)
    }
    fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
    fn is_error(&self) -> bool {
        matches!(self, Self::Error)
    }
}

// ---------------------------------------------------------------------------
// Memory operations trait
// ---------------------------------------------------------------------------

/// Trait for objects that provide memory access in a trace.
///
/// Ported from `ghidra.trace.model.memory.TraceMemoryOperations`.
/// This is implemented by `TraceMemoryManager` and `TraceProgramView`.
pub trait TraceMemoryOperations {
    /// Read bytes from memory.
    ///
    /// Returns the number of bytes actually read (may be less than `buf.len()`
    /// if the read extends beyond known memory).
    fn get_bytes(&self, snap: i64, address: u64, buf: &mut [u8]) -> usize;

    /// Write bytes to memory.
    fn put_bytes(&mut self, snap: i64, address: u64, data: &[u8]);

    /// Get the state of a range of memory bytes.
    fn get_states(&self, snap: i64, address: u64, length: u64) -> Vec<TraceMemoryState>;

    /// Set the state of a range of memory bytes.
    fn set_states(&mut self, snap: i64, address: u64, length: u64, state: TraceMemoryState);

    /// Check if all bytes in a range are in the given state.
    fn is_state_entirely(
        &self,
        snap: i64,
        min_address: u64,
        max_address: u64,
        state: TraceMemoryState,
    ) -> bool {
        let states = self.get_states(snap, min_address, max_address - min_address + 1);
        states.iter().all(|s| *s == state)
    }

    /// Get the defined memory regions at a given snap.
    fn get_regions(&self, snap: i64) -> Vec<MemoryRegionInfo>;
}

/// Information about a memory region in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionInfo {
    /// Start address of the region.
    pub min_address: u64,
    /// End address of the region (inclusive).
    pub max_address: u64,
    /// The lifespan during which this region exists.
    pub lifespan: Lifespan,
    /// Whether the region is writable.
    pub writable: bool,
    /// Whether the region is executable.
    pub executable: bool,
    /// Whether the region is readable.
    pub readable: bool,
    /// Name of the region (e.g., module name).
    pub name: String,
}

impl MemoryRegionInfo {
    /// Create a new memory region info.
    pub fn new(
        min_address: u64,
        max_address: u64,
        lifespan: Lifespan,
        name: impl Into<String>,
    ) -> Self {
        Self {
            min_address,
            max_address,
            lifespan,
            writable: true,
            executable: false,
            readable: true,
            name: name.into(),
        }
    }

    /// Set permissions.
    pub fn with_permissions(mut self, read: bool, write: bool, exec: bool) -> Self {
        self.readable = read;
        self.writable = write;
        self.executable = exec;
        self
    }

    /// The size of this region in bytes.
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }

    /// Check if an address is within this region.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.min_address && address <= self.max_address
    }

    /// Check if this region overlaps with an address range.
    pub fn overlaps(&self, min: u64, max: u64) -> bool {
        self.min_address <= max && self.max_address >= min
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation for testing
// ---------------------------------------------------------------------------

/// A simple in-memory implementation of `TraceMemoryOperations`.
///
/// Useful for testing and for emulation where no database is needed.
#[derive(Debug, Default)]
pub struct InMemoryTraceMemory {
    /// Byte storage indexed by (snap, address).
    bytes: BTreeMap<(i64, u64), u8>,
    /// State storage indexed by (snap, address).
    states: BTreeMap<(i64, u64), TraceMemoryState>,
    /// Memory regions.
    regions: Vec<MemoryRegionInfo>,
}

impl InMemoryTraceMemory {
    /// Create a new empty in-memory trace memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a memory region.
    pub fn add_region(&mut self, region: MemoryRegionInfo) {
        self.regions.push(region);
    }
}

impl TraceMemoryOperations for InMemoryTraceMemory {
    fn get_bytes(&self, snap: i64, address: u64, buf: &mut [u8]) -> usize {
        let mut count = 0;
        for (i, byte) in buf.iter_mut().enumerate() {
            if let Some(&v) = self.bytes.get(&(snap, address + i as u64)) {
                *byte = v;
                count += 1;
            } else {
                *byte = 0;
            }
        }
        count
    }

    fn put_bytes(&mut self, snap: i64, address: u64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.bytes.insert((snap, address + i as u64), byte);
            self.states.insert((snap, address + i as u64), TraceMemoryState::Known);
        }
    }

    fn get_states(&self, snap: i64, address: u64, length: u64) -> Vec<TraceMemoryState> {
        (0..length)
            .map(|i| {
                self.states
                    .get(&(snap, address + i))
                    .copied()
                    .unwrap_or(TraceMemoryState::Unknown)
            })
            .collect()
    }

    fn set_states(&mut self, snap: i64, address: u64, length: u64, state: TraceMemoryState) {
        for i in 0..length {
            self.states.insert((snap, address + i), state);
        }
    }

    fn get_regions(&self, snap: i64) -> Vec<MemoryRegionInfo> {
        self.regions
            .iter()
            .filter(|r| r.lifespan.contains(snap))
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// State query utilities
// ---------------------------------------------------------------------------

/// Check if a range of memory is entirely in the given state.
pub fn is_state_entirely(
    min_address: u64,
    max_address: u64,
    states: &[TraceMemoryState],
    expected: TraceMemoryState,
) -> bool {
    let expected_count = (max_address - min_address + 1) as usize;
    if states.len() < expected_count {
        return false;
    }
    states[..expected_count].iter().all(|s| *s == expected)
}

/// Get the first address in a range that does NOT match the expected state.
pub fn find_first_non_matching(
    min_address: u64,
    states: &[TraceMemoryState],
    expected: TraceMemoryState,
) -> Option<u64> {
    states
        .iter()
        .enumerate()
        .find(|(_, s)| **s != expected)
        .map(|(i, _)| min_address + i as u64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_state_properties() {
        assert!(TraceMemoryState::Known.is_known());
        assert!(!TraceMemoryState::Known.is_unknown());
        assert!(!TraceMemoryState::Unknown.is_known());
        assert!(TraceMemoryState::Error.is_error());
    }

    #[test]
    fn test_memory_region_info() {
        let region = MemoryRegionInfo::new(0x400000, 0x400FFF, Lifespan::span(0, 100), ".text")
            .with_permissions(true, false, true);

        assert_eq!(region.size(), 0x1000);
        assert!(region.contains(0x400100));
        assert!(!region.contains(0x500000));
        assert!(region.readable);
        assert!(!region.writable);
        assert!(region.executable);
    }

    #[test]
    fn test_memory_region_overlaps() {
        let region = MemoryRegionInfo::new(0x400000, 0x400FFF, Lifespan::span(0, 100), ".text");
        assert!(region.overlaps(0x400100, 0x400200));
        assert!(region.overlaps(0x3FFFFF, 0x400001));
        assert!(!region.overlaps(0x500000, 0x500100));
    }

    #[test]
    fn test_in_memory_trace_memory() {
        let mut mem = InMemoryTraceMemory::new();

        // Write bytes
        mem.put_bytes(0, 0x400000, &[0x55, 0x48, 0x89, 0xE5]);
        assert_eq!(mem.get_states(0, 0x400000, 4), vec![
            TraceMemoryState::Known,
            TraceMemoryState::Known,
            TraceMemoryState::Known,
            TraceMemoryState::Known,
        ]);

        // Read bytes back
        let mut buf = [0u8; 4];
        let count = mem.get_bytes(0, 0x400000, &mut buf);
        assert_eq!(count, 4);
        assert_eq!(buf, [0x55, 0x48, 0x89, 0xE5]);
    }

    #[test]
    fn test_in_memory_trace_memory_unknown() {
        let mem = InMemoryTraceMemory::new();
        let states = mem.get_states(0, 0x400000, 4);
        assert!(states.iter().all(|s| *s == TraceMemoryState::Unknown));
    }

    #[test]
    fn test_in_memory_trace_memory_regions() {
        let mut mem = InMemoryTraceMemory::new();
        mem.add_region(
            MemoryRegionInfo::new(0x400000, 0x400FFF, Lifespan::span(0, 100), ".text")
        );

        let regions = mem.get_regions(50);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].name, ".text");

        let regions = mem.get_regions(200);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_is_state_entirely() {
        let states = vec![
            TraceMemoryState::Known,
            TraceMemoryState::Known,
            TraceMemoryState::Unknown,
        ];
        assert!(!is_state_entirely(0, 2, &states, TraceMemoryState::Known));
        assert!(is_state_entirely(0, 1, &states, TraceMemoryState::Known));
    }

    #[test]
    fn test_find_first_non_matching() {
        let states = vec![
            TraceMemoryState::Known,
            TraceMemoryState::Known,
            TraceMemoryState::Unknown,
            TraceMemoryState::Known,
        ];
        assert_eq!(
            find_first_non_matching(0x400000, &states, TraceMemoryState::Known),
            Some(0x400002)
        );
        assert_eq!(
            find_first_non_matching(0x400000, &states, TraceMemoryState::Unknown),
            Some(0x400000)
        );
    }

    #[test]
    fn test_is_state_entirely_helper() {
        let mut mem = InMemoryTraceMemory::new();
        mem.put_bytes(0, 0x400000, &[1, 2, 3, 4]);

        assert!(mem.is_state_entirely(0, 0x400000, 0x400003, TraceMemoryState::Known));
        assert!(!mem.is_state_entirely(0, 0x400000, 0x400004, TraceMemoryState::Known));
    }
}
