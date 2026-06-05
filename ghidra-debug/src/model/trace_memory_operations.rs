//! TraceMemoryOperations - operations for reading and writing trace memory.
//!
//! Ported from Ghidra's `ghidra.trace.model.memory.TraceMemoryOperations`.

use super::Lifespan;
use super::memory::{TraceMemoryRegion, TraceMemoryState};
use super::memory_ext::TraceOverlappedRegionException;

/// The set of operations for managing trace memory state.
///
/// This trait defines the low-level read/write interface for memory bytes
/// and their observation states (known, unknown, error).
pub trait TraceMemoryOperations {
    /// Get the space name this operates on.
    fn space_name(&self) -> &str;

    /// Get the memory state at a specific snap, address.
    fn get_state(&self, snap: i64, address: u64) -> TraceMemoryState;

    /// Set the memory state for a range at a given snap.
    fn set_state(
        &mut self,
        snap: i64,
        min_addr: u64,
        max_addr: u64,
        state: TraceMemoryState,
    );

    /// Read bytes from memory at a snap and address.
    fn get_bytes(&self, snap: i64, address: u64, length: u32) -> Vec<u8>;

    /// Write bytes to memory at a snap and address.
    fn set_bytes(&mut self, snap: i64, address: u64, bytes: &[u8]);

    /// Get all regions at a given snap.
    fn get_regions(&self, snap: i64) -> Vec<&TraceMemoryRegion>;

    /// Add a region.
    fn add_region(
        &mut self,
        path: &str,
        lifespan: &Lifespan,
        min_addr: u64,
        max_addr: u64,
        flags: &[super::memory_flag::TraceMemoryFlag],
    ) -> Result<&TraceMemoryRegion, TraceOverlappedRegionException>;

    /// Remove a region by path.
    fn remove_region(&mut self, path: &str);

    /// Get a region by path at a snap.
    fn get_region_by_path(&self, snap: i64, path: &str) -> Option<&TraceMemoryRegion>;

    /// Get the region containing a specific address at a snap.
    fn get_region_containing(&self, snap: i64, address: u64) -> Option<&TraceMemoryRegion>;

    /// Get the union of all region address ranges at a snap.
    fn get_regions_address_set(&self, snap: i64) -> Vec<(u64, u64)>;

    /// Check if a specific address is in a known state at a snap.
    fn is_known(&self, snap: i64, address: u64) -> bool {
        self.get_state(snap, address) == TraceMemoryState::Known
    }

    /// Check if a specific address is in an unknown state at a snap.
    fn is_unknown(&self, snap: i64, address: u64) -> bool {
        self.get_state(snap, address) == TraceMemoryState::Unknown
    }
}

/// In-memory implementation of memory operations for testing.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTraceMemory {
    /// Space name.
    pub space_name: String,
    /// Stored regions.
    pub regions: Vec<TraceMemoryRegion>,
    /// Memory bytes: (snap, address) -> byte value.
    pub bytes: std::collections::BTreeMap<(i64, u64), u8>,
    /// Memory states: (snap, address) -> state.
    pub states: std::collections::BTreeMap<(i64, u64), TraceMemoryState>,
}

impl InMemoryTraceMemory {
    /// Create a new in-memory trace memory.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            regions: Vec::new(),
            bytes: std::collections::BTreeMap::new(),
            states: std::collections::BTreeMap::new(),
        }
    }
}

impl TraceMemoryOperations for InMemoryTraceMemory {
    fn space_name(&self) -> &str {
        &self.space_name
    }

    fn get_state(&self, snap: i64, address: u64) -> TraceMemoryState {
        self.states
            .get(&(snap, address))
            .copied()
            .unwrap_or(TraceMemoryState::Unknown)
    }

    fn set_state(&mut self, snap: i64, min_addr: u64, max_addr: u64, state: TraceMemoryState) {
        for addr in min_addr..=max_addr {
            self.states.insert((snap, addr), state);
        }
    }

    fn get_bytes(&self, snap: i64, address: u64, length: u32) -> Vec<u8> {
        (0..length as u64)
            .map(|i| {
                self.bytes
                    .get(&(snap, address + i))
                    .copied()
                    .unwrap_or(0)
            })
            .collect()
    }

    fn set_bytes(&mut self, snap: i64, address: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.bytes.insert((snap, address + i as u64), b);
            self.states
                .insert((snap, address + i as u64), TraceMemoryState::Known);
        }
    }

    fn get_regions(&self, _snap: i64) -> Vec<&TraceMemoryRegion> {
        self.regions.iter().collect()
    }

    fn add_region(
        &mut self,
        _path: &str,
        _lifespan: &Lifespan,
        min_addr: u64,
        max_addr: u64,
        _flags: &[super::memory_flag::TraceMemoryFlag],
    ) -> Result<&TraceMemoryRegion, TraceOverlappedRegionException> {
        self.regions
            .push(TraceMemoryRegion::new(min_addr, max_addr, TraceMemoryState::Known));
        Ok(self.regions.last().unwrap())
    }

    fn remove_region(&mut self, _path: &str) {
        // Simplified: in real impl would use path
        self.regions.pop();
    }

    fn get_region_by_path(&self, _snap: i64, _path: &str) -> Option<&TraceMemoryRegion> {
        self.regions.first()
    }

    fn get_region_containing(&self, _snap: i64, address: u64) -> Option<&TraceMemoryRegion> {
        self.regions
            .iter()
            .find(|r| address >= r.min_offset && address <= r.max_offset)
    }

    fn get_regions_address_set(&self, _snap: i64) -> Vec<(u64, u64)> {
        self.regions
            .iter()
            .map(|r| (r.min_offset, r.max_offset))
            .collect()
    }
}

/// In-memory trace memory manager that handles regions.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTraceMemoryManager {
    /// Stored regions.
    pub regions: Vec<TraceMemoryRegion>,
}

impl InMemoryTraceMemoryManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region.
    pub fn add_region(
        &mut self,
        min_offset: u64,
        max_offset: u64,
        state: TraceMemoryState,
    ) -> &TraceMemoryRegion {
        self.regions
            .push(TraceMemoryRegion::new(min_offset, max_offset, state));
        self.regions.last().unwrap()
    }

    /// Get all regions.
    pub fn get_all_regions(&self) -> &[TraceMemoryRegion] {
        &self.regions
    }

    /// Get the region containing an address.
    pub fn get_region_containing(&self, address: u64) -> Option<&TraceMemoryRegion> {
        self.regions
            .iter()
            .find(|r| address >= r.min_offset && address <= r.max_offset)
    }

    /// Get regions intersecting a range.
    pub fn get_regions_intersecting(&self, min: u64, max: u64) -> Vec<&TraceMemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.min_offset <= max && r.max_offset >= min)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_memory() {
        let mut mem = InMemoryTraceMemory::new("ram");
        assert_eq!(mem.space_name(), "ram");

        mem.set_bytes(0, 0x1000, &[0x90, 0x90, 0x90]);
        assert_eq!(mem.get_state(0, 0x1000), TraceMemoryState::Known);
        assert_eq!(mem.get_bytes(0, 0x1000, 3), vec![0x90, 0x90, 0x90]);

        assert!(mem.is_known(0, 0x1000));
        assert!(!mem.is_unknown(0, 0x1000));
    }

    #[test]
    fn test_state_operations() {
        let mut mem = InMemoryTraceMemory::new("ram");
        mem.set_state(0, 0x1000, 0x100F, TraceMemoryState::Known);
        assert!(mem.is_known(0, 0x1005));
        assert!(!mem.is_known(0, 0x2000));
    }

    #[test]
    fn test_memory_manager() {
        let mut mgr = InMemoryTraceMemoryManager::new();
        mgr.add_region(0x1000, 0x1FFF, TraceMemoryState::Known);
        mgr.add_region(0x3000, 0x3FFF, TraceMemoryState::Known);

        assert_eq!(mgr.get_all_regions().len(), 2);
        assert!(mgr.get_region_containing(0x1500).is_some());
        assert!(mgr.get_region_containing(0x2500).is_none());
    }

    #[test]
    fn test_regions_intersecting() {
        let mut mgr = InMemoryTraceMemoryManager::new();
        mgr.add_region(0x1000, 0x1FFF, TraceMemoryState::Known);
        mgr.add_region(0x3000, 0x3FFF, TraceMemoryState::Known);

        let result = mgr.get_regions_intersecting(0x1500, 0x3500);
        assert_eq!(result.len(), 2);
    }
}
