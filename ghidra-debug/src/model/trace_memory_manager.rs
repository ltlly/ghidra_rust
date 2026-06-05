//! Trace memory manager - manages memory regions and memory state.
//!
//! Ported from Ghidra's `TraceMemoryManager`, `TraceMemorySpace`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::lifespan::Lifespan;
use super::memory::TraceMemoryState;

/// A memory region with full metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryRegionFull {
    /// Unique key.
    pub key: i64,
    /// Region path (e.g. "MemoryRegions[0]").
    pub path: String,
    /// Region display name.
    pub name: String,
    /// Start address offset.
    pub min_address: u64,
    /// End address offset.
    pub max_address: u64,
    /// Address space name.
    pub space: String,
    /// Whether the region is readable.
    pub readable: bool,
    /// Whether the region is writable.
    pub writable: bool,
    /// Whether the region is executable.
    pub executable: bool,
    /// Whether the region is volatile.
    pub volatile: bool,
    /// The lifespan of this region.
    pub lifespan: Lifespan,
}

impl TraceMemoryRegionFull {
    /// Create a new memory region.
    pub fn new(
        key: i64,
        path: impl Into<String>,
        name: impl Into<String>,
        min_address: u64,
        max_address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            path: path.into(),
            name: name.into(),
            min_address,
            max_address,
            space: space.into(),
            readable: true,
            writable: true,
            executable: false,
            volatile: false,
            lifespan,
        }
    }

    /// Size in bytes.
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }

    /// Set permissions.
    pub fn with_permissions(mut self, read: bool, write: bool, exec: bool) -> Self {
        self.readable = read;
        self.writable = write;
        self.executable = exec;
        self
    }

    /// Check if region is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// A memory space holding byte data and state per snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceMemorySpace {
    /// Space name.
    pub name: String,
    /// Byte data by address.
    data: BTreeMap<u64, u8>,
    /// State tracking by address.
    state: BTreeMap<u64, TraceMemoryState>,
}

impl TraceMemorySpace {
    /// Create a new memory space.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data: BTreeMap::new(),
            state: BTreeMap::new(),
        }
    }

    /// Write a byte at the given address.
    pub fn set_byte(&mut self, addr: u64, val: u8) {
        self.data.insert(addr, val);
        self.state.insert(addr, TraceMemoryState::Known);
    }

    /// Read a byte at the given address.
    pub fn get_byte(&self, addr: u64) -> (Option<u8>, TraceMemoryState) {
        let state = self.state.get(&addr).copied().unwrap_or(TraceMemoryState::Unknown);
        (self.data.get(&addr).copied(), state)
    }

    /// Write a byte range.
    pub fn set_bytes(&mut self, addr: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.set_byte(addr + i as u64, b);
        }
    }

    /// Read a byte range.
    pub fn get_bytes(&self, addr: u64, len: usize) -> Vec<Option<u8>> {
        (0..len)
            .map(|i| self.data.get(&(addr + i as u64)).copied())
            .collect()
    }

    /// Set memory state at an address.
    pub fn set_state(&mut self, addr: u64, state: TraceMemoryState) {
        self.state.insert(addr, state);
    }

    /// Number of known bytes.
    pub fn known_byte_count(&self) -> usize {
        self.data.len()
    }
}

/// Manages memory spaces and regions for a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceMemoryManager {
    /// Memory spaces by name.
    spaces: BTreeMap<String, TraceMemorySpace>,
    /// Memory regions by key.
    regions: BTreeMap<i64, TraceMemoryRegionFull>,
    /// Next region key.
    next_key: i64,
}

impl TraceMemoryManager {
    /// Create a new memory manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a memory space.
    pub fn get_or_create_space(&mut self, name: &str) -> &mut TraceMemorySpace {
        self.spaces
            .entry(name.to_string())
            .or_insert_with(|| TraceMemorySpace::new(name))
    }

    /// Get a memory space.
    pub fn get_space(&self, name: &str) -> Option<&TraceMemorySpace> {
        self.spaces.get(name)
    }

    /// Add a memory region.
    pub fn add_region(&mut self, mut region: TraceMemoryRegionFull) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        region.key = key;
        self.regions.insert(key, region);
        key
    }

    /// Get a region by key.
    pub fn get_region(&self, key: i64) -> Option<&TraceMemoryRegionFull> {
        self.regions.get(&key)
    }

    /// Get all regions valid at a snap.
    pub fn regions_at_snap(&self, snap: i64) -> Vec<&TraceMemoryRegionFull> {
        self.regions
            .values()
            .filter(|r| r.is_valid_at(snap))
            .collect()
    }

    /// Number of spaces.
    pub fn space_count(&self) -> usize {
        self.spaces.len()
    }

    /// Number of regions.
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_space_rw() {
        let mut space = TraceMemorySpace::new("ram");
        space.set_byte(0x100, 0x42);
        let (val, state) = space.get_byte(0x100);
        assert_eq!(val, Some(0x42));
        assert_eq!(state, TraceMemoryState::Known);
    }

    #[test]
    fn test_memory_space_bytes() {
        let mut space = TraceMemorySpace::new("ram");
        space.set_bytes(0x100, &[1, 2, 3, 4]);
        let bytes = space.get_bytes(0x100, 4);
        assert_eq!(bytes, vec![Some(1), Some(2), Some(3), Some(4)]);
    }

    #[test]
    fn test_memory_manager_regions() {
        let mut mgr = TraceMemoryManager::new();
        let r = TraceMemoryRegionFull::new(
            0, "Regions[0]", ".text", 0x400000, 0x400fff, "ram", Lifespan::span(0, 10),
        )
        .with_permissions(true, false, true);
        let _key = mgr.add_region(r);
        assert_eq!(mgr.regions_at_snap(5).len(), 1);
        assert_eq!(mgr.regions_at_snap(15).len(), 0);
    }
}
