//! DBTraceMemoryManager and related memory storage implementations.
//!
//! Ported from `ghidra/trace/database/memory/` package. Provides:
//! - `DBTraceMemoryManager`: manages memory regions, blocks, and register state
//! - `DBTraceMemorySpace`: a memory space backed by byte arrays
//! - `DBTraceMemoryRegion`: a named region within a memory space
//! - `DBTraceObjectMemory`: target object memory facade
//! - `DBTraceObjectRegister`: register state storage

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::model::Lifespan;

// ============================================================================
// Error Types
// ============================================================================

/// Errors from memory operations.
#[derive(Debug, Error)]
pub enum MemoryError {
    /// Overlapping memory regions.
    #[error("Overlapping region: {existing} overlaps with {new_region}")]
    OverlappingRegion {
        /// Existing region description.
        existing: String,
        /// New region description.
        new_region: String,
    },
    /// Region not found.
    #[error("Region not found at {space}:{offset:#x}")]
    RegionNotFound {
        /// Space name.
        space: String,
        /// Address offset.
        offset: u64,
    },
    /// Address out of bounds.
    #[error("Address {offset:#x} out of bounds [{min:#x}..{max:#x}]")]
    OutOfBounds {
        /// Requested offset.
        offset: u64,
        /// Range minimum.
        min: u64,
        /// Range maximum.
        max: u64,
    },
    /// Space not found.
    #[error("Space not found: {0}")]
    SpaceNotFound(String),
    /// A generic memory error.
    #[error("Memory error: {0}")]
    Other(String),
}

/// Result type for memory operations.
pub type MemoryResult<T> = Result<T, MemoryError>;

// ============================================================================
// Memory State
// ============================================================================

/// The state of a memory byte (known, unknown, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryState {
    /// Byte value is known.
    Known,
    /// Byte value is unknown.
    Unknown,
}

impl Default for MemoryState {
    fn default() -> Self {
        MemoryState::Unknown
    }
}

// ============================================================================
// Memory Region
// ============================================================================

/// A memory region defining a range of addresses in a space.
///
/// Ported from `DBTraceMemoryRegion.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Unique region ID.
    pub id: u64,
    /// Region name.
    pub name: String,
    /// The address space name.
    pub space_name: String,
    /// Start offset.
    pub offset_min: u64,
    /// End offset.
    pub offset_max: u64,
    /// Minimum snap (inclusive).
    pub snap_min: i64,
    /// Maximum snap (inclusive).
    pub snap_max: i64,
    /// Whether the region is readable.
    pub readable: bool,
    /// Whether the region is writable.
    pub writable: bool,
    /// Whether the region is executable.
    pub executable: bool,
    /// Whether the region is volatile.
    pub volatile: bool,
}

impl MemoryRegion {
    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.snap_min, self.snap_max)
    }

    /// Whether the region contains the given offset.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.offset_min && offset <= self.offset_max
    }

    /// Get the size of the region in bytes.
    pub fn size(&self) -> u64 {
        self.offset_max - self.offset_min + 1
    }
}

// ============================================================================
// Memory Block Entry
// ============================================================================

/// A memory block entry storing actual bytes.
///
/// Ported from `DBTraceMemoryBlockEntry.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBlockEntry {
    /// Block ID.
    pub id: u64,
    /// Start offset.
    pub offset: u64,
    /// Length of the block.
    pub length: u32,
    /// The byte data.
    pub data: Vec<u8>,
    /// The snap at which this block was written.
    pub snap: i64,
}

// ============================================================================
// Memory Buffer Entry
// ============================================================================

/// A memory buffer entry for reading.
///
/// Ported from `DBTraceMemoryBufferEntry.java`.
#[derive(Debug, Clone)]
pub struct MemoryBufferEntry<'a> {
    /// Start offset of this buffer.
    pub offset: u64,
    /// The bytes.
    pub data: &'a [u8],
}

// ============================================================================
// Memory State Entry
// ============================================================================

/// State tracking for individual bytes.
///
/// Ported from `DBTraceMemoryStateEntry.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStateEntry {
    /// Start offset.
    pub offset_min: u64,
    /// End offset.
    pub offset_max: u64,
    /// The state of the bytes.
    pub state: MemoryState,
    /// Snap at which the state applies.
    pub snap: i64,
}

// ============================================================================
// DBTraceMemorySpace
// ============================================================================

/// A memory space storing byte data for a specific address space.
///
/// Ported from `DBTraceMemorySpace.java`.
#[derive(Debug)]
pub struct DbTraceMemorySpace {
    /// The space name.
    pub space_name: String,
    /// Byte data keyed by (snap, offset).
    blocks: BTreeMap<(i64, u64), Vec<u8>>,
    /// Memory state entries keyed by (snap, offset).
    state_entries: BTreeMap<(i64, u64), MemoryState>,
}

impl DbTraceMemorySpace {
    /// Create a new memory space.
    pub fn new(space_name: String) -> Self {
        Self {
            space_name,
            blocks: BTreeMap::new(),
            state_entries: BTreeMap::new(),
        }
    }

    /// Write bytes at a given snap and offset.
    pub fn write_bytes(&mut self, snap: i64, offset: u64, data: &[u8]) {
        self.blocks.insert((snap, offset), data.to_vec());
        // Mark as known
        for i in 0..data.len() {
            self.state_entries
                .insert((snap, offset + i as u64), MemoryState::Known);
        }
    }

    /// Read bytes at a given snap and offset.
    pub fn read_bytes(&self, snap: i64, offset: u64, length: usize) -> Option<Vec<u8>> {
        // Find the latest block at or before the given snap that covers this offset
        self.blocks
            .range(..=(snap, offset + length as u64))
            .rev()
            .find(|&((s, o), data)| {
                *s <= snap && *o <= offset && *o + data.len() as u64 > offset
            })
            .map(|((_, o), data)| {
                let start = (offset - o) as usize;
                let end = (start + length).min(data.len());
                data[start..end].to_vec()
            })
    }

    /// Get the memory state at a given snap and offset.
    pub fn state_at(&self, snap: i64, offset: u64) -> MemoryState {
        self.state_entries
            .range(..=(snap, offset))
            .next_back()
            .filter(|&((s, _), _)| *s <= snap)
            .map(|(_, state)| *state)
            .unwrap_or(MemoryState::Unknown)
    }

    /// Set the state of a range.
    pub fn set_state(&mut self, snap: i64, offset_min: u64, offset_max: u64, state: MemoryState) {
        for offset in offset_min..=offset_max {
            self.state_entries.insert((snap, offset), state);
        }
    }

    /// Get all block entries at a snap.
    pub fn blocks_at_snap(&self, snap: i64) -> Vec<(&u64, &Vec<u8>)> {
        self.blocks
            .range((snap, 0)..=(snap, u64::MAX))
            .map(|((_, offset), data)| (offset, data))
            .collect()
    }

    /// Clear all data at a snap.
    pub fn clear_snap(&mut self, snap: i64) {
        let keys: Vec<_> = self
            .blocks
            .keys()
            .filter(|(s, _)| *s == snap)
            .copied()
            .collect();
        for key in keys {
            self.blocks.remove(&key);
        }
    }

    /// Number of stored blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

// ============================================================================
// DBTraceObjectMemory
// ============================================================================

/// Object-level memory facade for a specific target object.
///
/// Ported from `DBTraceObjectMemory.java`.
#[derive(Debug)]
pub struct DbTraceObjectMemory {
    /// Object key path.
    pub key_path: String,
    /// The underlying space.
    pub space_name: String,
    /// Mapped regions.
    pub regions: Vec<MemoryRegion>,
}

impl DbTraceObjectMemory {
    /// Create a new object memory.
    pub fn new(key_path: String, space_name: String) -> Self {
        Self {
            key_path,
            space_name,
            regions: Vec::new(),
        }
    }

    /// Add a region.
    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Get regions active at a given snap.
    pub fn regions_at_snap(&self, snap: i64) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.snap_min <= snap && r.snap_max >= snap)
            .collect()
    }
}

// ============================================================================
// DBTraceObjectRegister
// ============================================================================

/// Register state storage for a specific target object.
///
/// Ported from `DBTraceObjectRegister.java`.
#[derive(Debug)]
pub struct DbTraceObjectRegister {
    /// Register name.
    pub name: String,
    /// Register value bytes.
    pub value: Option<Vec<u8>>,
    /// Snap at which the value was set.
    pub snap: i64,
}

impl DbTraceObjectRegister {
    /// Create a new register state.
    pub fn new(name: String) -> Self {
        Self {
            name,
            value: None,
            snap: 0,
        }
    }

    /// Set the register value.
    pub fn set_value(&mut self, snap: i64, value: Vec<u8>) {
        self.value = Some(value);
        self.snap = snap;
    }

    /// Get the register value.
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    /// Whether this register has a known value.
    pub fn has_value(&self) -> bool {
        self.value.is_some()
    }
}

// ============================================================================
// DBTraceObjectRegisterContainer
// ============================================================================

/// Container for register state of a target object.
///
/// Ported from `DBTraceObjectRegisterContainer.java`.
#[derive(Debug)]
pub struct DbTraceObjectRegisterContainer {
    /// Object key path.
    pub key_path: String,
    /// Register name to register mapping.
    registers: BTreeMap<String, DbTraceObjectRegister>,
}

impl DbTraceObjectRegisterContainer {
    /// Create a new register container.
    pub fn new(key_path: String) -> Self {
        Self {
            key_path,
            registers: BTreeMap::new(),
        }
    }

    /// Get or create a register.
    pub fn get_or_create(&mut self, name: &str) -> &mut DbTraceObjectRegister {
        self.registers
            .entry(name.to_string())
            .or_insert_with(|| DbTraceObjectRegister::new(name.to_string()))
    }

    /// Get a register.
    pub fn get(&self, name: &str) -> Option<&DbTraceObjectRegister> {
        self.registers.get(name)
    }

    /// Get all register names.
    pub fn register_names(&self) -> Vec<&str> {
        self.registers.keys().map(|s| s.as_str()).collect()
    }

    /// Number of registers.
    pub fn len(&self) -> usize {
        self.registers.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }
}

// ============================================================================
// InternalTraceMemoryOperations
// ============================================================================

/// Internal memory operations trait for trace database.
///
/// Ported from `InternalTraceMemoryOperations.java`.
pub trait InternalTraceMemoryOperations {
    /// Write bytes to memory.
    fn write_memory(&mut self, space: &str, snap: i64, offset: u64, data: &[u8]) -> MemoryResult<()>;

    /// Read bytes from memory.
    fn read_memory(&self, space: &str, snap: i64, offset: u64, length: usize) -> MemoryResult<Vec<u8>>;

    /// Get the memory state at a point.
    fn memory_state(&self, space: &str, snap: i64, offset: u64) -> MemoryResult<MemoryState>;

    /// Add a memory region.
    fn add_region(&mut self, region: MemoryRegion) -> MemoryResult<u64>;

    /// Remove a memory region.
    fn remove_region(&mut self, id: u64) -> MemoryResult<()>;

    /// Get regions at a snap.
    fn regions_at_snap(&self, space: &str, snap: i64) -> Vec<&MemoryRegion>;
}

// ============================================================================
// DBTraceMemoryManager
// ============================================================================

/// Top-level memory manager for a trace database.
///
/// Ported from `DBTraceMemoryManager.java`.
#[derive(Debug)]
pub struct DbTraceMemoryManager {
    /// Per-space memory storage.
    spaces: BTreeMap<String, DbTraceMemorySpace>,
    /// All regions across all spaces.
    regions: BTreeMap<u64, MemoryRegion>,
    /// Next region ID.
    next_region_id: u64,
    /// Register containers keyed by object key path.
    register_containers: BTreeMap<String, DbTraceObjectRegisterContainer>,
}

impl DbTraceMemoryManager {
    /// Create a new memory manager.
    pub fn new() -> Self {
        Self {
            spaces: BTreeMap::new(),
            regions: BTreeMap::new(),
            next_region_id: 1,
            register_containers: BTreeMap::new(),
        }
    }

    /// Get or create a memory space.
    pub fn get_or_create_space(&mut self, space_name: &str) -> &mut DbTraceMemorySpace {
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(|| DbTraceMemorySpace::new(space_name.to_string()))
    }

    /// Write bytes.
    pub fn write_bytes(
        &mut self,
        space_name: &str,
        snap: i64,
        offset: u64,
        data: &[u8],
    ) {
        let space = self.get_or_create_space(space_name);
        space.write_bytes(snap, offset, data);
    }

    /// Read bytes.
    pub fn read_bytes(
        &self,
        space_name: &str,
        snap: i64,
        offset: u64,
        length: usize,
    ) -> Option<Vec<u8>> {
        self.spaces
            .get(space_name)
            .and_then(|s| s.read_bytes(snap, offset, length))
    }

    /// Add a memory region.
    pub fn add_region(&mut self, mut region: MemoryRegion) -> u64 {
        let id = self.next_region_id;
        self.next_region_id += 1;
        region.id = id;
        self.regions.insert(id, region);
        id
    }

    /// Remove a memory region.
    pub fn remove_region(&mut self, id: u64) -> Option<MemoryRegion> {
        self.regions.remove(&id)
    }

    /// Get a region by ID.
    pub fn get_region(&self, id: u64) -> Option<&MemoryRegion> {
        self.regions.get(&id)
    }

    /// Get regions at a snap for a space.
    pub fn regions_at_snap(&self, space_name: &str, snap: i64) -> Vec<&MemoryRegion> {
        self.regions
            .values()
            .filter(|r| r.space_name == space_name && r.snap_min <= snap && r.snap_max >= snap)
            .collect()
    }

    /// Get all regions.
    pub fn all_regions(&self) -> Vec<&MemoryRegion> {
        self.regions.values().collect()
    }

    /// Get or create a register container.
    pub fn get_or_create_register_container(
        &mut self,
        key_path: &str,
    ) -> &mut DbTraceObjectRegisterContainer {
        self.register_containers
            .entry(key_path.to_string())
            .or_insert_with(|| DbTraceObjectRegisterContainer::new(key_path.to_string()))
    }

    /// Set a register value.
    pub fn set_register(
        &mut self,
        key_path: &str,
        name: &str,
        snap: i64,
        value: Vec<u8>,
    ) {
        let container = self.get_or_create_register_container(key_path);
        let reg = container.get_or_create(name);
        reg.set_value(snap, value);
    }

    /// Get a register value.
    pub fn get_register(&self, key_path: &str, name: &str) -> Option<&[u8]> {
        self.register_containers
            .get(key_path)
            .and_then(|c| c.get(name))
            .and_then(|r| r.value())
    }

    /// Number of memory spaces.
    pub fn space_count(&self) -> usize {
        self.spaces.len()
    }

    /// Total number of regions.
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
}

impl Default for DbTraceMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InternalTraceMemoryOperations for DbTraceMemoryManager {
    fn write_memory(&mut self, space: &str, snap: i64, offset: u64, data: &[u8]) -> MemoryResult<()> {
        self.write_bytes(space, snap, offset, data);
        Ok(())
    }

    fn read_memory(&self, space: &str, snap: i64, offset: u64, length: usize) -> MemoryResult<Vec<u8>> {
        self.read_bytes(space, snap, offset, length)
            .ok_or_else(|| MemoryError::SpaceNotFound(space.to_string()))
    }

    fn memory_state(&self, space: &str, snap: i64, offset: u64) -> MemoryResult<MemoryState> {
        self.spaces
            .get(space)
            .map(|s| s.state_at(snap, offset))
            .ok_or_else(|| MemoryError::SpaceNotFound(space.to_string()))
    }

    fn add_region(&mut self, region: MemoryRegion) -> MemoryResult<u64> {
        Ok(self.add_region(region))
    }

    fn remove_region(&mut self, id: u64) -> MemoryResult<()> {
        self.regions.remove(&id);
        Ok(())
    }

    fn regions_at_snap(&self, space: &str, snap: i64) -> Vec<&MemoryRegion> {
        self.regions_at_snap(space, snap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_space_write_read() {
        let mut space = DbTraceMemorySpace::new("ram".into());
        space.write_bytes(0, 0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]);

        let data = space.read_bytes(0, 0x1000, 4).unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_memory_space_state() {
        let mut space = DbTraceMemorySpace::new("ram".into());
        assert_eq!(space.state_at(0, 0x1000), MemoryState::Unknown);

        space.write_bytes(0, 0x1000, &[0x42]);
        assert_eq!(space.state_at(0, 0x1000), MemoryState::Known);
    }

    #[test]
    fn test_memory_manager_write_read() {
        let mut mgr = DbTraceMemoryManager::new();
        mgr.write_bytes("ram", 0, 0x400000, &[0x55]);
        let data = mgr.read_bytes("ram", 0, 0x400000, 1).unwrap();
        assert_eq!(data, vec![0x55]);
    }

    #[test]
    fn test_memory_region() {
        let mut mgr = DbTraceMemoryManager::new();
        let region = MemoryRegion {
            id: 0,
            name: ".text".into(),
            space_name: "ram".into(),
            offset_min: 0x400000,
            offset_max: 0x401000,
            snap_min: 0,
            snap_max: 100,
            readable: true,
            writable: false,
            executable: true,
            volatile: false,
        };
        let id = mgr.add_region(region);
        let r = mgr.get_region(id).unwrap();
        assert_eq!(r.name, ".text");
        assert!(r.contains(0x400500));
        assert!(!r.contains(0x300000));
    }

    #[test]
    fn test_memory_region_snap_filtering() {
        let mut mgr = DbTraceMemoryManager::new();
        mgr.add_region(MemoryRegion {
            id: 0,
            name: ".text".into(),
            space_name: "ram".into(),
            offset_min: 0x400000,
            offset_max: 0x401000,
            snap_min: 0,
            snap_max: 50,
            readable: true,
            writable: false,
            executable: true,
            volatile: false,
        });

        let regions = mgr.regions_at_snap("ram", 30);
        assert_eq!(regions.len(), 1);

        let regions = mgr.regions_at_snap("ram", 60);
        assert_eq!(regions.len(), 0);
    }

    #[test]
    fn test_register_container() {
        let mut mgr = DbTraceMemoryManager::new();
        mgr.set_register("thread:1", "RAX", 0, vec![0x42; 8]);
        let val = mgr.get_register("thread:1", "RAX").unwrap();
        assert_eq!(val, &[0x42; 8]);
    }

    #[test]
    fn test_object_register() {
        let mut reg = DbTraceObjectRegister::new("RIP".into());
        assert!(!reg.has_value());
        reg.set_value(0, vec![0x00, 0x40, 0x00, 0x00]);
        assert!(reg.has_value());
        assert_eq!(reg.value(), Some(&[0x00, 0x40, 0x00, 0x00][..]));
    }

    #[test]
    fn test_internal_trait() {
        let mut mgr = DbTraceMemoryManager::new();
        InternalTraceMemoryOperations::write_memory(&mut mgr, "ram", 0, 0x100, &[0xAA]).unwrap();
        let data = InternalTraceMemoryOperations::read_memory(&mgr, "ram", 0, 0x100, 1).unwrap();
        assert_eq!(data, vec![0xAA]);
    }
}
