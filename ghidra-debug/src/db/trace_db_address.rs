//! Address space manager for trace databases.
//!
//! Ported from Ghidra's `ghidra.trace.database.address` package in
//! Framework-TraceModeling. Manages the mapping of address spaces to
//! their trace-specific representations, including variable-length
//! address space support and address space overlay management.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Trace address space
// ---------------------------------------------------------------------------

/// An address space in a trace database.
///
/// Ported from Ghidra's `AbstractDBTraceSpace` and related classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAddressSpace {
    /// The unique space ID (assigned by the trace database).
    pub space_id: u32,
    /// The name of the address space (e.g., "ram", "register", "unique").
    pub name: String,
    /// The size of the address space in bytes (addressable range).
    pub size: u64,
    /// Whether this is a register space.
    pub is_register_space: bool,
    /// Whether this is the unique (temporary) space.
    pub is_unique_space: bool,
    /// Whether this space is an overlay.
    pub is_overlay: bool,
    /// The language address space ID (from Ghidra's language).
    pub language_space_id: Option<String>,
    /// The word size (bytes per addressable unit).
    pub word_size: u32,
}

impl TraceAddressSpace {
    /// Create a new address space.
    pub fn new(space_id: u32, name: impl Into<String>, size: u64) -> Self {
        Self {
            space_id,
            name: name.into(),
            size,
            is_register_space: false,
            is_unique_space: false,
            is_overlay: false,
            language_space_id: None,
            word_size: 1,
        }
    }

    /// Create a register space.
    pub fn register(space_id: u32, name: impl Into<String>, size: u64) -> Self {
        let mut space = Self::new(space_id, name, size);
        space.is_register_space = true;
        space
    }

    /// Create an overlay space.
    pub fn overlay(space_id: u32, name: impl Into<String>, base_name: impl Into<String>, size: u64) -> Self {
        let mut space = Self::new(space_id, name, size);
        space.is_overlay = true;
        space.language_space_id = Some(base_name.into());
        space
    }

    /// Check if an offset is within the space's range.
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset < self.size
    }

    /// Get the maximum valid offset.
    pub fn max_offset(&self) -> u64 {
        self.size.saturating_sub(1)
    }
}

// ---------------------------------------------------------------------------
// Address space manager
// ---------------------------------------------------------------------------

/// Manages address spaces for a trace database.
///
/// Ported from Ghidra's `AbstractDBTraceSpaceBased` and the space
/// management in `DBTrace`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSpaceManager {
    /// All registered address spaces.
    spaces: HashMap<String, TraceAddressSpace>,
    /// Space ID to name mapping.
    id_to_name: HashMap<u32, String>,
    /// The next available space ID.
    next_space_id: u32,
}

impl AddressSpaceManager {
    /// Create a new address space manager.
    pub fn new() -> Self {
        Self {
            spaces: HashMap::new(),
            id_to_name: HashMap::new(),
            next_space_id: 0,
        }
    }

    /// Register a new address space.
    pub fn add_space(&mut self, mut space: TraceAddressSpace) -> u32 {
        let id = if space.space_id == 0 {
            let id = self.next_space_id;
            self.next_space_id += 1;
            space.space_id = id;
            id
        } else {
            if space.space_id >= self.next_space_id {
                self.next_space_id = space.space_id + 1;
            }
            space.space_id
        };
        let name = space.name.clone();
        self.id_to_name.insert(id, name.clone());
        self.spaces.insert(name, space);
        id
    }

    /// Get a space by name.
    pub fn get_space(&self, name: &str) -> Option<&TraceAddressSpace> {
        self.spaces.get(name)
    }

    /// Get a space by ID.
    pub fn get_space_by_id(&self, id: u32) -> Option<&TraceAddressSpace> {
        self.id_to_name
            .get(&id)
            .and_then(|name| self.spaces.get(name))
    }

    /// Get all spaces.
    pub fn all_spaces(&self) -> Vec<&TraceAddressSpace> {
        self.spaces.values().collect()
    }

    /// Get the register space (if any).
    pub fn register_space(&self) -> Option<&TraceAddressSpace> {
        self.spaces.values().find(|s| s.is_register_space)
    }

    /// Get the number of registered spaces.
    pub fn space_count(&self) -> usize {
        self.spaces.len()
    }

    /// Check if a space exists.
    pub fn has_space(&self, name: &str) -> bool {
        self.spaces.contains_key(name)
    }
}

// ---------------------------------------------------------------------------
// Address space type hints
// ---------------------------------------------------------------------------

/// The type of an address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressSpaceType {
    /// Physical memory (RAM).
    Physical,
    /// Register space.
    Register,
    /// Unique (temporary) space.
    Unique,
    /// Stack space.
    Stack,
    /// Join space (composite).
    Join,
    /// Overlay space.
    Overlay,
}

// ---------------------------------------------------------------------------
// Overlay space info
// ---------------------------------------------------------------------------

/// Information about an overlay address space.
///
/// Ported from Ghidra's overlay space handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlaySpaceInfo {
    /// The overlay space name.
    pub overlay_name: String,
    /// The base space name.
    pub base_name: String,
    /// The overlay's start address in the base space.
    pub overlay_start: u64,
    /// The overlay's size.
    pub overlay_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_address_space() {
        let space = TraceAddressSpace::new(0, "ram", 0x1_0000_0000);
        assert_eq!(space.name, "ram");
        assert_eq!(space.size, 0x1_0000_0000);
        assert!(!space.is_register_space);
        assert!(!space.is_overlay);
        assert!(space.contains_offset(0x400000));
        assert!(!space.contains_offset(0x2_0000_0000));
    }

    #[test]
    fn test_register_space() {
        let space = TraceAddressSpace::register(1, "register", 0x1000);
        assert!(space.is_register_space);
        assert_eq!(space.max_offset(), 0xFFF);
    }

    #[test]
    fn test_overlay_space() {
        let space = TraceAddressSpace::overlay(2, "MY_OVERLAY", "ram", 0x10000);
        assert!(space.is_overlay);
        assert_eq!(space.language_space_id.as_deref(), Some("ram"));
    }

    #[test]
    fn test_address_space_manager() {
        let mut mgr = AddressSpaceManager::new();
        assert_eq!(mgr.space_count(), 0);

        let ram = TraceAddressSpace::new(0, "ram", 0x1_0000_0000);
        let reg = TraceAddressSpace::register(1, "register", 0x1000);
        let unique = TraceAddressSpace::new(2, "unique", 0x10000);

        mgr.add_space(ram);
        mgr.add_space(reg);
        mgr.add_space(unique);

        assert_eq!(mgr.space_count(), 3);
        assert!(mgr.has_space("ram"));
        assert!(!mgr.has_space("nonexistent"));
    }

    #[test]
    fn test_space_lookup() {
        let mut mgr = AddressSpaceManager::new();
        let ram = TraceAddressSpace::new(5, "ram", 0x1_0000_0000);
        mgr.add_space(ram);

        let space = mgr.get_space("ram").unwrap();
        assert_eq!(space.space_id, 5);

        let space = mgr.get_space_by_id(5).unwrap();
        assert_eq!(space.name, "ram");

        assert!(mgr.get_space_by_id(99).is_none());
    }

    #[test]
    fn test_register_space_lookup() {
        let mut mgr = AddressSpaceManager::new();
        mgr.add_space(TraceAddressSpace::new(0, "ram", 0x1_0000_0000));
        mgr.add_space(TraceAddressSpace::register(1, "register", 0x1000));

        let reg = mgr.register_space().unwrap();
        assert_eq!(reg.name, "register");
    }

    #[test]
    fn test_auto_space_id() {
        let mut mgr = AddressSpaceManager::new();
        let space1 = TraceAddressSpace::new(0, "a", 100);
        let id1 = mgr.add_space(space1);
        let space2 = TraceAddressSpace::new(0, "b", 200);
        let id2 = mgr.add_space(space2);
        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
    }

    #[test]
    fn test_address_space_type() {
        let space = TraceAddressSpace::new(0, "ram", 100);
        assert!(!space.is_register_space);
        assert!(!space.is_unique_space);
        assert!(!space.is_overlay);
    }
}
