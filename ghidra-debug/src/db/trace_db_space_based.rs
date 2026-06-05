//! Space-based manager abstraction for database-backed trace managers.
//!
//! Ported from Ghidra's `ghidra.trace.database.space` package:
//! - `AbstractDBTraceSpaceBasedManager`: base class for per-address-space managers
//! - `DBTraceSpaceBased`: trait for objects associated with an address space
//! - `DBTraceDelegatingManager`: delegating pattern for dispatching operations
//!   to the correct per-space manager
//!
//! In Ghidra, several managers (listing, memory, bookmarks, equates, references,
//! property maps, register context, stacks) are "space-based": they maintain a
//! separate sub-manager per address space. This module provides the common
//! infrastructure for that pattern.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// Address space representation (simplified for trace-internal use)
// ---------------------------------------------------------------------------

/// A simplified address space identifier used internally by the trace database.
///
/// In Ghidra this corresponds to `ghidra.program.model.address.AddressSpace`.
/// The full Ghidra address space model is complex (overlay, register, external,
/// etc.); for the database layer we only need a name and type discriminator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TraceDbAddressSpace {
    /// The unique name of the address space (e.g. "ram", "register", "DATA:BE:64").
    pub name: String,
    /// Whether this is a register space.
    pub is_register_space: bool,
    /// Whether this is an overlay space.
    pub is_overlay_space: bool,
    /// Size of addresses in this space (in bytes).
    pub address_size: u32,
}

impl TraceDbAddressSpace {
    /// Create a new address space descriptor.
    pub fn new(name: impl Into<String>, address_size: u32) -> Self {
        Self {
            name: name.into(),
            is_register_space: false,
            is_overlay_space: false,
            address_size,
        }
    }

    /// Create a register space descriptor.
    pub fn register(name: impl Into<String>, address_size: u32) -> Self {
        Self {
            name: name.into(),
            is_register_space: true,
            is_overlay_space: false,
            address_size,
        }
    }

    /// Create an overlay space descriptor.
    pub fn overlay(name: impl Into<String>, base_name: impl Into<String>, address_size: u32) -> Self {
        let _ = base_name; // stored for reference; simplified here
        Self {
            name: name.into(),
            is_register_space: false,
            is_overlay_space: true,
            address_size,
        }
    }
}

// ---------------------------------------------------------------------------
// DBTraceSpaceBased
// ---------------------------------------------------------------------------

/// Trait for database objects associated with a particular address space.
///
/// Ported from `ghidra.trace.database.space.DBTraceSpaceBased`.
/// Provides convenience methods for asserting addresses belong to the
/// expected space.
pub trait DbTraceSpaceBased {
    /// Get the address space this object is associated with.
    fn address_space(&self) -> &TraceDbAddressSpace;

    /// Check whether the given space matches this object's space.
    fn is_my_space(&self, space: &TraceDbAddressSpace) -> bool {
        self.address_space().name == space.name
    }

    /// Assert that an offset belongs to this space; return the offset.
    fn assert_in_space(&self, space: &TraceDbAddressSpace, offset: u64) -> Result<u64, String> {
        if !self.is_my_space(space) {
            return Err(format!(
                "Address space '{}' is not this space '{}'",
                space.name,
                self.address_space().name
            ));
        }
        Ok(offset)
    }
}

// ---------------------------------------------------------------------------
// DBTraceSpaceEntry
// ---------------------------------------------------------------------------

/// An entry in the space store mapping space names to space-based managers.
///
/// Ported from `AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceSpaceEntry {
    /// Row/key in the space store.
    pub key: i64,
    /// The name of the address space.
    pub space_name: String,
    /// Thread key for register spaces (or -1 for non-register spaces).
    pub thread_key: i64,
    /// Frame level for register spaces (or -1 for non-register spaces).
    pub frame_level: i32,
}

impl DbTraceSpaceEntry {
    /// Create a new space entry.
    pub fn new(key: i64, space_name: impl Into<String>) -> Self {
        Self {
            key,
            space_name: space_name.into(),
            thread_key: -1,
            frame_level: -1,
        }
    }

    /// Create a register space entry bound to a thread and frame.
    pub fn register(key: i64, space_name: impl Into<String>, thread_key: i64, frame_level: i32) -> Self {
        Self {
            key,
            space_name: space_name.into(),
            thread_key,
            frame_level,
        }
    }
}

// ---------------------------------------------------------------------------
// AbstractDBTraceSpaceBasedManager
// ---------------------------------------------------------------------------

/// Base manager that maintains a set of per-address-space sub-managers.
///
/// Ported from `ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager`.
///
/// Many trace managers (listing, memory, bookmarks, equates, references,
/// property maps, register context) delegate to per-space sub-managers. This
/// provides the common pattern for looking up and creating sub-managers.
#[derive(Debug)]
pub struct SpaceBasedManager<S> {
    /// The name of this manager (for diagnostics).
    pub name: String,
    /// Space entries in insertion order.
    pub space_entries: Vec<DbTraceSpaceEntry>,
    /// Map from space name to sub-manager.
    pub spaces: BTreeMap<String, S>,
    /// Next key for space entry allocation.
    pub next_space_key: i64,
}

impl<S> SpaceBasedManager<S> {
    /// Create a new space-based manager.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            space_entries: Vec::new(),
            spaces: BTreeMap::new(),
            next_space_key: 1,
        }
    }

    /// Get the sub-manager for the given space name, if it exists.
    pub fn get_for_space(&self, space_name: &str) -> Option<&S> {
        self.spaces.get(space_name)
    }

    /// Get or create the sub-manager for the given space name.
    pub fn get_or_create_space<F>(&mut self, space_name: &str, factory: F) -> &mut S
    where
        F: FnOnce(&DbTraceSpaceEntry) -> S,
    {
        if !self.spaces.contains_key(space_name) {
            let entry = DbTraceSpaceEntry::new(self.next_space_key, space_name);
            self.next_space_key += 1;
            let sub_manager = factory(&entry);
            self.space_entries.push(entry);
            self.spaces.insert(space_name.to_string(), sub_manager);
        }
        self.spaces.get_mut(space_name).unwrap()
    }

    /// Get all space names.
    pub fn space_names(&self) -> Vec<&str> {
        self.spaces.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of address spaces.
    pub fn space_count(&self) -> usize {
        self.spaces.len()
    }

    /// Iterate over all sub-managers.
    pub fn iter_spaces(&self) -> impl Iterator<Item = (&String, &S)> {
        self.spaces.iter()
    }

    /// Mutably iterate over all sub-managers.
    pub fn iter_spaces_mut(&mut self) -> impl Iterator<Item = (&String, &mut S)> {
        self.spaces.iter_mut()
    }
}

// ---------------------------------------------------------------------------
// DBTraceDelegatingManager
// ---------------------------------------------------------------------------

/// Trait for managers that delegate operations to per-space sub-managers.
///
/// Ported from `ghidra.trace.database.space.DBTraceDelegatingManager`.
///
/// This provides a dispatching pattern where a high-level manager looks up the
/// correct sub-manager for an address space and forwards the operation.
pub trait DelegatingManager<M> {
    /// Get the sub-manager for the given space name.
    fn get_for_space(&self, space_name: &str) -> Option<&M>;

    /// Get or create the sub-manager for the given space name.
    fn get_for_space_or_create(&mut self, space_name: &str) -> &mut M;

    /// Delegate a read-only operation to the correct sub-manager.
    fn delegate_read<T, F>(&self, space_name: &str, f: F) -> Result<T, String>
    where
        F: FnOnce(&M) -> T,
    {
        let m = self.get_for_space(space_name)
            .ok_or_else(|| format!("No sub-manager for space '{}'", space_name))?;
        Ok(f(m))
    }

    /// Delegate a mutating operation to the correct sub-manager.
    fn delegate_write<T, F>(&mut self, space_name: &str, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut M) -> T,
    {
        let m = self.get_for_space_or_create(space_name);
        Ok(f(m))
    }
}

// ---------------------------------------------------------------------------
// Register container binding
// ---------------------------------------------------------------------------

/// Describes a register container object's binding to a register address space.
///
/// In Ghidra, register spaces are created per-thread (and optionally per-frame).
/// This tracks the association.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterContainerBinding {
    /// The object path of the register container.
    pub container_path: Vec<String>,
    /// The thread key (if applicable).
    pub thread_key: i64,
    /// The frame level (if applicable).
    pub frame_level: i32,
    /// The register address space name.
    pub register_space_name: String,
}

impl RegisterContainerBinding {
    /// Create a new binding.
    pub fn new(
        container_path: Vec<String>,
        thread_key: i64,
        frame_level: i32,
        register_space_name: impl Into<String>,
    ) -> Self {
        Self {
            container_path,
            thread_key,
            frame_level,
            register_space_name: register_space_name.into(),
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
    fn test_address_space_new() {
        let space = TraceDbAddressSpace::new("ram", 8);
        assert_eq!(space.name, "ram");
        assert_eq!(space.address_size, 8);
        assert!(!space.is_register_space);
        assert!(!space.is_overlay_space);
    }

    #[test]
    fn test_address_space_register() {
        let space = TraceDbAddressSpace::register("register", 4);
        assert!(space.is_register_space);
        assert_eq!(space.address_size, 4);
    }

    #[test]
    fn test_address_space_overlay() {
        let space = TraceDbAddressSpace::overlay("my_overlay", "ram", 8);
        assert!(space.is_overlay_space);
        assert_eq!(space.name, "my_overlay");
    }

    #[test]
    fn test_address_space_ordering() {
        let a = TraceDbAddressSpace::new("a", 4);
        let b = TraceDbAddressSpace::new("b", 4);
        assert!(a < b);
    }

    struct TestSpaceBased {
        space: TraceDbAddressSpace,
    }

    impl DbTraceSpaceBased for TestSpaceBased {
        fn address_space(&self) -> &TraceDbAddressSpace {
            &self.space
        }
    }

    #[test]
    fn test_is_my_space() {
        let obj = TestSpaceBased {
            space: TraceDbAddressSpace::new("ram", 8),
        };
        assert!(obj.is_my_space(&TraceDbAddressSpace::new("ram", 8)));
        assert!(!obj.is_my_space(&TraceDbAddressSpace::new("register", 4)));
    }

    #[test]
    fn test_assert_in_space() {
        let obj = TestSpaceBased {
            space: TraceDbAddressSpace::new("ram", 8),
        };
        assert!(obj.assert_in_space(&TraceDbAddressSpace::new("ram", 8), 0x400000).is_ok());
        assert!(obj.assert_in_space(&TraceDbAddressSpace::new("register", 4), 0).is_err());
    }

    #[test]
    fn test_space_entry() {
        let entry = DbTraceSpaceEntry::new(1, "ram");
        assert_eq!(entry.key, 1);
        assert_eq!(entry.space_name, "ram");
        assert_eq!(entry.thread_key, -1);

        let reg_entry = DbTraceSpaceEntry::register(2, "register", 100, 0);
        assert_eq!(reg_entry.thread_key, 100);
        assert_eq!(reg_entry.frame_level, 0);
    }

    #[test]
    fn test_space_based_manager_create() {
        let mut mgr: SpaceBasedManager<Vec<i32>> = SpaceBasedManager::new("test");
        assert_eq!(mgr.space_count(), 0);

        mgr.get_or_create_space("ram", |_| vec![1, 2, 3]);
        assert_eq!(mgr.space_count(), 1);
        assert!(mgr.get_for_space("ram").is_some());
        assert!(mgr.get_for_space("register").is_none());
    }

    #[test]
    fn test_space_based_manager_get_or_create() {
        let mut mgr: SpaceBasedManager<String> = SpaceBasedManager::new("test");

        // First call creates
        let s1 = mgr.get_or_create_space("ram", |_| "created".to_string());
        assert_eq!(s1, "created");

        // Second call returns existing
        let s2 = mgr.get_for_space("ram").unwrap();
        assert_eq!(s2, "created");
    }

    #[test]
    fn test_space_based_manager_multiple_spaces() {
        let mut mgr: SpaceBasedManager<u64> = SpaceBasedManager::new("test");
        mgr.get_or_create_space("ram", |_| 100);
        mgr.get_or_create_space("register", |_| 200);

        assert_eq!(mgr.space_count(), 2);
        let names = mgr.space_names();
        assert!(names.contains(&"ram"));
        assert!(names.contains(&"register"));
    }

    #[test]
    fn test_delegating_manager() {
        struct TestDelegating {
            spaces: BTreeMap<String, Vec<i32>>,
        }

        impl DelegatingManager<Vec<i32>> for TestDelegating {
            fn get_for_space(&self, space_name: &str) -> Option<&Vec<i32>> {
                self.spaces.get(space_name)
            }
            fn get_for_space_or_create(&mut self, space_name: &str) -> &mut Vec<i32> {
                self.spaces.entry(space_name.to_string()).or_default()
            }
        }

        let mut delegating = TestDelegating {
            spaces: BTreeMap::new(),
        };

        // Write creates space and inserts value
        delegating.delegate_write("ram", |m| m.push(42)).unwrap();
        assert_eq!(delegating.spaces.get("ram").unwrap(), &vec![42]);

        // Read returns value
        let sum = delegating.delegate_read("ram", |m| m.iter().sum::<i32>()).unwrap();
        assert_eq!(sum, 42);

        // Read from nonexistent space fails
        assert!(delegating.delegate_read("nonexistent", |_| ()).is_err());
    }

    #[test]
    fn test_register_container_binding() {
        let binding = RegisterContainerBinding::new(
            vec!["Threads".to_string(), "0".to_string()],
            0,
            0,
            "register",
        );
        assert_eq!(binding.thread_key, 0);
        assert_eq!(binding.register_space_name, "register");
    }

    #[test]
    fn test_space_based_manager_iter() {
        let mut mgr: SpaceBasedManager<i32> = SpaceBasedManager::new("test");
        mgr.get_or_create_space("a", |_| 1);
        mgr.get_or_create_space("b", |_| 2);
        mgr.get_or_create_space("c", |_| 3);

        let items: Vec<_> = mgr.iter_spaces().collect();
        assert_eq!(items.len(), 3);
    }
}
