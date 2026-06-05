//! Trace code manager implementation.
//!
//! Ported from Ghidra's `TraceCodeManager` and related interfaces in
//! Framework-TraceModeling. Provides the high-level API for managing
//! code units (instructions, data) in a trace, including the fluent
//! interface for listing operations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::lifespan::Lifespan;

/// An address space identifier used by the code manager.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AddressSpaceId(pub String);

impl AddressSpaceId {
    /// Create a new address space ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The type of a code space (memory or register).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CodeSpaceType {
    /// A memory address space (e.g., "ram", "rom").
    Memory,
    /// A register address space (per-thread, per-frame).
    Register,
}

/// A code space in a trace.
///
/// Ported from Ghidra's `TraceCodeSpace`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCodeSpace {
    /// The address space ID.
    pub space_id: AddressSpaceId,
    /// The type of this space.
    pub space_type: CodeSpaceType,
    /// The thread ID (for register spaces).
    pub thread_id: Option<u64>,
    /// The frame level (for register spaces).
    pub frame_level: Option<u32>,
    /// Whether to create this space if absent.
    pub create_if_absent: bool,
    /// The lifespan of this space.
    pub lifespan: Lifespan,
}

impl TraceCodeSpace {
    /// Create a memory code space.
    pub fn memory(space_id: AddressSpaceId, lifespan: Lifespan) -> Self {
        Self {
            space_id,
            space_type: CodeSpaceType::Memory,
            thread_id: None,
            frame_level: None,
            create_if_absent: false,
            lifespan,
        }
    }

    /// Create a register code space.
    pub fn register(
        space_id: AddressSpaceId,
        thread_id: u64,
        frame_level: u32,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            space_id,
            space_type: CodeSpaceType::Register,
            thread_id: Some(thread_id),
            frame_level: Some(frame_level),
            create_if_absent: false,
            lifespan,
        }
    }

    /// Whether this is a memory space.
    pub fn is_memory(&self) -> bool {
        self.space_type == CodeSpaceType::Memory
    }

    /// Whether this is a register space.
    pub fn is_register(&self) -> bool {
        self.space_type == CodeSpaceType::Register
    }
}

/// The code manager for a trace.
///
/// Ported from Ghidra's `TraceCodeManager` interface. This is the
/// equivalent of `Listing` for traces, supporting time-aware code
/// unit management.
#[derive(Debug, Default)]
pub struct TraceCodeManagerImpl {
    /// Code spaces indexed by space ID.
    spaces: BTreeMap<AddressSpaceId, TraceCodeSpace>,
    /// Default space (typically "ram").
    default_space: Option<AddressSpaceId>,
}

impl TraceCodeManagerImpl {
    /// Create a new code manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a code space for the given address space.
    pub fn get_code_space(
        &mut self,
        space_id: AddressSpaceId,
        create_if_absent: bool,
    ) -> Option<&TraceCodeSpace> {
        if self.spaces.contains_key(&space_id) {
            return self.spaces.get(&space_id);
        }
        if create_if_absent {
            let space = TraceCodeSpace::memory(space_id.clone(), Lifespan::ALL);
            self.spaces.insert(space_id.clone(), space);
            self.spaces.get(&space_id)
        } else {
            None
        }
    }

    /// Get or create a register code space for a thread.
    pub fn get_code_register_space(
        &mut self,
        space_id: AddressSpaceId,
        thread_id: u64,
        create_if_absent: bool,
    ) -> Option<&TraceCodeSpace> {
        let key = space_id.clone();
        if self.spaces.contains_key(&key) {
            return self.spaces.get(&key);
        }
        if create_if_absent {
            let space = TraceCodeSpace::register(key.clone(), thread_id, 0, Lifespan::ALL);
            self.spaces.insert(key.clone(), space);
            self.spaces.get(&key)
        } else {
            None
        }
    }

    /// Set the default address space.
    pub fn set_default_space(&mut self, space_id: AddressSpaceId) {
        self.default_space = Some(space_id);
    }

    /// Get the default address space.
    pub fn default_space(&self) -> Option<&AddressSpaceId> {
        self.default_space.as_ref()
    }

    /// Get all code spaces.
    pub fn spaces(&self) -> &BTreeMap<AddressSpaceId, TraceCodeSpace> {
        &self.spaces
    }

    /// Remove a code space.
    pub fn remove_space(&mut self, space_id: &AddressSpaceId) -> Option<TraceCodeSpace> {
        self.spaces.remove(space_id)
    }

    /// Get the number of code spaces.
    pub fn space_count(&self) -> usize {
        self.spaces.len()
    }
}

/// Operations supported by a trace code space.
///
/// Ported from Ghidra's `TraceCodeOperations`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCodeOperations {
    /// The space ID.
    pub space_id: AddressSpaceId,
    /// Whether this supports instructions.
    pub supports_instructions: bool,
    /// Whether this supports data.
    pub supports_data: bool,
    /// Whether this supports defined data.
    pub supports_defined_data: bool,
}

impl TraceCodeOperations {
    /// Create operations for a full-featured code space.
    pub fn full(space_id: AddressSpaceId) -> Self {
        Self {
            space_id,
            supports_instructions: true,
            supports_data: true,
            supports_defined_data: true,
        }
    }

    /// Create operations for a register space (no instructions).
    pub fn register_only(space_id: AddressSpaceId) -> Self {
        Self {
            space_id,
            supports_instructions: false,
            supports_data: true,
            supports_defined_data: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_space_id() {
        let id = AddressSpaceId::new("ram");
        assert_eq!(id.as_str(), "ram");
    }

    #[test]
    fn test_code_space_memory() {
        let space = TraceCodeSpace::memory(
            AddressSpaceId::new("ram"),
            Lifespan::ALL,
        );
        assert!(space.is_memory());
        assert!(!space.is_register());
        assert!(space.thread_id.is_none());
    }

    #[test]
    fn test_code_space_register() {
        let space = TraceCodeSpace::register(
            AddressSpaceId::new("reg"),
            1,
            0,
            Lifespan::ALL,
        );
        assert!(!space.is_memory());
        assert!(space.is_register());
        assert_eq!(space.thread_id, Some(1));
        assert_eq!(space.frame_level, Some(0));
    }

    #[test]
    fn test_code_manager_default() {
        let manager = TraceCodeManagerImpl::new();
        assert!(manager.spaces().is_empty());
        assert!(manager.default_space().is_none());
    }

    #[test]
    fn test_code_manager_get_space() {
        let mut manager = TraceCodeManagerImpl::new();

        // Without create_if_absent, should return None
        assert!(manager.get_code_space(AddressSpaceId::new("ram"), false).is_none());

        // With create_if_absent, should create and return
        let space = manager.get_code_space(AddressSpaceId::new("ram"), true);
        assert!(space.is_some());
        assert_eq!(space.unwrap().space_id.as_str(), "ram");
        assert_eq!(manager.space_count(), 1);

        // Subsequent calls should return existing
        let space2 = manager.get_code_space(AddressSpaceId::new("ram"), false);
        assert!(space2.is_some());
    }

    #[test]
    fn test_code_manager_register_space() {
        let mut manager = TraceCodeManagerImpl::new();
        let space = manager.get_code_register_space(
            AddressSpaceId::new("reg"),
            42,
            true,
        );
        assert!(space.is_some());
        assert!(space.unwrap().is_register());
    }

    #[test]
    fn test_code_manager_default_space() {
        let mut manager = TraceCodeManagerImpl::new();
        manager.set_default_space(AddressSpaceId::new("ram"));
        assert_eq!(manager.default_space().unwrap().as_str(), "ram");
    }

    #[test]
    fn test_code_manager_remove_space() {
        let mut manager = TraceCodeManagerImpl::new();
        manager.get_code_space(AddressSpaceId::new("ram"), true);
        assert_eq!(manager.space_count(), 1);

        manager.remove_space(&AddressSpaceId::new("ram"));
        assert_eq!(manager.space_count(), 0);
    }

    #[test]
    fn test_code_operations() {
        let ops = TraceCodeOperations::full(AddressSpaceId::new("ram"));
        assert!(ops.supports_instructions);
        assert!(ops.supports_data);

        let ops = TraceCodeOperations::register_only(AddressSpaceId::new("reg"));
        assert!(!ops.supports_instructions);
        assert!(ops.supports_data);
    }

    #[test]
    fn test_code_space_serde() {
        let space = TraceCodeSpace::memory(
            AddressSpaceId::new("ram"),
            Lifespan::ALL,
        );
        let json = serde_json::to_string(&space).unwrap();
        let back: TraceCodeSpace = serde_json::from_str(&json).unwrap();
        assert_eq!(back.space_id.as_str(), "ram");
    }
}
