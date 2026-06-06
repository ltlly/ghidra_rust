//! DB-backed register and register container for trace objects.
//!
//! Ported from Ghidra's `ghidra.trace.database.memory`:
//! - `DBTraceObjectRegister`: A register value attached to a trace object.
//! - `DBTraceObjectRegisterContainer`: A container of register values.
//! - `InternalTraceMemoryOperations`: Internal interface for memory operations
//!   that support register-level read/write.
//!
//! These types allow trace objects (typically threads) to hold register state
//! within the object model tree, bridging the register context with the
//! target object model.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::Lifespan;

/// A register value stored on a trace object.
///
/// Ported from `DBTraceObjectRegister`. Represents a single register's value
/// within a register container object in the trace tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceObjectRegister {
    /// The register name (e.g., "RAX", "PC", "SP").
    pub name: String,
    /// The register value as bytes (big-endian or little-endian depending on arch).
    pub value: Vec<u8>,
    /// The lifespan during which this register value is valid.
    pub lifespan: Lifespan,
    /// The bit length of the register.
    pub bit_length: u32,
    /// Whether the register value is defined (known) at this point.
    pub is_defined: bool,
}

impl DbTraceObjectRegister {
    /// Create a new register with the given name and value.
    pub fn new(name: &str, value: Vec<u8>, lifespan: Lifespan, bit_length: u32) -> Self {
        Self {
            name: name.to_string(),
            value,
            lifespan,
            bit_length,
            is_defined: true,
        }
    }

    /// Create an undefined (unknown) register.
    pub fn undefined(name: &str, bit_length: u32, lifespan: Lifespan) -> Self {
        Self {
            name: name.to_string(),
            value: vec![0u8; (bit_length as usize + 7) / 8],
            lifespan,
            bit_length,
            is_defined: false,
        }
    }

    /// Get the value as a u64 (assuming little-endian, up to 64 bits).
    pub fn value_as_u64(&self) -> Option<u64> {
        if !self.is_defined || self.value.len() > 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf[..self.value.len()].copy_from_slice(&self.value);
        Some(u64::from_le_bytes(buf))
    }

    /// Get the value as a u128 (assuming little-endian, up to 128 bits).
    pub fn value_as_u128(&self) -> Option<u128> {
        if !self.is_defined || self.value.len() > 16 {
            return None;
        }
        let mut buf = [0u8; 16];
        buf[..self.value.len()].copy_from_slice(&self.value);
        Some(u128::from_le_bytes(buf))
    }

    /// Get the byte length of the register value.
    pub fn byte_length(&self) -> usize {
        self.value.len()
    }
}

/// A container of register values attached to a trace object.
///
/// Ported from `DBTraceObjectRegisterContainer`. This is typically attached to
/// a thread or stack frame object to hold all its register values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceObjectRegisterContainer {
    /// Register values keyed by register name.
    registers: BTreeMap<String, DbTraceObjectRegister>,
    /// The parent container key path.
    pub container_path: String,
    /// The snap at which these register values are observed.
    pub snap: i64,
}

impl DbTraceObjectRegisterContainer {
    /// Create a new empty register container.
    pub fn new(container_path: &str, snap: i64) -> Self {
        Self {
            registers: BTreeMap::new(),
            container_path: container_path.to_string(),
            snap,
        }
    }

    /// Set a register value.
    pub fn set_register(&mut self, reg: DbTraceObjectRegister) {
        self.registers.insert(reg.name.clone(), reg);
    }

    /// Get a register value by name.
    pub fn get_register(&self, name: &str) -> Option<&DbTraceObjectRegister> {
        self.registers.get(name)
    }

    /// Remove a register value by name.
    pub fn remove_register(&mut self, name: &str) -> Option<DbTraceObjectRegister> {
        self.registers.remove(name)
    }

    /// Check if a register is defined (known).
    pub fn is_register_defined(&self, name: &str) -> bool {
        self.registers
            .get(name)
            .map_or(false, |r| r.is_defined)
    }

    /// Get all register names.
    pub fn register_names(&self) -> Vec<&str> {
        self.registers.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of registers.
    pub fn register_count(&self) -> usize {
        self.registers.len()
    }

    /// Iterate over all registers.
    pub fn iter(&self) -> impl Iterator<Item = &DbTraceObjectRegister> {
        self.registers.values()
    }

    /// Check if the container is empty.
    pub fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }

    /// Get all defined register values as name-value pairs.
    pub fn defined_values(&self) -> Vec<(&str, &[u8])> {
        self.registers
            .values()
            .filter(|r| r.is_defined)
            .map(|r| (r.name.as_str(), r.value.as_slice()))
            .collect()
    }

    /// Get all register values as name-u64 pairs (for registers up to 64 bits).
    pub fn values_as_u64(&self) -> Vec<(&str, u64)> {
        self.registers
            .values()
            .filter_map(|r| r.value_as_u64().map(|v| (r.name.as_str(), v)))
            .collect()
    }

    /// Apply a diff of register changes to this container.
    pub fn apply_changes(&mut self, changes: BTreeMap<String, Option<DbTraceObjectRegister>>) {
        for (name, maybe_reg) in changes {
            match maybe_reg {
                Some(reg) => { self.registers.insert(name, reg); }
                None => { self.registers.remove(&name); }
            }
        }
    }
}

/// Internal interface for memory operations that include register access.
///
/// Ported from `InternalTraceMemoryOperations`. Combines memory region management
/// with register-level read/write capabilities.
pub trait InternalTraceMemoryOperations {
    /// Read register bytes for the given thread/frame at the given snap.
    fn read_register_bytes(
        &self,
        snap: i64,
        thread_key: &str,
        frame_level: i32,
        register_name: &str,
    ) -> Option<Vec<u8>>;

    /// Write register bytes for the given thread/frame over the given lifespan.
    fn write_register_bytes(
        &mut self,
        lifespan: &Lifespan,
        thread_key: &str,
        frame_level: i32,
        register_name: &str,
        value: &[u8],
    );

    /// Get the defined state of a register.
    fn get_register_state(
        &self,
        snap: i64,
        thread_key: &str,
        frame_level: i32,
        register_name: &str,
    ) -> RegisterDefinedState;

    /// Set a register as undefined.
    fn set_register_undefined(
        &mut self,
        lifespan: &Lifespan,
        thread_key: &str,
        frame_level: i32,
        register_name: &str,
    );

    /// Read memory bytes at the given address and snap.
    fn read_memory_bytes(
        &self,
        snap: i64,
        address: u64,
        length: usize,
    ) -> Option<Vec<u8>>;

    /// Write memory bytes at the given address over the given lifespan.
    fn write_memory_bytes(
        &mut self,
        lifespan: &Lifespan,
        address: u64,
        value: &[u8],
    );
}

/// Whether a register value is defined, partially defined, or unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterDefinedState {
    /// The register value is fully defined (known).
    Defined,
    /// The register value is partially defined.
    Partial,
    /// The register value is unknown.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_register_basic() {
        let reg = DbTraceObjectRegister::new(
            "RAX",
            vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            Lifespan::span(0, 1),
            64,
        );

        assert_eq!(reg.name, "RAX");
        assert_eq!(reg.bit_length, 64);
        assert!(reg.is_defined);
        assert_eq!(reg.value_as_u64(), Some(0x42));
    }

    #[test]
    fn test_object_register_undefined() {
        let reg = DbTraceObjectRegister::undefined("RBX", 64, Lifespan::span(0, 1));
        assert!(!reg.is_defined);
        assert_eq!(reg.byte_length(), 8);
        // Undefined registers return None from value_as_u64
        assert!(reg.value_as_u64().is_none());
    }

    #[test]
    fn test_object_register_u128() {
        let mut value = vec![0u8; 16];
        value[0] = 0xFF;
        value[15] = 0x01;
        let reg = DbTraceObjectRegister::new("XMM0", value, Lifespan::span(0, 1), 128);

        let val = reg.value_as_u128();
        assert!(val.is_some());
        // Little-endian: 0x01_00..00_FF
        assert_eq!(val.unwrap(), 0x01_00_00_00_00_00_00_00_00_00_00_00_00_00_00_FF);
    }

    #[test]
    fn test_register_container_basic() {
        let mut container = DbTraceObjectRegisterContainer::new("Threads[0]", 0);

        container.set_register(DbTraceObjectRegister::new(
            "RAX",
            vec![0x42, 0, 0, 0, 0, 0, 0, 0],
            Lifespan::span(0, 1),
            64,
        ));
        container.set_register(DbTraceObjectRegister::new(
            "RBX",
            vec![0x99, 0, 0, 0, 0, 0, 0, 0],
            Lifespan::span(0, 1),
            64,
        ));

        assert_eq!(container.register_count(), 2);
        assert!(container.is_register_defined("RAX"));
        assert!(container.get_register("RAX").is_some());
        assert!(container.get_register("NONE").is_none());
    }

    #[test]
    fn test_register_container_register_names() {
        let mut container = DbTraceObjectRegisterContainer::new("Threads[0]", 0);

        container.set_register(DbTraceObjectRegister::new(
            "RAX", vec![1, 0, 0, 0, 0, 0, 0, 0], Lifespan::span(0, 1), 64,
        ));
        container.set_register(DbTraceObjectRegister::new(
            "RBX", vec![2, 0, 0, 0, 0, 0, 0, 0], Lifespan::span(0, 1), 64,
        ));

        let names = container.register_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"RAX"));
        assert!(names.contains(&"RBX"));
    }

    #[test]
    fn test_register_container_remove() {
        let mut container = DbTraceObjectRegisterContainer::new("Threads[0]", 0);
        container.set_register(DbTraceObjectRegister::new(
            "RAX", vec![1, 0, 0, 0, 0, 0, 0, 0], Lifespan::span(0, 1), 64,
        ));

        let removed = container.remove_register("RAX");
        assert!(removed.is_some());
        assert_eq!(container.register_count(), 0);
    }

    #[test]
    fn test_register_container_defined_values() {
        let mut container = DbTraceObjectRegisterContainer::new("Threads[0]", 0);

        container.set_register(DbTraceObjectRegister::new(
            "RAX", vec![0x42, 0, 0, 0, 0, 0, 0, 0], Lifespan::span(0, 1), 64,
        ));
        container.set_register(DbTraceObjectRegister::undefined("RBX", 64, Lifespan::span(0, 1)));

        let defined = container.defined_values();
        assert_eq!(defined.len(), 1);
        assert_eq!(defined[0].0, "RAX");
    }

    #[test]
    fn test_register_container_values_as_u64() {
        let mut container = DbTraceObjectRegisterContainer::new("Threads[0]", 0);

        container.set_register(DbTraceObjectRegister::new(
            "RAX", vec![0x42, 0, 0, 0, 0, 0, 0, 0], Lifespan::span(0, 1), 64,
        ));
        container.set_register(DbTraceObjectRegister::new(
            "RSP", vec![0x00, 0x10, 0, 0, 0, 0, 0, 0], Lifespan::span(0, 1), 64,
        ));

        let vals = container.values_as_u64();
        assert_eq!(vals.len(), 2);
        assert_eq!(vals.iter().find(|(n, _)| *n == "RAX").unwrap().1, 0x42);
        assert_eq!(vals.iter().find(|(n, _)| *n == "RSP").unwrap().1, 0x1000);
    }

    #[test]
    fn test_register_container_apply_changes() {
        let mut container = DbTraceObjectRegisterContainer::new("Threads[0]", 0);
        container.set_register(DbTraceObjectRegister::new(
            "RAX", vec![1, 0, 0, 0, 0, 0, 0, 0], Lifespan::span(0, 1), 64,
        ));

        let mut changes = BTreeMap::new();
        changes.insert(
            "RAX".to_string(),
            Some(DbTraceObjectRegister::new(
                "RAX", vec![0x99, 0, 0, 0, 0, 0, 0, 0], Lifespan::span(0, 1), 64,
            )),
        );
        changes.insert("RBX".to_string(), None); // Remove RBX (doesn't exist, should be no-op)

        container.apply_changes(changes);
        assert_eq!(container.get_register("RAX").unwrap().value_as_u64(), Some(0x99));
    }

    #[test]
    fn test_register_defined_state() {
        assert_ne!(RegisterDefinedState::Defined, RegisterDefinedState::Unknown);
        assert_ne!(RegisterDefinedState::Partial, RegisterDefinedState::Unknown);
    }

    #[test]
    fn test_register_container_empty() {
        let container = DbTraceObjectRegisterContainer::new("Threads[0]", 0);
        assert!(container.is_empty());
        assert_eq!(container.register_count(), 0);
        assert!(container.defined_values().is_empty());
        assert!(container.values_as_u64().is_empty());
    }
}
