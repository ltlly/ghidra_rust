//! Register object and container for the trace database.
//!
//! Ported from Ghidra's `DBTraceObjectRegister` and
//! `DBTraceObjectRegisterContainer` in
//! `ghidra.trace.database.memory`. Represents register values and
//! register containers within the target object hierarchy.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A register object in the target object hierarchy.
///
/// Ported from Ghidra's `DBTraceObjectRegister`. Each register is a
/// named value that can change over time within a register bank.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceObjectRegister {
    /// Database object ID.
    pub object_id: i64,
    /// The register name (e.g., "RAX", "PC").
    pub name: String,
    /// The register size in bytes.
    pub size: u32,
    /// The register value as raw bytes (most recent).
    pub value: Option<Vec<u8>>,
    /// The snap range during which this register exists.
    pub min_snap: i64,
    pub max_snap: i64,
}

impl DbTraceObjectRegister {
    /// Create a new register object.
    pub fn new(
        object_id: i64,
        name: impl Into<String>,
        size: u32,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            object_id,
            name: name.into(),
            size,
            value: None,
            min_snap: lifespan.lmin(),
            max_snap: lifespan.lmax(),
        }
    }

    /// Set the register value.
    pub fn set_value(&mut self, value: Vec<u8>) {
        self.value = Some(value);
    }

    /// Get the register value.
    pub fn get_value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    /// Get the register value as a u64 (little-endian).
    pub fn get_value_u64(&self) -> Option<u64> {
        self.value.as_ref().map(|v| {
            let mut buf = [0u8; 8];
            let len = v.len().min(8);
            buf[..len].copy_from_slice(&v[..len]);
            u64::from_le_bytes(buf)
        })
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }
}

/// A register container (bank) in the target object hierarchy.
///
/// Ported from Ghidra's `DBTraceObjectRegisterContainer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceObjectRegisterContainer {
    /// Database object ID.
    pub object_id: i64,
    /// The container name (e.g., "Registers", "VFP").
    pub name: String,
    /// Child register object IDs.
    pub register_ids: Vec<i64>,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

impl DbTraceObjectRegisterContainer {
    /// Create a new register container.
    pub fn new(
        object_id: i64,
        name: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            object_id,
            name: name.into(),
            register_ids: Vec::new(),
            min_snap: lifespan.lmin(),
            max_snap: lifespan.lmax(),
        }
    }

    /// Add a register to this container.
    pub fn add_register(&mut self, register_id: i64) {
        self.register_ids.push(register_id);
    }

    /// Get the number of registers in this container.
    pub fn register_count(&self) -> usize {
        self.register_ids.len()
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_creation() {
        let reg = DbTraceObjectRegister::new(1, "RAX", 8, Lifespan::span(0, 100));
        assert_eq!(reg.name, "RAX");
        assert_eq!(reg.size, 8);
        assert!(reg.get_value().is_none());
    }

    #[test]
    fn test_register_value() {
        let mut reg = DbTraceObjectRegister::new(1, "RAX", 8, Lifespan::span(0, 100));
        reg.set_value(vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(reg.get_value_u64(), Some(0x42));
    }

    #[test]
    fn test_register_container() {
        let mut container = DbTraceObjectRegisterContainer::new(
            1, "Registers", Lifespan::span(0, 100),
        );
        assert_eq!(container.register_count(), 0);
        container.add_register(10);
        container.add_register(11);
        assert_eq!(container.register_count(), 2);
    }
}
