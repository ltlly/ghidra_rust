//! Register value types for trace data.
//!
//! Ported from Ghidra's `TraceRegister`, `TraceRegisterContainer`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A register definition within a trace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceRegister {
    /// Register name (e.g., "RAX", "EIP").
    pub name: String,
    /// Register size in bytes.
    pub size: usize,
    /// Parent register name, if this is a sub-register.
    pub parent: Option<String>,
    /// Least significant bit offset within parent.
    pub lsb_offset: usize,
}

impl TraceRegister {
    /// Create a new register.
    pub fn new(name: impl Into<String>, size: usize) -> Self {
        Self {
            name: name.into(),
            size,
            parent: None,
            lsb_offset: 0,
        }
    }

    /// Set the parent register.
    pub fn with_parent(mut self, parent: impl Into<String>, lsb_offset: usize) -> Self {
        self.parent = Some(parent.into());
        self.lsb_offset = lsb_offset;
        self
    }

    /// Whether this is a sub-register.
    pub fn is_sub_register(&self) -> bool {
        self.parent.is_some()
    }
}

/// A group of registers (e.g., "General Purpose", "Floating Point").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRegisterGroup {
    /// Group name.
    pub name: String,
    /// Register names in this group.
    pub registers: Vec<String>,
}

impl TraceRegisterGroup {
    /// Create a new register group.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            registers: Vec::new(),
        }
    }

    /// Add a register to this group.
    pub fn add_register(&mut self, name: impl Into<String>) {
        self.registers.push(name.into());
    }
}

/// A container that holds register name -> value mappings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceRegisterContainer {
    /// Register values by name.
    values: BTreeMap<String, Vec<u8>>,
}

impl TraceRegisterContainer {
    /// Create an empty register container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a register value.
    pub fn set_value(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.values.insert(name.into(), value);
    }

    /// Get a register value.
    pub fn get_value(&self, name: &str) -> Option<&Vec<u8>> {
        self.values.get(name)
    }

    /// Check if a register has a value.
    pub fn has_value(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// Remove a register value.
    pub fn clear_value(&mut self, name: &str) -> Option<Vec<u8>> {
        self.values.remove(name)
    }

    /// Iterate over all register-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<u8>)> {
        self.values.iter()
    }

    /// Number of register values stored.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the container is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register() {
        let r = TraceRegister::new("RAX", 8);
        assert_eq!(r.size, 8);
        assert!(!r.is_sub_register());

        let sub = TraceRegister::new("EAX", 4).with_parent("RAX", 0);
        assert!(sub.is_sub_register());
    }

    #[test]
    fn test_register_container() {
        let mut c = TraceRegisterContainer::new();
        c.set_value("RAX", vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        assert!(c.has_value("RAX"));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn test_register_group() {
        let mut g = TraceRegisterGroup::new("General Purpose");
        g.add_register("RAX");
        g.add_register("RBX");
        assert_eq!(g.registers.len(), 2);
    }
}
