//! Symbolic register map.
//!
//! Ported from `SymZ3RegisterMap.java` in the SymbolicSummaryZ3 extension.
//!
//! Maps register names to their offset and size in the register address
//! space, providing symbolic value lookup by name.

use super::model::SymValueZ3;
use super::state::{SpaceKind, SymZ3State};
use std::collections::HashMap;

/// A register descriptor.
#[derive(Debug, Clone)]
pub struct RegisterDescriptor {
    /// Register name (e.g., "RAX", "EIP").
    pub name: String,
    /// Offset in the register address space.
    pub offset: u64,
    /// Size in bytes.
    pub size: u32,
}

impl RegisterDescriptor {
    /// Create a new register descriptor.
    pub fn new(name: impl Into<String>, offset: u64, size: u32) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
        }
    }
}

/// Maps register names to their locations in the register space.
#[derive(Debug, Clone, Default)]
pub struct SymZ3RegisterMap {
    /// Register descriptors by name.
    registers: HashMap<String, RegisterDescriptor>,
    /// Name lookup by (offset, size).
    by_offset: HashMap<(u64, u32), String>,
}

impl SymZ3RegisterMap {
    /// Create an empty register map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a register descriptor.
    pub fn add(&mut self, desc: RegisterDescriptor) {
        self.by_offset
            .insert((desc.offset, desc.size), desc.name.clone());
        self.registers.insert(desc.name.clone(), desc);
    }

    /// Get a register descriptor by name.
    pub fn get(&self, name: &str) -> Option<&RegisterDescriptor> {
        self.registers.get(name)
    }

    /// Get a register name by offset and size.
    pub fn name_at(&self, offset: u64, size: u32) -> Option<&str> {
        self.by_offset
            .get(&(offset, size))
            .map(|s| s.as_str())
    }

    /// Get the symbolic value for a register by name.
    pub fn get_value<'a>(&self, name: &str, state: &'a SymZ3State) -> Option<&'a SymValueZ3> {
        let desc = self.registers.get(name)?;
        state.get_value(SpaceKind::Register, desc.offset, desc.size)
    }

    /// Set the symbolic value for a register by name.
    pub fn set_value(
        &self,
        name: &str,
        state: &mut SymZ3State,
        value: SymValueZ3,
    ) -> bool {
        if let Some(desc) = self.registers.get(name) {
            state.set_value(SpaceKind::Register, desc.offset, desc.size, value);
            true
        } else {
            false
        }
    }

    /// Number of registers in the map.
    pub fn len(&self) -> usize {
        self.registers.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }

    /// Create a default x86-64 register map.
    pub fn x86_64() -> Self {
        let mut map = Self::new();
        map.add(RegisterDescriptor::new("RAX", 0, 8));
        map.add(RegisterDescriptor::new("RBX", 8, 8));
        map.add(RegisterDescriptor::new("RCX", 16, 8));
        map.add(RegisterDescriptor::new("RDX", 24, 8));
        map.add(RegisterDescriptor::new("RSI", 32, 8));
        map.add(RegisterDescriptor::new("RDI", 40, 8));
        map.add(RegisterDescriptor::new("RBP", 48, 8));
        map.add(RegisterDescriptor::new("RSP", 56, 8));
        map.add(RegisterDescriptor::new("RIP", 64, 8));
        // Sub-registers
        map.add(RegisterDescriptor::new("EAX", 0, 4));
        map.add(RegisterDescriptor::new("AX", 0, 2));
        map.add(RegisterDescriptor::new("AL", 0, 1));
        map
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_map() {
        let mut map = SymZ3RegisterMap::new();
        map.add(RegisterDescriptor::new("RAX", 0, 8));
        map.add(RegisterDescriptor::new("RBX", 8, 8));

        assert!(map.get("RAX").is_some());
        assert!(map.get("RCX").is_none());
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_name_at_offset() {
        let mut map = SymZ3RegisterMap::new();
        map.add(RegisterDescriptor::new("RAX", 0, 8));

        assert_eq!(map.name_at(0, 8), Some("RAX"));
        assert_eq!(map.name_at(0, 4), None);
    }

    #[test]
    fn test_x86_64_map() {
        let map = SymZ3RegisterMap::x86_64();
        assert!(map.get("RAX").is_some());
        assert!(map.get("AL").is_some());
        assert!(map.get("RIP").is_some());
    }

    #[test]
    fn test_set_and_get_value() {
        let mut map = SymZ3RegisterMap::new();
        map.add(RegisterDescriptor::new("RAX", 0, 8));

        let mut state = SymZ3State::new();
        map.set_value("RAX", &mut state, SymValueZ3::from_bitvec("rax_val"));

        let val = map.get_value("RAX", &state).unwrap();
        assert_eq!(val.bitvec_expr_string.as_deref(), Some("rax_val"));
    }
}
