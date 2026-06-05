//! Extended program view types for database-backed traces.
//!
//! Ported from Ghidra's `ghidra.trace.database.program` package.
//! Provides the program context and reference manager for the trace
//! program view that adapts the trace's register context and references
//! into the Ghidra Program interface.

use std::collections::BTreeMap;

use crate::model::lifespan::Lifespan;

/// Register value at a specific address and snap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramRegisterValue {
    /// Register name.
    pub register: String,
    /// Address offset.
    pub address: u64,
    /// Snap (time point).
    pub snap: i64,
    /// Value bytes (big or little endian per platform).
    pub value: Vec<u8>,
}

impl ProgramRegisterValue {
    /// Create a new register value entry.
    pub fn new(
        register: impl Into<String>,
        address: u64,
        snap: i64,
        value: Vec<u8>,
    ) -> Self {
        Self {
            register: register.into(),
            address,
            snap,
            value,
        }
    }

    /// Get the value as a u64 (assuming little-endian).
    pub fn as_u64_le(&self) -> Option<u64> {
        if self.value.len() >= 8 {
            Some(u64::from_le_bytes([
                self.value[0], self.value[1], self.value[2], self.value[3],
                self.value[4], self.value[5], self.value[6], self.value[7],
            ]))
        } else if self.value.len() >= 4 {
            Some(u32::from_le_bytes([
                self.value[0], self.value[1], self.value[2], self.value[3],
            ]) as u64)
        } else {
            None
        }
    }

    /// Get the value as a u64 (assuming big-endian).
    pub fn as_u64_be(&self) -> Option<u64> {
        if self.value.len() >= 8 {
            Some(u64::from_be_bytes([
                self.value[0], self.value[1], self.value[2], self.value[3],
                self.value[4], self.value[5], self.value[6], self.value[7],
            ]))
        } else if self.value.len() >= 4 {
            Some(u32::from_be_bytes([
                self.value[0], self.value[1], self.value[2], self.value[3],
            ]) as u64)
        } else {
            None
        }
    }

    /// Get the size of the register value in bytes.
    pub fn size(&self) -> usize {
        self.value.len()
    }
}

/// Program context that provides register values at specific addresses.
///
/// Corresponds to Java's `DBTraceProgramViewProgramContext`. Adapts
/// the trace's register context data into the Ghidra ProgramContext
/// interface for use in the program view.
#[derive(Debug)]
pub struct ProgramViewProgramContext {
    /// Register definitions: (name, size_in_bytes).
    register_defs: BTreeMap<String, u32>,
    /// Register values indexed by (register, address).
    values: BTreeMap<(String, u64), ProgramRegisterValue>,
    /// Default register values.
    defaults: BTreeMap<String, Vec<u8>>,
}

impl ProgramViewProgramContext {
    /// Create a new program view context.
    pub fn new() -> Self {
        Self {
            register_defs: BTreeMap::new(),
            values: BTreeMap::new(),
            defaults: BTreeMap::new(),
        }
    }

    /// Add a register definition.
    pub fn add_register(&mut self, name: impl Into<String>, size_bytes: u32) {
        self.register_defs.insert(name.into(), size_bytes);
    }

    /// Set a register value at a specific address.
    pub fn set_value(&mut self, value: ProgramRegisterValue) {
        let key = (value.register.clone(), value.address);
        self.values.insert(key, value);
    }

    /// Get a register value at a specific address.
    pub fn get_value(&self, register: &str, address: u64) -> Option<&ProgramRegisterValue> {
        self.values.get(&(register.to_string(), address))
    }

    /// Set the default value for a register.
    pub fn set_default_value(&mut self, register: impl Into<String>, value: Vec<u8>) {
        self.defaults.insert(register.into(), value);
    }

    /// Get the default value for a register.
    pub fn get_default_value(&self, register: &str) -> Option<&Vec<u8>> {
        self.defaults.get(register)
    }

    /// Get the register size in bytes.
    pub fn register_size(&self, name: &str) -> Option<u32> {
        self.register_defs.get(name).copied()
    }

    /// Get all register names.
    pub fn register_names(&self) -> Vec<&str> {
        self.register_defs.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of register values set.
    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// Remove a register value.
    pub fn remove_value(&mut self, register: &str, address: u64) {
        self.values.remove(&(register.to_string(), address));
    }

    /// Remove all register values in an address range.
    pub fn remove_range(&mut self, start: u64, end: u64, register: &str) {
        let keys: Vec<_> = self
            .values
            .keys()
            .filter(|(r, a)| r == register && *a >= start && *a <= end)
            .cloned()
            .collect();
        for key in keys {
            self.values.remove(&key);
        }
    }

    /// Check if a register has a non-default value at a given address.
    pub fn has_value(&self, register: &str, address: u64) -> bool {
        self.values.contains_key(&(register.to_string(), address))
    }

    /// Check if all registers at an address have the same value as defaults.
    pub fn has_uniform_value(&self, register: &str, value: &[u8], start: u64, end: u64) -> bool {
        for addr in start..=end {
            if let Some(v) = self.get_value(register, addr) {
                if v.value != value {
                    return false;
                }
            } else if let Some(def) = self.get_default_value(register) {
                if def != value {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

impl Default for ProgramViewProgramContext {
    fn default() -> Self {
        Self::new()
    }
}

/// A reference entry in the program view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramViewReference {
    /// Source address.
    pub from_address: u64,
    /// Destination address.
    pub to_address: u64,
    /// Reference type.
    pub ref_type: ProgramViewReferenceType,
    /// Operand index.
    pub operand_index: i32,
    /// Whether this is a primary reference.
    pub is_primary: bool,
}

/// Types of references in the program view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramViewReferenceType {
    /// Data read reference.
    Read,
    /// Data write reference.
    Write,
    /// Data read/write reference.
    ReadWrite,
    /// Flow reference (call, jump).
    Flow,
    /// Indirect reference.
    Indirect,
    /// Offset reference.
    Offset,
    /// Shifted reference.
    Shifted,
}

/// Program view reference manager.
///
/// Corresponds to Java's `AbstractDBTraceProgramViewReferenceManager`.
/// Manages cross-references in the trace program view.
#[derive(Debug)]
pub struct ProgramViewReferenceManager {
    /// References indexed by (from_address, to_address).
    references: BTreeMap<(u64, u64), ProgramViewReference>,
}

impl ProgramViewReferenceManager {
    /// Create a new reference manager.
    pub fn new() -> Self {
        Self {
            references: BTreeMap::new(),
        }
    }

    /// Add a reference.
    pub fn add_reference(&mut self, reference: ProgramViewReference) {
        self.references
            .insert((reference.from_address, reference.to_address), reference);
    }

    /// Get references from a specific address.
    pub fn get_references_from(&self, from: u64) -> Vec<&ProgramViewReference> {
        self.references
            .range((from, 0)..=(from, u64::MAX))
            .map(|(_, r)| r)
            .collect()
    }

    /// Get references to a specific address.
    pub fn get_references_to(&self, to: u64) -> Vec<&ProgramViewReference> {
        self.references
            .values()
            .filter(|r| r.to_address == to)
            .collect()
    }

    /// Delete a reference.
    pub fn delete_reference(&mut self, from: u64, to: u64) -> bool {
        self.references.remove(&(from, to)).is_some()
    }

    /// Delete all references from an address.
    pub fn delete_references_from(&mut self, from: u64) -> usize {
        let keys: Vec<_> = self
            .references
            .range((from, 0)..=(from, u64::MAX))
            .map(|(k, _)| *k)
            .collect();
        let count = keys.len();
        for key in keys {
            self.references.remove(&key);
        }
        count
    }

    /// Check if there are references from an address.
    pub fn has_references_from(&self, from: u64) -> bool {
        self.references
            .range((from, 0)..=(from, u64::MAX))
            .next()
            .is_some()
    }

    /// Check if there are references to an address.
    pub fn has_references_to(&self, to: u64) -> bool {
        self.references.values().any(|r| r.to_address == to)
    }

    /// Get the number of references from an address.
    pub fn reference_count_from(&self, from: u64) -> usize {
        self.references
            .range((from, 0)..=(from, u64::MAX))
            .count()
    }

    /// Get the number of references to an address.
    pub fn reference_count_to(&self, to: u64) -> usize {
        self.references.values().filter(|r| r.to_address == to).count()
    }

    /// Get total reference count.
    pub fn total_references(&self) -> usize {
        self.references.len()
    }

    /// Set a reference as primary.
    pub fn set_primary(&mut self, from: u64, to: u64, is_primary: bool) {
        if let Some(r) = self.references.get_mut(&(from, to)) {
            r.is_primary = is_primary;
        }
    }
}

impl Default for ProgramViewReferenceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_value_as_u64() {
        let rv = ProgramRegisterValue::new("RAX", 0x400000, 0, vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        assert_eq!(rv.as_u64_le(), Some(0x12345678));
        assert_eq!(rv.as_u64_be(), Some(0x7856341200000000));
    }

    #[test]
    fn test_register_value_size() {
        let rv = ProgramRegisterValue::new("EAX", 0x400000, 0, vec![0, 0, 0, 0]);
        assert_eq!(rv.size(), 4);
        assert!(rv.as_u64_le().is_some());
    }

    #[test]
    fn test_program_view_context_basic() {
        let mut ctx = ProgramViewProgramContext::new();
        ctx.add_register("RAX", 8);
        ctx.add_register("RBX", 8);

        assert_eq!(ctx.register_size("RAX"), Some(8));
        assert_eq!(ctx.register_names().len(), 2);
    }

    #[test]
    fn test_program_view_context_set_get() {
        let mut ctx = ProgramViewProgramContext::new();
        ctx.add_register("RAX", 8);

        let rv = ProgramRegisterValue::new("RAX", 0x400000, 0, vec![42, 0, 0, 0, 0, 0, 0, 0]);
        ctx.set_value(rv);

        let val = ctx.get_value("RAX", 0x400000);
        assert!(val.is_some());
        assert_eq!(val.unwrap().value[0], 42);
        assert_eq!(ctx.value_count(), 1);
    }

    #[test]
    fn test_program_view_context_default_values() {
        let mut ctx = ProgramViewProgramContext::new();
        ctx.set_default_value("RAX", vec![0; 8]);

        let def = ctx.get_default_value("RAX");
        assert!(def.is_some());
        assert_eq!(def.unwrap().len(), 8);
    }

    #[test]
    fn test_program_view_context_remove_range() {
        let mut ctx = ProgramViewProgramContext::new();
        ctx.set_value(ProgramRegisterValue::new("RAX", 0x1000, 0, vec![1; 8]));
        ctx.set_value(ProgramRegisterValue::new("RAX", 0x1001, 0, vec![2; 8]));
        ctx.set_value(ProgramRegisterValue::new("RAX", 0x2000, 0, vec![3; 8]));

        ctx.remove_range(0x1000, 0x1001, "RAX");
        assert_eq!(ctx.value_count(), 1);
        assert!(ctx.has_value("RAX", 0x2000));
    }

    #[test]
    fn test_program_view_context_uniform() {
        let mut ctx = ProgramViewProgramContext::new();
        ctx.set_default_value("RAX", vec![0; 8]);
        ctx.set_value(ProgramRegisterValue::new("RAX", 0x1000, 0, vec![42; 8]));

        assert!(ctx.has_uniform_value("RAX", &[42; 8], 0x1000, 0x1000));
        // 0x1001 uses default (0s) which != [42;8]
        assert!(!ctx.has_uniform_value("RAX", &[42; 8], 0x1000, 0x1001));
    }

    #[test]
    fn test_reference_manager_add_and_query() {
        let mut mgr = ProgramViewReferenceManager::new();
        mgr.add_reference(ProgramViewReference {
            from_address: 0x400000,
            to_address: 0x400100,
            ref_type: ProgramViewReferenceType::Flow,
            operand_index: 0,
            is_primary: true,
        });
        mgr.add_reference(ProgramViewReference {
            from_address: 0x400000,
            to_address: 0x400200,
            ref_type: ProgramViewReferenceType::Read,
            operand_index: 1,
            is_primary: false,
        });

        assert_eq!(mgr.total_references(), 2);
        assert!(mgr.has_references_from(0x400000));
        assert!(!mgr.has_references_from(0x400005));
        assert_eq!(mgr.reference_count_from(0x400000), 2);
    }

    #[test]
    fn test_reference_manager_references_to() {
        let mut mgr = ProgramViewReferenceManager::new();
        mgr.add_reference(ProgramViewReference {
            from_address: 0x1000,
            to_address: 0x2000,
            ref_type: ProgramViewReferenceType::Flow,
            operand_index: 0,
            is_primary: true,
        });
        mgr.add_reference(ProgramViewReference {
            from_address: 0x1500,
            to_address: 0x2000,
            ref_type: ProgramViewReferenceType::Read,
            operand_index: 0,
            is_primary: false,
        });

        let refs_to = mgr.get_references_to(0x2000);
        assert_eq!(refs_to.len(), 2);
        assert!(mgr.has_references_to(0x2000));
        assert!(!mgr.has_references_to(0x3000));
    }

    #[test]
    fn test_reference_manager_delete() {
        let mut mgr = ProgramViewReferenceManager::new();
        mgr.add_reference(ProgramViewReference {
            from_address: 0x1000,
            to_address: 0x2000,
            ref_type: ProgramViewReferenceType::Flow,
            operand_index: 0,
            is_primary: true,
        });

        assert!(mgr.delete_reference(0x1000, 0x2000));
        assert_eq!(mgr.total_references(), 0);
        assert!(!mgr.delete_reference(0x1000, 0x2000));
    }

    #[test]
    fn test_reference_manager_delete_all_from() {
        let mut mgr = ProgramViewReferenceManager::new();
        mgr.add_reference(ProgramViewReference {
            from_address: 0x1000,
            to_address: 0x2000,
            ref_type: ProgramViewReferenceType::Flow,
            operand_index: 0,
            is_primary: true,
        });
        mgr.add_reference(ProgramViewReference {
            from_address: 0x1000,
            to_address: 0x3000,
            ref_type: ProgramViewReferenceType::Read,
            operand_index: 0,
            is_primary: false,
        });

        let deleted = mgr.delete_references_from(0x1000);
        assert_eq!(deleted, 2);
        assert_eq!(mgr.total_references(), 0);
    }

    #[test]
    fn test_reference_manager_set_primary() {
        let mut mgr = ProgramViewReferenceManager::new();
        mgr.add_reference(ProgramViewReference {
            from_address: 0x1000,
            to_address: 0x2000,
            ref_type: ProgramViewReferenceType::Flow,
            operand_index: 0,
            is_primary: false,
        });

        mgr.set_primary(0x1000, 0x2000, true);
        let refs = mgr.get_references_from(0x1000);
        assert!(refs[0].is_primary);
    }
}
