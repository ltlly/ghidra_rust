//! Deep register context database types.
//!
//! Ported from Ghidra's Framework-TraceModeling register context types.
//! Provides register value management, context range operations, and
//! register state tracking for the trace database.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The defined state of a register value at a given address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterDefinedState {
    /// The register value is fully defined.
    Defined,
    /// The register value is partially defined (some bits known).
    Partial,
    /// The register value is completely unknown.
    Unknown,
}

impl RegisterDefinedState {
    /// Whether the value has any known bits.
    pub fn has_known_bits(&self) -> bool {
        matches!(self, RegisterDefinedState::Defined | RegisterDefinedState::Partial)
    }
}

/// A register value with its mask indicating which bits are known.
///
/// Ported from Ghidra's `RegisterValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepRegisterValue {
    /// The register name.
    pub register: String,
    /// The value bytes (little-endian).
    pub value: Vec<u8>,
    /// The mask bytes indicating which bits are known (1 = known).
    pub mask: Vec<u8>,
}

impl DeepRegisterValue {
    /// Create a fully defined register value.
    pub fn defined(register: impl Into<String>, value: Vec<u8>) -> Self {
        let mask = vec![0xFF; value.len()];
        Self {
            register: register.into(),
            value,
            mask,
        }
    }

    /// Create an undefined register value.
    pub fn undefined(register: impl Into<String>, size: usize) -> Self {
        Self {
            register: register.into(),
            value: vec![0; size],
            mask: vec![0; size],
        }
    }

    /// Create a partially defined register value.
    pub fn partial(
        register: impl Into<String>,
        value: Vec<u8>,
        mask: Vec<u8>,
    ) -> Self {
        Self {
            register: register.into(),
            value,
            mask,
        }
    }

    /// Get the defined state.
    pub fn defined_state(&self) -> RegisterDefinedState {
        let all_known = self.mask.iter().all(|&m| m == 0xFF);
        let all_unknown = self.mask.iter().all(|&m| m == 0x00);
        if all_known {
            RegisterDefinedState::Defined
        } else if all_unknown {
            RegisterDefinedState::Unknown
        } else {
            RegisterDefinedState::Partial
        }
    }

    /// Whether this value is fully defined.
    pub fn is_defined(&self) -> bool {
        self.defined_state() == RegisterDefinedState::Defined
    }

    /// Get the value as u64 (little-endian), if fully defined.
    pub fn as_u64(&self) -> Option<u64> {
        if !self.is_defined() || self.value.len() < 8 {
            return None;
        }
        Some(u64::from_le_bytes(self.value[..8].try_into().unwrap()))
    }

    /// Get the value as u32 (little-endian), if fully defined.
    pub fn as_u32(&self) -> Option<u32> {
        if !self.is_defined() || self.value.len() < 4 {
            return None;
        }
        Some(u32::from_le_bytes(self.value[..4].try_into().unwrap()))
    }
}

/// A context register value at a specific address range.
///
/// Ported from Ghidra's `ContextRegisterValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextRegisterValue {
    /// The register name.
    pub register: String,
    /// The start address of the range.
    pub min_address: u64,
    /// The end address of the range (inclusive).
    pub max_address: u64,
    /// The register value.
    pub value: DeepRegisterValue,
}

impl ContextRegisterValue {
    /// Create a new context register value.
    pub fn new(
        register: impl Into<String>,
        min_address: u64,
        max_address: u64,
        value: DeepRegisterValue,
    ) -> Self {
        Self {
            register: register.into(),
            min_address,
            max_address,
            value,
        }
    }

    /// The length of the address range.
    pub fn range_length(&self) -> u64 {
        self.max_address - self.min_address + 1
    }

    /// Whether this range contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.min_address && addr <= self.max_address
    }
}

/// A masked context value range used for register context queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskedContextValue {
    /// The register name.
    pub register: String,
    /// The value.
    pub value: u64,
    /// The mask (1 bits indicate which bits of value are relevant).
    pub mask: u64,
    /// The start address of the range.
    pub min_address: u64,
    /// The end address of the range.
    pub max_address: u64,
}

impl MaskedContextValue {
    /// Create a new masked context value.
    pub fn new(
        register: impl Into<String>,
        value: u64,
        mask: u64,
        min_address: u64,
        max_address: u64,
    ) -> Self {
        Self {
            register: register.into(),
            value,
            mask,
            min_address,
            max_address,
        }
    }

    /// Get the effective value (value & mask).
    pub fn effective_value(&self) -> u64 {
        self.value & self.mask
    }

    /// Whether this range contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.min_address && addr <= self.max_address
    }
}

/// The register context manager for a trace.
///
/// Ported from Ghidra's `TraceRegisterContextManager` and related types.
#[derive(Debug, Default)]
pub struct DeepRegisterContextManager {
    /// Register values indexed by (register_name, address).
    values: BTreeMap<(String, u64), DeepRegisterValue>,
    /// Address ranges for each register.
    ranges: BTreeMap<String, Vec<(u64, u64)>>,
    /// Known register names.
    registers: BTreeSet<String>,
}

impl DeepRegisterContextManager {
    /// Create a new context manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a register value at a specific address.
    pub fn set_value(&mut self, register: &str, address: u64, value: DeepRegisterValue) {
        self.registers.insert(register.to_string());
        self.ranges
            .entry(register.to_string())
            .or_default()
            .push((address, address));
        self.values
            .insert((register.to_string(), address), value);
    }

    /// Get a register value at a specific address.
    pub fn get_value(&self, register: &str, address: u64) -> Option<&DeepRegisterValue> {
        self.values.get(&(register.to_string(), address))
    }

    /// Get all values for a register.
    pub fn get_values_for_register(&self, register: &str) -> Vec<(u64, &DeepRegisterValue)> {
        self.values
            .range((register.to_string(), 0)..=(register.to_string(), u64::MAX))
            .map(|((_, addr), val)| (*addr, val))
            .collect()
    }

    /// Get all known register names.
    pub fn register_names(&self) -> &BTreeSet<String> {
        &self.registers
    }

    /// Whether a register is known.
    pub fn has_register(&self, register: &str) -> bool {
        self.registers.contains(register)
    }

    /// Get the number of stored values.
    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// Remove all values for a register.
    pub fn clear_register(&mut self, register: &str) {
        let keys: Vec<_> = self
            .values
            .keys()
            .filter(|(r, _)| r == register)
            .cloned()
            .collect();
        for key in keys {
            self.values.remove(&key);
        }
        self.ranges.remove(register);
        self.registers.remove(register);
    }

    /// Clear all values.
    pub fn clear(&mut self) {
        self.values.clear();
        self.ranges.clear();
        self.registers.clear();
    }

    /// Whether the context is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deep_register_value_defined() {
        let val = DeepRegisterValue::defined("RAX", vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00]);
        assert!(val.is_defined());
        assert_eq!(val.defined_state(), RegisterDefinedState::Defined);
        assert_eq!(val.as_u64(), Some(0x0000000012345678));
    }

    #[test]
    fn test_deep_register_value_undefined() {
        let val = DeepRegisterValue::undefined("RAX", 8);
        assert!(!val.is_defined());
        assert_eq!(val.defined_state(), RegisterDefinedState::Unknown);
        assert!(val.as_u64().is_none());
    }

    #[test]
    fn test_deep_register_value_partial() {
        let val = DeepRegisterValue::partial(
            "RAX",
            vec![0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00],
            vec![0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        assert_eq!(val.defined_state(), RegisterDefinedState::Partial);
        assert!(val.defined_state().has_known_bits());
    }

    #[test]
    fn test_context_register_value() {
        let val = DeepRegisterValue::defined("TMode", vec![1]);
        let crv = ContextRegisterValue::new("TMode", 0x400000, 0x400FFF, val);
        assert_eq!(crv.range_length(), 0x1000);
        assert!(crv.contains(0x400500));
        assert!(!crv.contains(0x500000));
    }

    #[test]
    fn test_masked_context_value() {
        let mcv = MaskedContextValue::new("TMode", 1, 0xFF, 0x400000, 0x400FFF);
        assert_eq!(mcv.effective_value(), 1);
        assert!(mcv.contains(0x400500));
    }

    #[test]
    fn test_context_manager() {
        let mut ctx = DeepRegisterContextManager::new();
        assert!(ctx.register_names().is_empty());

        let val = DeepRegisterValue::defined("RAX", vec![0x42; 8]);
        ctx.set_value("RAX", 0x400000, val);
        assert!(ctx.has_register("RAX"));
        assert_eq!(ctx.value_count(), 1);

        let retrieved = ctx.get_value("RAX", 0x400000);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().as_u64(), Some(0x4242424242424242));
    }

    #[test]
    fn test_context_manager_multiple_values() {
        let mut ctx = DeepRegisterContextManager::new();

        ctx.set_value("RAX", 0x400000, DeepRegisterValue::defined("RAX", vec![1; 8]));
        ctx.set_value("RAX", 0x400100, DeepRegisterValue::defined("RAX", vec![2; 8]));
        ctx.set_value("RBX", 0x400000, DeepRegisterValue::defined("RBX", vec![3; 8]));

        assert_eq!(ctx.value_count(), 3);

        let rax_values = ctx.get_values_for_register("RAX");
        assert_eq!(rax_values.len(), 2);
    }

    #[test]
    fn test_context_manager_clear_register() {
        let mut ctx = DeepRegisterContextManager::new();
        ctx.set_value("RAX", 0x400000, DeepRegisterValue::defined("RAX", vec![1; 8]));
        ctx.set_value("RBX", 0x400000, DeepRegisterValue::defined("RBX", vec![2; 8]));

        ctx.clear_register("RAX");
        assert!(!ctx.has_register("RAX"));
        assert!(ctx.has_register("RBX"));
        assert_eq!(ctx.value_count(), 1);
    }

    #[test]
    fn test_context_manager_clear() {
        let mut ctx = DeepRegisterContextManager::new();
        ctx.set_value("RAX", 0, DeepRegisterValue::undefined("RAX", 8));
        ctx.clear();
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_register_defined_state() {
        assert!(RegisterDefinedState::Defined.has_known_bits());
        assert!(RegisterDefinedState::Partial.has_known_bits());
        assert!(!RegisterDefinedState::Unknown.has_known_bits());
    }

    #[test]
    fn test_deep_register_value_serde() {
        let val = DeepRegisterValue::defined("RAX", vec![0x42; 8]);
        let json = serde_json::to_string(&val).unwrap();
        let back: DeepRegisterValue = serde_json::from_str(&json).unwrap();
        assert_eq!(back.register, "RAX");
        assert!(back.is_defined());
    }
}
