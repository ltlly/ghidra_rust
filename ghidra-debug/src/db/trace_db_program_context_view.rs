//! Program context view for trace program views.
//!
//! Ported from Ghidra's `DBTraceProgramViewProgramContext` in
//! `ghidra.trace.database.program`. Provides register context
//! (value ranges over address ranges) for a single snapshot of a trace.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A register value applied over an address range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterValueRange {
    /// Start address offset.
    pub start: u64,
    /// End address offset.
    pub end: u64,
    /// The register name.
    pub register: String,
    /// The register value bytes.
    pub value: Vec<u8>,
    /// Whether the value has a defined mask.
    pub has_mask: bool,
    /// The mask bytes (which bits are set).
    pub mask: Vec<u8>,
}

impl RegisterValueRange {
    /// Create a new register value range.
    pub fn new(
        start: u64,
        end: u64,
        register: impl Into<String>,
        value: Vec<u8>,
    ) -> Self {
        Self {
            start,
            end,
            register: register.into(),
            value,
            has_mask: false,
            mask: Vec::new(),
        }
    }

    /// Create with a defined mask.
    pub fn with_mask(
        start: u64,
        end: u64,
        register: impl Into<String>,
        value: Vec<u8>,
        mask: Vec<u8>,
    ) -> Self {
        Self {
            start,
            end,
            register: register.into(),
            value,
            has_mask: true,
            mask,
        }
    }

    /// Check if this range contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }

    /// Get the effective value (applying mask if present).
    pub fn effective_value(&self) -> Vec<u8> {
        if !self.has_mask {
            return self.value.clone();
        }
        self.value
            .iter()
            .zip(self.mask.iter())
            .map(|(v, m)| v & m)
            .collect()
    }
}

/// Program context view for trace program views.
///
/// Provides register context values at a specific snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewProgramContext {
    /// The snap this context is for.
    pub snap: i64,
    /// Register value ranges indexed by register name.
    values: BTreeMap<String, Vec<RegisterValueRange>>,
    /// Default register values (set globally, not per-range).
    defaults: BTreeMap<String, Vec<u8>>,
}

impl ProgramViewProgramContext {
    /// Create a new program context for the given snap.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            values: BTreeMap::new(),
            defaults: BTreeMap::new(),
        }
    }

    /// Set a register value over an address range.
    pub fn set_value(&mut self, range: RegisterValueRange) {
        self.values
            .entry(range.register.clone())
            .or_default()
            .push(range);
    }

    /// Get the register value at the given address.
    pub fn get_value(&self, register: &str, address: u64) -> Option<Vec<u8>> {
        self.values.get(register).and_then(|ranges| {
            ranges
                .iter()
                .find(|r| r.contains(address))
                .map(|r| r.effective_value())
        })
    }

    /// Get all register values at the given address.
    pub fn get_all_values_at(&self, address: u64) -> Vec<(String, Vec<u8>)> {
        self.values
            .iter()
            .filter_map(|(reg, ranges)| {
                ranges
                    .iter()
                    .find(|r| r.contains(address))
                    .map(|r| (reg.clone(), r.effective_value()))
            })
            .collect()
    }

    /// Set a default register value.
    pub fn set_default(&mut self, register: impl Into<String>, value: Vec<u8>) {
        self.defaults.insert(register.into(), value);
    }

    /// Get a default register value.
    pub fn get_default(&self, register: &str) -> Option<&Vec<u8>> {
        self.defaults.get(register)
    }

    /// Get all defined register names.
    pub fn register_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.values.keys().cloned().collect();
        for name in self.defaults.keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names.sort();
        names
    }

    /// Clear all values.
    pub fn clear(&mut self) {
        self.values.clear();
        self.defaults.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_value_range_new() {
        let r = RegisterValueRange::new(0x1000, 0x1FFF, "TMode", vec![1]);
        assert!(r.contains(0x1500));
        assert!(!r.contains(0x2000));
        assert!(!r.has_mask);
    }

    #[test]
    fn test_register_value_range_with_mask() {
        let r = RegisterValueRange::with_mask(0, 0xFF, "SR", vec![0xFF], vec![0x0F]);
        assert_eq!(r.effective_value(), vec![0x0F]);
    }

    #[test]
    fn test_program_context_set_and_get() {
        let mut ctx = ProgramViewProgramContext::new(0);
        ctx.set_value(RegisterValueRange::new(0x100, 0x1FF, "TMode", vec![1]));
        assert_eq!(ctx.get_value("TMode", 0x150), Some(vec![1]));
        assert_eq!(ctx.get_value("TMode", 0x250), None);
    }

    #[test]
    fn test_program_context_default() {
        let mut ctx = ProgramViewProgramContext::new(0);
        ctx.set_default("TMode", vec![0]);
        assert_eq!(ctx.get_default("TMode"), Some(&vec![0]));
    }

    #[test]
    fn test_program_context_register_names() {
        let mut ctx = ProgramViewProgramContext::new(0);
        ctx.set_value(RegisterValueRange::new(0, 0xFF, "A", vec![1]));
        ctx.set_value(RegisterValueRange::new(0, 0xFF, "B", vec![2]));
        ctx.set_default("C", vec![3]);
        let names = ctx.register_names();
        assert_eq!(names, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_program_context_clear() {
        let mut ctx = ProgramViewProgramContext::new(0);
        ctx.set_value(RegisterValueRange::new(0, 0xFF, "X", vec![1]));
        ctx.clear();
        assert!(ctx.register_names().is_empty());
    }

    #[test]
    fn test_program_context_overlapping() {
        let mut ctx = ProgramViewProgramContext::new(0);
        ctx.set_value(RegisterValueRange::new(0x100, 0x1FF, "R", vec![10]));
        ctx.set_value(RegisterValueRange::new(0x200, 0x2FF, "R", vec![20]));
        assert_eq!(ctx.get_value("R", 0x150), Some(vec![10]));
        assert_eq!(ctx.get_value("R", 0x250), Some(vec![20]));
    }

    #[test]
    fn test_program_context_get_all_values_at() {
        let mut ctx = ProgramViewProgramContext::new(0);
        ctx.set_value(RegisterValueRange::new(0, 0xFF, "A", vec![1]));
        ctx.set_value(RegisterValueRange::new(0, 0xFF, "B", vec![2]));
        let vals = ctx.get_all_values_at(0x50);
        assert_eq!(vals.len(), 2);
    }
}
