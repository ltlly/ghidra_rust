//! Analysis state and context management for function analysis.
//!
//! Ported from `ghidra.util.state`.
//!
//! Provides [`AnalysisState`] for tracking analysis results (register values,
//! address references) during forward/backward analysis passes, and
//! [`ContextState`] for evaluator context tracking.

use std::collections::{BTreeMap, HashMap};

// ---------------------------------------------------------------------------
// AnalysisState
// ---------------------------------------------------------------------------

/// Tracks the results of a data-flow analysis pass.
///
/// Maps addresses to sets of register/value pairs and reference targets,
/// used during auto-analysis to propagate known values through code.
#[derive(Debug, Clone, Default)]
pub struct AnalysisState {
    /// Known register values at each address.
    register_values: BTreeMap<u64, HashMap<String, u64>>,
    /// Address references found during analysis.
    references: BTreeMap<u64, Vec<u64>>,
    /// Whether any new information was discovered in the latest pass.
    changed: bool,
}

impl AnalysisState {
    /// Create a new empty analysis state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a register value at an address.
    pub fn set_register_value(&mut self, address: u64, register: &str, value: u64) {
        let regs = self.register_values.entry(address).or_default();
        let key = register.to_string();
        if regs.get(&key) != Some(&value) {
            regs.insert(key, value);
            self.changed = true;
        }
    }

    /// Get the value of a register at an address.
    pub fn get_register_value(&self, address: u64, register: &str) -> Option<u64> {
        self.register_values
            .get(&address)
            .and_then(|regs| regs.get(register).copied())
    }

    /// Get all register values at an address.
    pub fn get_all_register_values(&self, address: u64) -> Option<&HashMap<String, u64>> {
        self.register_values.get(&address)
    }

    /// Record a reference from source to target.
    pub fn add_reference(&mut self, source: u64, target: u64) {
        let refs = self.references.entry(source).or_default();
        if !refs.contains(&target) {
            refs.push(target);
            self.changed = true;
        }
    }

    /// Get all reference targets from a source address.
    pub fn get_references(&self, source: u64) -> Option<&Vec<u64>> {
        self.references.get(&source)
    }

    /// Whether the state changed in the latest update.
    pub fn changed(&self) -> bool {
        self.changed
    }

    /// Clear the changed flag.
    pub fn clear_changed(&mut self) {
        self.changed = false;
    }

    /// Clear all stored state.
    pub fn clear(&mut self) {
        self.register_values.clear();
        self.references.clear();
        self.changed = false;
    }

    /// Merge another analysis state into this one.
    pub fn merge(&mut self, other: &AnalysisState) {
        for (addr, regs) in &other.register_values {
            let entry = self.register_values.entry(*addr).or_default();
            for (reg, val) in regs {
                if entry.get(reg) != Some(val) {
                    entry.insert(reg.clone(), *val);
                    self.changed = true;
                }
            }
        }
        for (src, targets) in &other.references {
            let entry = self.references.entry(*src).or_default();
            for target in targets {
                if !entry.contains(target) {
                    entry.push(*target);
                    self.changed = true;
                }
            }
        }
    }

    /// Total number of addresses with register values.
    pub fn register_value_count(&self) -> usize {
        self.register_values.len()
    }

    /// Total number of addresses with references.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }
}

// ---------------------------------------------------------------------------
// ContextState
// ---------------------------------------------------------------------------

/// Tracks the evaluation context during disassembly / analysis.
///
/// Records processor context register values at specific addresses,
/// used by the disassembler to properly decode context-dependent instructions.
#[derive(Debug, Clone, Default)]
pub struct ContextState {
    /// Context register values at each address.
    context_values: BTreeMap<u64, HashMap<String, u32>>,
}

impl ContextState {
    /// Create a new empty context state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a context register value at an address.
    pub fn set_context_register(&mut self, address: u64, register: &str, value: u32) {
        self.context_values
            .entry(address)
            .or_default()
            .insert(register.to_string(), value);
    }

    /// Get a context register value at an address.
    pub fn get_context_register(&self, address: u64, register: &str) -> Option<u32> {
        self.context_values
            .get(&address)
            .and_then(|ctx| ctx.get(register).copied())
    }

    /// Get all context registers at an address.
    pub fn get_all_context_registers(&self, address: u64) -> Option<&HashMap<String, u32>> {
        self.context_values.get(&address)
    }

    /// Remove all context values at an address.
    pub fn clear_address(&mut self, address: u64) {
        self.context_values.remove(&address);
    }

    /// Total number of addresses with context values.
    pub fn address_count(&self) -> usize {
        self.context_values.len()
    }

    /// Whether the state is empty.
    pub fn is_empty(&self) -> bool {
        self.context_values.is_empty()
    }
}

// ---------------------------------------------------------------------------
// VarnodeState
// ---------------------------------------------------------------------------

/// Represents the state of a varnode (register or memory location) during analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarnodeState {
    /// The address of the varnode.
    pub address: u64,
    /// The size of the varnode in bytes.
    pub size: u32,
    /// The known value (None if unknown).
    pub value: Option<u64>,
}

impl VarnodeState {
    /// Create a new varnode state with unknown value.
    pub fn unknown(address: u64, size: u32) -> Self {
        Self {
            address,
            size,
            value: None,
        }
    }

    /// Create a new varnode state with a known value.
    pub fn known(address: u64, size: u32, value: u64) -> Self {
        Self {
            address,
            size,
            value: Some(value),
        }
    }

    /// Whether the value is known.
    pub fn is_known(&self) -> bool {
        self.value.is_some()
    }
}

// ---------------------------------------------------------------------------
// SequenceRange
// ---------------------------------------------------------------------------

/// A contiguous range of addresses used during analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceRange {
    /// Start address (inclusive).
    pub start: u64,
    /// End address (inclusive).
    pub end: u64,
}

impl SequenceRange {
    /// Create a new address range.
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// The length of this range in bytes.
    pub fn length(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Whether this range contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr <= self.end
    }

    /// Whether this range overlaps with another.
    pub fn overlaps(&self, other: &SequenceRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_state_register_values() {
        let mut state = AnalysisState::new();
        state.set_register_value(0x1000, "RAX", 0x42);
        assert_eq!(state.get_register_value(0x1000, "RAX"), Some(0x42));
        assert_eq!(state.get_register_value(0x1000, "RBX"), None);
        assert_eq!(state.get_register_value(0x2000, "RAX"), None);
    }

    #[test]
    fn test_analysis_state_references() {
        let mut state = AnalysisState::new();
        state.add_reference(0x1000, 0x2000);
        state.add_reference(0x1000, 0x3000);
        let refs = state.get_references(0x1000).unwrap();
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&0x2000));
        assert!(refs.contains(&0x3000));
    }

    #[test]
    fn test_analysis_state_changed() {
        let mut state = AnalysisState::new();
        assert!(!state.changed());
        state.set_register_value(0x1000, "RAX", 42);
        assert!(state.changed());
        state.clear_changed();
        assert!(!state.changed());
    }

    #[test]
    fn test_analysis_state_no_duplicate_reference() {
        let mut state = AnalysisState::new();
        state.add_reference(0x1000, 0x2000);
        state.add_reference(0x1000, 0x2000);
        let refs = state.get_references(0x1000).unwrap();
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn test_analysis_state_merge() {
        let mut state1 = AnalysisState::new();
        state1.set_register_value(0x1000, "RAX", 1);

        let mut state2 = AnalysisState::new();
        state2.set_register_value(0x1000, "RBX", 2);
        state2.set_register_value(0x2000, "RAX", 3);

        state1.merge(&state2);
        assert_eq!(state1.get_register_value(0x1000, "RAX"), Some(1));
        assert_eq!(state1.get_register_value(0x1000, "RBX"), Some(2));
        assert_eq!(state1.get_register_value(0x2000, "RAX"), Some(3));
    }

    #[test]
    fn test_context_state() {
        let mut ctx = ContextState::new();
        assert!(ctx.is_empty());

        ctx.set_context_register(0x1000, "TMode", 1);
        assert_eq!(ctx.get_context_register(0x1000, "TMode"), Some(1));
        assert_eq!(ctx.address_count(), 1);

        ctx.clear_address(0x1000);
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_varnode_state() {
        let unknown = VarnodeState::unknown(0x1000, 8);
        assert!(!unknown.is_known());
        assert_eq!(unknown.size, 8);

        let known = VarnodeState::known(0x2000, 4, 0xDEADBEEF);
        assert!(known.is_known());
        assert_eq!(known.value, Some(0xDEADBEEF));
    }

    #[test]
    fn test_sequence_range() {
        let range = SequenceRange::new(0x1000, 0x1FFF);
        assert_eq!(range.length(), 0x1000);
        assert!(range.contains(0x1500));
        assert!(!range.contains(0x2000));

        let other = SequenceRange::new(0x1F00, 0x2100);
        assert!(range.overlaps(&other));

        let disjoint = SequenceRange::new(0x3000, 0x4000);
        assert!(!range.overlaps(&disjoint));
    }

    #[test]
    fn test_analysis_state_all_register_values() {
        let mut state = AnalysisState::new();
        state.set_register_value(0x1000, "RAX", 1);
        state.set_register_value(0x1000, "RBX", 2);
        state.set_register_value(0x1000, "RCX", 3);

        let all = state.get_all_register_values(0x1000).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all.get("RAX"), Some(&1));
    }
}
