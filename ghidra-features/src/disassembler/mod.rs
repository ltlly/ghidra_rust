//! Disassembler Plugin -- disassembly actions and model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.disassembler` Java package.
//!
//! Provides model-level logic for disassembly operations including
//! linear sweep, recursive descent, and disassembly at specific addresses.
//!
//! # Architecture
//!
//! - [`DisassemblerAction`] -- types of disassembly actions.
//! - [`DisassemblerModel`] -- business logic for disassembly.
//! - [`DisassemblyResult`] -- the result of a disassembly operation.
//! - [`actions`] -- disassembly action identifiers, flow overrides, dialogs, contexts, and call fixups.

pub mod actions;
pub mod address_table_analyzer;
pub mod auto_table_disassembler;
pub mod call_fixup_analyzer;
pub mod entry_point_analyzer;
pub mod processor_actions;

/// Disassembly options and configuration.
///
/// Ported from disassembly configuration classes in
/// `ghidra.app.plugin.core.disassembler`.
pub mod disassembly_options;

/// Flow override actions, dialogs, and context modification.
///
/// Ported from `ghidra.app.plugin.core.disassembler.SetFlowOverrideAction`,
/// `SetFlowOverrideDialog`, `SetLengthOverrideAction`, `ContextAction`,
/// `StaticDisassembleAction`, `RestrictedDisassembleAction`,
/// `DisassembledViewPlugin`, `ProcessorStateDialog`, and
/// `AddressTableDialog`.
pub mod flow_override;

use ghidra_core::Address;
use std::collections::{BTreeMap, HashSet};

// ============================================================================
// DisassemblerAction -- types of disassembly actions
// ============================================================================

/// The type of disassembly action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisassemblerAction {
    /// Disassemble a single instruction at the current address.
    Single,
    /// Disassemble from the current address through the selection.
    ThroughSelection,
    /// Recursive disassembly from the entry point.
    RecursiveDescent,
    /// Linear sweep from start to end address.
    LinearSweep,
}

// ============================================================================
// DisassemblyResult -- result of a disassembly operation
// ============================================================================

/// The result of a disassembly operation.
#[derive(Debug, Clone)]
pub struct DisassemblyResult {
    /// Addresses that were successfully disassembled.
    pub disassembled: Vec<Address>,
    /// Addresses that could not be disassembled (errors).
    pub failed: Vec<Address>,
    /// The number of instructions disassembled.
    pub instruction_count: usize,
    /// The number of data blocks encountered.
    pub data_count: usize,
}

impl DisassemblyResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            disassembled: Vec::new(),
            failed: Vec::new(),
            instruction_count: 0,
            data_count: 0,
        }
    }

    /// Whether any instructions were disassembled.
    pub fn has_results(&self) -> bool {
        !self.disassembled.is_empty()
    }

    /// Whether any failures occurred.
    pub fn has_failures(&self) -> bool {
        !self.failed.is_empty()
    }
}

impl Default for DisassemblyResult {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DisassemblerModel -- business logic for disassembly
// ============================================================================

/// Business logic for disassembly operations.
///
/// Tracks which addresses have been disassembled and provides methods for
/// different disassembly strategies.
#[derive(Debug)]
pub struct DisassemblerModel {
    /// Set of addresses that have been disassembled.
    disassembled: HashSet<u64>,
    /// Set of addresses that are known to be data (not code).
    data_addresses: HashSet<u64>,
    /// Instruction lengths at each disassembled address.
    instruction_lengths: BTreeMap<u64, usize>,
    /// Whether to follow fall-throughs during disassembly.
    follow_fallthroughs: bool,
    /// Whether to follow call targets during disassembly.
    follow_calls: bool,
    /// Whether to follow indirect jumps.
    follow_indirect_jumps: bool,
}

impl DisassemblerModel {
    /// Create a new disassembler model.
    pub fn new() -> Self {
        Self {
            disassembled: HashSet::new(),
            data_addresses: HashSet::new(),
            instruction_lengths: BTreeMap::new(),
            follow_fallthroughs: true,
            follow_calls: true,
            follow_indirect_jumps: false,
        }
    }

    /// Record a disassembled instruction at the given address.
    pub fn record_instruction(&mut self, address: Address, length: usize) {
        self.disassembled.insert(address.offset);
        self.instruction_lengths.insert(address.offset, length);
    }

    /// Record a data element at the given address.
    pub fn record_data(&mut self, address: Address) {
        self.data_addresses.insert(address.offset);
    }

    /// Check whether the given address has been disassembled.
    pub fn is_disassembled(&self, address: Address) -> bool {
        self.disassembled.contains(&address.offset)
    }

    /// Check whether the given address is a known data address.
    pub fn is_data(&self, address: Address) -> bool {
        self.data_addresses.contains(&address.offset)
    }

    /// Get the instruction length at the given address.
    pub fn get_instruction_length(&self, address: Address) -> Option<usize> {
        self.instruction_lengths.get(&address.offset).copied()
    }

    /// Get the next instruction address after the given address.
    pub fn get_next_instruction_address(&self, address: Address) -> Option<Address> {
        let offset = address.offset;
        if let Some(&len) = self.instruction_lengths.get(&offset) {
            let next = offset + len as u64;
            if self.disassembled.contains(&next) {
                return Some(Address::new(next));
            }
        }
        // Find the nearest disassembled address after this one
        self.instruction_lengths
            .range((offset + 1)..)
            .next()
            .map(|(&addr, _)| Address::new(addr))
    }

    /// Get the total number of disassembled instructions.
    pub fn instruction_count(&self) -> usize {
        self.disassembled.len()
    }

    /// Set whether to follow fall-throughs.
    pub fn set_follow_fallthroughs(&mut self, follow: bool) {
        self.follow_fallthroughs = follow;
    }

    /// Set whether to follow call targets.
    pub fn set_follow_calls(&mut self, follow: bool) {
        self.follow_calls = follow;
    }

    /// Set whether to follow indirect jumps.
    pub fn set_follow_indirect_jumps(&mut self, follow: bool) {
        self.follow_indirect_jumps = follow;
    }

    /// Whether fall-throughs are followed.
    pub fn follows_fallthroughs(&self) -> bool {
        self.follow_fallthroughs
    }

    /// Whether call targets are followed.
    pub fn follows_calls(&self) -> bool {
        self.follow_calls
    }

    /// Clear all recorded disassembly data.
    pub fn clear(&mut self) {
        self.disassembled.clear();
        self.data_addresses.clear();
        self.instruction_lengths.clear();
    }
}

impl Default for DisassemblerModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_check_instruction() {
        let mut model = DisassemblerModel::new();
        model.record_instruction(Address::new(0x1000), 4);
        assert!(model.is_disassembled(Address::new(0x1000)));
        assert!(!model.is_disassembled(Address::new(0x1004)));
    }

    #[test]
    fn test_get_instruction_length() {
        let mut model = DisassemblerModel::new();
        model.record_instruction(Address::new(0x1000), 3);
        assert_eq!(model.get_instruction_length(Address::new(0x1000)), Some(3));
        assert_eq!(model.get_instruction_length(Address::new(0x2000)), None);
    }

    #[test]
    fn test_get_next_instruction_address() {
        let mut model = DisassemblerModel::new();
        model.record_instruction(Address::new(0x1000), 4);
        model.record_instruction(Address::new(0x1004), 2);
        let next = model.get_next_instruction_address(Address::new(0x1000));
        assert_eq!(next, Some(Address::new(0x1004)));
    }

    #[test]
    fn test_is_data() {
        let mut model = DisassemblerModel::new();
        model.record_data(Address::new(0x2000));
        assert!(model.is_data(Address::new(0x2000)));
        assert!(!model.is_data(Address::new(0x3000)));
    }

    #[test]
    fn test_instruction_count() {
        let mut model = DisassemblerModel::new();
        model.record_instruction(Address::new(0x1000), 4);
        model.record_instruction(Address::new(0x1004), 2);
        assert_eq!(model.instruction_count(), 2);
    }

    #[test]
    fn test_follow_options() {
        let mut model = DisassemblerModel::new();
        assert!(model.follows_fallthroughs());
        model.set_follow_fallthroughs(false);
        assert!(!model.follows_fallthroughs());
        model.set_follow_calls(false);
        assert!(!model.follows_calls());
    }

    #[test]
    fn test_clear() {
        let mut model = DisassemblerModel::new();
        model.record_instruction(Address::new(0x1000), 4);
        model.record_data(Address::new(0x2000));
        model.clear();
        assert_eq!(model.instruction_count(), 0);
        assert!(!model.is_data(Address::new(0x2000)));
    }

    #[test]
    fn test_disassembly_result() {
        let mut result = DisassemblyResult::new();
        assert!(!result.has_results());
        result.disassembled.push(Address::new(0x1000));
        assert!(result.has_results());
        assert!(!result.has_failures());
        result.failed.push(Address::new(0x2000));
        assert!(result.has_failures());
    }
}
