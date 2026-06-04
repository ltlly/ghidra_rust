//! Reference editor panel states for memory, stack, register, and external
//! reference types.
//!
//! Ported from `EditReferencePanel` (abstract base) and its four concrete
//! subclasses. In the Java version these are `JPanel` subclasses with Swing
//! widgets; here we model their *state* as plain Rust structs, since the UI
//! layer is separate.

use ghidra_core::addr::Address;
use ghidra_core::symbol::{DataRefType, RefType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The abstract interface for all reference edit panels.
///
/// Each panel is responsible for initializing its state for a given code unit
/// and operand, validating the current state, and producing the reference
/// change that the user wants to apply.
pub trait ReferenceEditPanel: fmt::Debug {
    /// Returns the name of this panel ("MEM", "STACK", "REG", "EXT").
    fn name(&self) -> &str;

    /// Returns `true` if the current state is valid for applying.
    fn is_valid_context(&self) -> bool;

    /// Prepare the panel for editing an existing reference.
    ///
    /// Returns `true` if the panel can handle this reference.
    fn initialize_for_edit(&mut self, to_addr: Address, ref_type: RefType) -> bool;

    /// Prepare the panel for adding a new reference.
    ///
    /// Returns `true` if the panel can add a reference for the given operand.
    fn initialize_for_add(&mut self, op_index: i32) -> bool;

    /// Attempt to switch the current operand index.
    ///
    /// Returns `true` if the new operand is supported.
    fn set_op_index(&mut self, op_index: i32) -> bool;

    /// Cleanup any program resources held.
    fn cleanup(&mut self);
}

// ============================================================================
// MemoryRefState
// ============================================================================

/// State for the memory reference editor panel.
///
/// Corresponds to `EditMemoryReferencePanel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRefState {
    /// The destination address.
    pub to_address: Option<Address>,
    /// The base address (for offset references).
    pub base_address: Option<Address>,
    /// Whether the offset field is enabled.
    pub offset_enabled: bool,
    /// The offset value (when offset_enabled is true).
    pub offset: i64,
    /// The selected reference type.
    pub ref_type: RefType,
    /// Whether the state is valid for applying.
    pub valid: bool,
    /// The source operand index (for add mode).
    pub op_index: i32,
    /// Address history for the current program (most recent first).
    pub address_history: Vec<Address>,
    /// Whether to include other overlay spaces.
    pub include_other_overlays: bool,
}

impl Default for MemoryRefState {
    fn default() -> Self {
        Self {
            to_address: None,
            base_address: None,
            offset_enabled: false,
            offset: 0,
            ref_type: RefType::Data(DataRefType::Data),
            valid: false,
            op_index: -1,
            address_history: Vec::new(),
            include_other_overlays: false,
        }
    }
}

impl MemoryRefState {
    /// Maximum number of address history entries.
    pub const MAX_HISTORY_LENGTH: usize = 10;

    /// Add an address to the history (most recent first, deduplicating).
    pub fn add_history_address(&mut self, addr: Address) {
        self.address_history.retain(|a| *a != addr);
        self.address_history.insert(0, addr);
        if self.address_history.len() > Self::MAX_HISTORY_LENGTH {
            self.address_history.truncate(Self::MAX_HISTORY_LENGTH);
        }
    }

    /// Returns the most recent history address, or None.
    pub fn last_history_address(&self) -> Option<Address> {
        self.address_history.first().copied()
    }

    /// Returns the effective destination address, applying the offset if
    /// enabled.
    pub fn effective_to_address(&self) -> Option<Address> {
        let base = if self.offset_enabled {
            self.base_address.or(self.to_address)?
        } else {
            self.to_address?
        };
        Some(base.add(self.offset as u64))
    }

    /// Validate the state: returns an error message if invalid, None if OK.
    pub fn validate(&self) -> Option<String> {
        if self.to_address.is_none() {
            return Some("No destination address specified.".to_string());
        }
        let addr = self.to_address.unwrap();
        if !addr.is_memory_address() {
            return Some("Invalid memory address specified.".to_string());
        }
        None
    }
}

impl ReferenceEditPanel for MemoryRefState {
    fn name(&self) -> &str {
        "MEM"
    }

    fn is_valid_context(&self) -> bool {
        self.valid
    }

    fn initialize_for_edit(&mut self, to_addr: Address, ref_type: RefType) -> bool {
        self.to_address = Some(to_addr);
        self.ref_type = ref_type;
        self.offset_enabled = false;
        self.offset = 0;
        self.valid = true;
        true
    }

    fn initialize_for_add(&mut self, op_index: i32) -> bool {
        self.op_index = op_index;
        self.valid = true;
        true // Memory references are always permitted
    }

    fn set_op_index(&mut self, op_index: i32) -> bool {
        self.op_index = op_index;
        self.valid = true;
        true
    }

    fn cleanup(&mut self) {
        self.valid = false;
        self.to_address = None;
    }
}

// ============================================================================
// StackRefState
// ============================================================================

/// State for the stack reference editor panel.
///
/// Corresponds to `EditStackReferencePanel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackRefState {
    /// The stack offset.
    pub stack_offset: i32,
    /// The selected reference type.
    pub ref_type: RefType,
    /// Whether this is a valid stack reference context.
    pub valid_stack_ref: bool,
    /// Whether the state is valid for applying.
    pub valid: bool,
    /// The source operand index.
    pub op_index: i32,
    /// Whether the source is within a function.
    pub in_function: bool,
}

impl Default for StackRefState {
    fn default() -> Self {
        Self {
            stack_offset: 0,
            ref_type: RefType::Data(DataRefType::Read),
            valid_stack_ref: false,
            valid: false,
            op_index: -1,
            in_function: false,
        }
    }
}

impl StackRefState {
    /// Returns whether the current stack offset is valid.
    pub fn is_valid_stack_ref(&self) -> bool {
        self.valid_stack_ref
    }

    /// Format a signed offset as hex string (e.g., "+0x8" or "-0x10").
    pub fn format_offset(val: i64) -> String {
        let neg = val < 0;
        let abs = if neg { -val } else { val };
        format!("{}0x{:x}", if neg { "-" } else { "+" }, abs)
    }
}

impl ReferenceEditPanel for StackRefState {
    fn name(&self) -> &str {
        "STACK"
    }

    fn is_valid_context(&self) -> bool {
        self.valid
    }

    fn initialize_for_edit(&mut self, _to_addr: Address, ref_type: RefType) -> bool {
        self.ref_type = ref_type;
        self.valid = true;
        true
    }

    fn initialize_for_add(&mut self, op_index: i32) -> bool {
        self.op_index = op_index;
        // Stack references are not valid for the mnemonic operand
        if op_index == MNEMONIC {
            self.valid = false;
            return false;
        }
        if !self.in_function {
            self.valid = false;
            return false;
        }
        self.valid = true;
        true
    }

    fn set_op_index(&mut self, op_index: i32) -> bool {
        self.op_index = op_index;
        if op_index == MNEMONIC {
            self.valid = false;
            return false;
        }
        self.valid = true;
        true
    }

    fn cleanup(&mut self) {
        self.valid = false;
    }
}

use ghidra_core::symbol::MNEMONIC;

// ============================================================================
// RegisterRefState
// ============================================================================

/// State for the register reference editor panel.
///
/// Corresponds to `EditRegisterReferencePanel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRefState {
    /// The selected register address (in register space).
    pub register_addr: Option<Address>,
    /// The selected reference type.
    pub ref_type: RefType,
    /// Whether the state is valid for applying.
    pub valid: bool,
    /// The source operand index.
    pub op_index: i32,
    /// Whether the source is within a function.
    pub in_function: bool,
}

impl Default for RegisterRefState {
    fn default() -> Self {
        Self {
            register_addr: None,
            ref_type: RefType::Data(DataRefType::Write),
            valid: false,
            op_index: -1,
            in_function: false,
        }
    }
}

impl ReferenceEditPanel for RegisterRefState {
    fn name(&self) -> &str {
        "REG"
    }

    fn is_valid_context(&self) -> bool {
        self.valid
    }

    fn initialize_for_edit(&mut self, to_addr: Address, ref_type: RefType) -> bool {
        self.register_addr = Some(to_addr);
        self.ref_type = ref_type;
        self.valid = true;
        true
    }

    fn initialize_for_add(&mut self, op_index: i32) -> bool {
        self.op_index = op_index;
        if !self.in_function {
            self.valid = false;
            return false;
        }
        self.valid = true;
        true
    }

    fn set_op_index(&mut self, op_index: i32) -> bool {
        self.op_index = op_index;
        if !self.in_function {
            self.valid = false;
            return false;
        }
        self.valid = true;
        true
    }

    fn cleanup(&mut self) {
        self.valid = false;
        self.register_addr = None;
    }
}

// ============================================================================
// ExternalRefState
// ============================================================================

/// State for the external reference editor panel.
///
/// Corresponds to `EditExternalReferencePanel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalRefState {
    /// The external library name.
    pub lib_name: String,
    /// The library program file path.
    pub lib_path: Option<String>,
    /// The label within the external library.
    pub label: Option<String>,
    /// The external address.
    pub ext_addr: Option<Address>,
    /// The selected reference type.
    pub ref_type: RefType,
    /// Whether the state is valid for applying.
    pub valid: bool,
    /// The source operand index.
    pub op_index: i32,
    /// List of known external library names.
    pub known_libraries: Vec<String>,
}

impl Default for ExternalRefState {
    fn default() -> Self {
        Self {
            lib_name: String::new(),
            lib_path: None,
            label: None,
            ext_addr: None,
            ref_type: RefType::Data(DataRefType::Data),
            valid: false,
            op_index: -1,
            known_libraries: Vec::new(),
        }
    }
}

impl ExternalRefState {
    /// Returns `true` if the library name has been entered.
    pub fn has_lib_name(&self) -> bool {
        !self.lib_name.trim().is_empty()
    }

    /// Returns `true` if either a label or address has been specified.
    pub fn has_reference_data(&self) -> bool {
        self.label.is_some() || self.ext_addr.is_some()
    }

    /// Validate the state: returns an error message if invalid, None if OK.
    pub fn validate(&self) -> Option<String> {
        if !self.has_lib_name() {
            return Some("An external program 'Name' must be specified.".to_string());
        }
        if self.ext_addr.is_none()
            && self
                .label
                .as_ref()
                .map_or(true, |l| l.trim().is_empty())
        {
            return Some(
                "Either (or both) an external 'Label' and/or 'Address' must be specified."
                    .to_string(),
            );
        }
        None
    }
}

impl ReferenceEditPanel for ExternalRefState {
    fn name(&self) -> &str {
        "EXT"
    }

    fn is_valid_context(&self) -> bool {
        self.valid
    }

    fn initialize_for_edit(&mut self, to_addr: Address, ref_type: RefType) -> bool {
        self.ext_addr = Some(to_addr);
        self.ref_type = ref_type;
        self.valid = true;
        true
    }

    fn initialize_for_add(&mut self, op_index: i32) -> bool {
        self.op_index = op_index;
        // External references are not valid for the mnemonic operand
        if op_index == MNEMONIC {
            self.valid = false;
            return false;
        }
        self.valid = true;
        true
    }

    fn set_op_index(&mut self, op_index: i32) -> bool {
        self.op_index = op_index;
        if op_index == MNEMONIC {
            self.valid = false;
            return false;
        }
        self.valid = true;
        true
    }

    fn cleanup(&mut self) {
        self.valid = false;
        self.lib_name.clear();
        self.lib_path = None;
        self.label = None;
        self.ext_addr = None;
    }
}

/// Flexible decimal/hex number parsing from user input.
///
/// Supports optional sign prefix (+/-) and "0x" hex prefix.
/// Corresponds to `EditReferencePanel.parseLongInput()`.
pub fn parse_long_input(s: &str) -> Result<i64, String> {
    let trimmed = s.trim().to_lowercase();
    if trimmed.is_empty() {
        return Err("Empty input".to_string());
    }

    let (neg, rest) = if let Some(r) = trimmed.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix('+') {
        (false, r)
    } else {
        (false, trimmed.as_str())
    };

    let value = if let Some(hex) = rest.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())?
    } else {
        rest.parse::<u64>().map_err(|e| format!("Invalid number: {}", e))?
    };

    Ok(if neg {
        -(value as i64)
    } else {
        value as i64
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_ref_state_default() {
        let state = MemoryRefState::default();
        assert!(!state.is_valid_context());
        assert_eq!(state.name(), "MEM");
    }

    #[test]
    fn test_memory_ref_state_initialize_for_edit() {
        let mut state = MemoryRefState::default();
        assert!(state.initialize_for_edit(Address::new(0x2000), RefType::Data(DataRefType::Data)));
        assert!(state.is_valid_context());
        assert_eq!(state.to_address, Some(Address::new(0x2000)));
    }

    #[test]
    fn test_memory_ref_state_history() {
        let mut state = MemoryRefState::default();
        state.add_history_address(Address::new(0x1000));
        state.add_history_address(Address::new(0x2000));
        state.add_history_address(Address::new(0x1000)); // dedup
        assert_eq!(state.address_history.len(), 2);
        assert_eq!(state.last_history_address(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_memory_ref_state_effective_address() {
        let mut state = MemoryRefState::default();
        state.to_address = Some(Address::new(0x1000));
        state.offset_enabled = true;
        state.offset = 0x10;
        assert_eq!(state.effective_to_address(), Some(Address::new(0x1010)));
    }

    #[test]
    fn test_memory_ref_state_validate_no_addr() {
        let state = MemoryRefState::default();
        assert!(state.validate().is_some());
    }

    #[test]
    fn test_stack_ref_state_format_offset() {
        assert_eq!(StackRefState::format_offset(8), "+0x8");
        assert_eq!(StackRefState::format_offset(-16), "-0x10");
        assert_eq!(StackRefState::format_offset(0), "+0x0");
    }

    #[test]
    fn test_stack_ref_state_add_mnemonic_rejected() {
        let mut state = StackRefState::default();
        assert!(!state.initialize_for_add(MNEMONIC));
        assert!(!state.is_valid_context());
    }

    #[test]
    fn test_register_ref_state_needs_function() {
        let mut state = RegisterRefState::default();
        state.in_function = false;
        assert!(!state.initialize_for_add(0));
    }

    #[test]
    fn test_external_ref_state_validate() {
        let mut state = ExternalRefState::default();
        state.lib_name = "libc.so".to_string();
        // No label or address
        assert!(state.validate().is_some());
        state.label = Some("printf".to_string());
        assert!(state.validate().is_none());
    }

    #[test]
    fn test_external_ref_state_add_mnemonic_rejected() {
        let mut state = ExternalRefState::default();
        assert!(!state.initialize_for_add(MNEMONIC));
    }

    #[test]
    fn test_parse_long_input_hex() {
        assert_eq!(parse_long_input("0xFF").unwrap(), 255);
    }

    #[test]
    fn test_parse_long_input_negative() {
        assert_eq!(parse_long_input("-0x10").unwrap(), -16);
    }

    #[test]
    fn test_parse_long_input_decimal() {
        assert_eq!(parse_long_input("42").unwrap(), 42);
    }

    #[test]
    fn test_parse_long_input_positive_sign() {
        assert_eq!(parse_long_input("+0x8").unwrap(), 8);
    }

    #[test]
    fn test_parse_long_input_empty() {
        assert!(parse_long_input("").is_err());
    }

    #[test]
    fn test_parse_long_input_invalid() {
        assert!(parse_long_input("not_a_number").is_err());
    }

    #[test]
    fn test_memory_ref_state_cleanup() {
        let mut state = MemoryRefState::default();
        state.initialize_for_edit(Address::new(0x2000), RefType::Data(DataRefType::Data));
        assert!(state.is_valid_context());
        state.cleanup();
        assert!(!state.is_valid_context());
        assert!(state.to_address.is_none());
    }

    #[test]
    fn test_external_ref_state_has_lib_name() {
        let mut state = ExternalRefState::default();
        assert!(!state.has_lib_name());
        state.lib_name = "  ".to_string();
        assert!(!state.has_lib_name());
        state.lib_name = "libc".to_string();
        assert!(state.has_lib_name());
    }
}
