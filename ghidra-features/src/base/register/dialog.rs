//! Register value dialog logic — validation and parameter management.
//!
//! Ported from `SetRegisterValueDialog` and `EditRegisterValueDialog`
//! in Ghidra's `ghidra.app.plugin.core.register`.
//!
//! This module provides [`RegisterValueDialogModel`], which manages the
//! validation logic for setting or clearing register values over an
//! address range. GUI code is not ported; only the data-model and
//! validation are provided.

use ghidra_core::addr::{Address, AddressRange, AddressSet};
use ghidra_core::program::lang::Register;

/// Validation errors for the register value dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterDialogError {
    /// No register was selected.
    NoRegisterSelected,
    /// The value field is empty or invalid.
    InvalidValue(String),
    /// The address range is empty.
    EmptyAddressRange,
    /// The selected register is not valid for the given program.
    InvalidRegister(String),
    /// The value is too large for the register's bit width.
    ValueOverflow {
        /// The register's bit width.
        bit_width: u32,
        /// The value provided.
        value: u64,
    },
}

impl std::fmt::Display for RegisterDialogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRegisterSelected => write!(f, "No register selected"),
            Self::InvalidValue(msg) => write!(f, "Invalid value: {}", msg),
            Self::EmptyAddressRange => write!(f, "Address range is empty"),
            Self::InvalidRegister(name) => write!(f, "Invalid register: {}", name),
            Self::ValueOverflow { bit_width, value } => {
                write!(
                    f,
                    "Value 0x{:x} overflows register with {} bits (max 0x{:x})",
                    value,
                    bit_width,
                    (1u128 << bit_width) - 1
                )
            }
        }
    }
}

impl std::error::Error for RegisterDialogError {}

/// Mode of the register value dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterDialogMode {
    /// Setting a register value (dialog has a value input field).
    SetValue,
    /// Clearing a register value (no value input; clears over the range).
    ClearValue,
}

/// Model for the register value dialog.
///
/// Ported from `SetRegisterValueDialog` in Java. Manages register
/// selection, value entry, and address range, validating each before
/// the dialog's OK action can proceed.
///
/// # Usage
///
/// ```ignore
/// let mut model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
/// model.set_register(eax_register);
/// model.set_value(42);
/// model.set_address_ranges(addr_set);
/// assert!(model.validate().is_ok());
/// ```
#[derive(Debug, Clone)]
pub struct RegisterValueDialogModel {
    /// Dialog mode (set or clear).
    mode: RegisterDialogMode,
    /// Currently selected register.
    register: Option<Register>,
    /// Available registers for selection.
    available_registers: Vec<Register>,
    /// The value to set (None for clear mode).
    value: Option<u64>,
    /// Address ranges where the value will be applied.
    address_ranges: AddressSet,
    /// Current status message (empty if valid).
    message: String,
}

impl RegisterValueDialogModel {
    /// Create a new dialog model in the given mode.
    pub fn new(mode: RegisterDialogMode) -> Self {
        Self {
            mode,
            register: None,
            available_registers: Vec::new(),
            value: None,
            address_ranges: AddressSet::new(),
            message: String::new(),
        }
    }

    /// Set the available registers (populated from the program).
    pub fn set_available_registers(&mut self, registers: Vec<Register>) {
        self.available_registers = registers;
    }

    /// Select a register by name.
    pub fn set_register(&mut self, register: Register) {
        self.register = Some(register);
    }

    /// Get the selected register.
    pub fn register(&self) -> Option<&Register> {
        self.register.as_ref()
    }

    /// Set the value to apply (for set-value mode).
    pub fn set_value(&mut self, value: u64) {
        self.value = Some(value);
    }

    /// Get the current value.
    pub fn value(&self) -> Option<u64> {
        self.value
    }

    /// Set the address ranges.
    pub fn set_address_ranges(&mut self, ranges: AddressSet) {
        self.address_ranges = ranges;
    }

    /// Get the address ranges.
    pub fn address_ranges(&self) -> &AddressSet {
        &self.address_ranges
    }

    /// Get the dialog mode.
    pub fn mode(&self) -> RegisterDialogMode {
        self.mode
    }

    /// Get the current status message (empty if valid).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether the OK button should be enabled.
    ///
    /// Returns `true` if all inputs are valid.
    pub fn is_ok_enabled(&self) -> bool {
        self.validate().is_ok()
    }

    /// Validate all inputs.
    ///
    /// Returns `Ok(())` if valid, or the specific error.
    pub fn validate(&self) -> Result<(), RegisterDialogError> {
        // Register must be selected
        let reg = self
            .register
            .as_ref()
            .ok_or(RegisterDialogError::NoRegisterSelected)?;

        // In set mode, value must be provided
        if self.mode == RegisterDialogMode::SetValue {
            let val = self
                .value
                .ok_or_else(|| RegisterDialogError::InvalidValue("No value entered".into()))?;

            // Check value fits in register
            let max_value = if reg.bit_length >= 64 {
                u64::MAX
            } else {
                (1u64 << reg.bit_length) - 1
            };
            if val > max_value {
                return Err(RegisterDialogError::ValueOverflow {
                    bit_width: reg.bit_length,
                    value: val,
                });
            }
        }

        // Address range must be non-empty
        if self.address_ranges.is_empty() {
            return Err(RegisterDialogError::EmptyAddressRange);
        }

        Ok(())
    }

    /// Get a summary of the dialog state (for display).
    pub fn summary(&self) -> String {
        let mode_str = match self.mode {
            RegisterDialogMode::SetValue => "Set",
            RegisterDialogMode::ClearValue => "Clear",
        };
        let reg_str = self
            .register
            .as_ref()
            .map(|r| r.name.as_str())
            .unwrap_or("(none)");
        let val_str = self
            .value
            .map(|v| format!("0x{:x}", v))
            .unwrap_or_else(|| "(clear)".into());
        format!("{} {} = {} over {} range(s)", mode_str, reg_str, val_str, self.address_ranges.num_addresses())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::program::lang::RegisterTypeFlags;
    use std::collections::HashSet;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_register(name: &str, bits: u32) -> Register {
        Register {
            name: name.to_string(),
            description: String::new(),
            group: None,
            parent: None,
            bit_length: bits,
            address: addr(0),
            num_bytes: (bits as usize + 7) / 8,
            least_significant_bit: 0,
            big_endian: false,
            type_flags: RegisterTypeFlags::default(),
            aliases: HashSet::new(),
            child_registers: Vec::new(),
            base_register: None,
            least_significant_bit_in_base: 0,
            lane_sizes: 0,
        }
    }

    fn make_addr_set(start: u64, end: u64) -> AddressSet {
        let mut set = AddressSet::new();
        set.add_range(addr(start), addr(end));
        set
    }

    #[test]
    fn test_new_set_mode() {
        let model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        assert_eq!(model.mode(), RegisterDialogMode::SetValue);
        assert!(model.register().is_none());
        assert!(model.value().is_none());
    }

    #[test]
    fn test_new_clear_mode() {
        let model = RegisterValueDialogModel::new(RegisterDialogMode::ClearValue);
        assert_eq!(model.mode(), RegisterDialogMode::ClearValue);
    }

    #[test]
    fn test_validate_no_register() {
        let model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        assert_eq!(
            model.validate().unwrap_err(),
            RegisterDialogError::NoRegisterSelected
        );
    }

    #[test]
    fn test_validate_no_value_in_set_mode() {
        let mut model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        model.set_register(make_register("EAX", 32));
        model.set_address_ranges(make_addr_set(0x1000, 0x1fff));
        assert!(matches!(
            model.validate().unwrap_err(),
            RegisterDialogError::InvalidValue(_)
        ));
    }

    #[test]
    fn test_validate_value_overflow() {
        let mut model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        model.set_register(make_register("AL", 8));
        model.set_value(0x1FF); // > 255
        model.set_address_ranges(make_addr_set(0x1000, 0x1fff));
        assert!(matches!(
            model.validate().unwrap_err(),
            RegisterDialogError::ValueOverflow { bit_width: 8, value: 0x1FF }
        ));
    }

    #[test]
    fn test_validate_empty_address_range() {
        let mut model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        model.set_register(make_register("EAX", 32));
        model.set_value(42);
        assert_eq!(
            model.validate().unwrap_err(),
            RegisterDialogError::EmptyAddressRange
        );
    }

    #[test]
    fn test_validate_success_set_mode() {
        let mut model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        model.set_register(make_register("EAX", 32));
        model.set_value(42);
        model.set_address_ranges(make_addr_set(0x1000, 0x1fff));
        assert!(model.validate().is_ok());
        assert!(model.is_ok_enabled());
    }

    #[test]
    fn test_validate_success_clear_mode() {
        let mut model = RegisterValueDialogModel::new(RegisterDialogMode::ClearValue);
        model.set_register(make_register("EAX", 32));
        model.set_address_ranges(make_addr_set(0x1000, 0x1fff));
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_validate_64bit_register_accepts_max() {
        let mut model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        model.set_register(make_register("RAX", 64));
        model.set_value(u64::MAX);
        model.set_address_ranges(make_addr_set(0x1000, 0x1fff));
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_summary() {
        let mut model = RegisterValueDialogModel::new(RegisterDialogMode::SetValue);
        model.set_register(make_register("EAX", 32));
        model.set_value(0xFF);
        model.set_address_ranges(make_addr_set(0x1000, 0x1fff));
        let summary = model.summary();
        assert!(summary.contains("Set"));
        assert!(summary.contains("EAX"));
        assert!(summary.contains("0xff"));
    }

    #[test]
    fn test_error_display() {
        let err = RegisterDialogError::ValueOverflow {
            bit_width: 8,
            value: 0x1FF,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("8 bits"));
        assert!(msg.contains("0x1ff"));
    }

    #[test]
    fn test_error_no_register() {
        let err = RegisterDialogError::NoRegisterSelected;
        assert!(!format!("{}", err).is_empty());
    }

    #[test]
    fn test_error_empty_range() {
        let err = RegisterDialogError::EmptyAddressRange;
        assert!(!format!("{}", err).is_empty());
    }
}
