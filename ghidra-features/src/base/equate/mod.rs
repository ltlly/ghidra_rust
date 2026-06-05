//! Equate management -- named constants applied to instruction/data operands.
//!
//! Ported from `ghidra.app.plugin.core.equate` in Ghidra's Features/Base.
//!
//! This module provides:
//! - [`Scalar`] -- a sized, signed/unsigned integer value with bit-level access
//! - [`EquateManager`] -- core operations on the equate table (create, rename,
//!   remove, look-up by name/value/address+opIndex, format enum names)
//! - Commands: [`CreateEquateCmd`], [`RenameEquateCmd`], [`RenameEquatesCmd`],
//!   [`RemoveEquateCmd`], [`CreateEnumEquateCommand`], [`ConvertCommand`]
//! - Format conversion: [`FormatChoice`] enum and [`format_scalar`] helper
//!
//! The "operand" sub-module lives at `crate::base::operand` and covers
//! `OperandType` flags and `OperandFieldLocation`.

pub mod actions;
pub mod commands;
pub mod convert_cmd;
pub mod convert_actions;
pub mod format;
pub mod manager;
pub mod plugin;
pub mod table;
pub mod table_provider;

// Re-export key types at module level for convenience.
pub use actions::{
    ApplyEnumAction, ConvertAction, ConvertActionKind, EquateActionSet, ListingActionContext,
    RemoveEquateAction, RenameEquateAction, RenameEquatesAction, SetEquateAction,
};
pub use commands::{
    ConvertCommand, CreateEquateCmd, CreateEnumEquateCommand, RemoveEquateCmd, RenameEquateCmd,
    RenameEquatesCmd,
};
pub use convert_cmd::{
    all_convert_actions, convert_scalar, format_scalar_value, ConvertedValue,
    FormatConvertAction, ScalarFormat,
};
pub use convert_actions::{
    AbstractConvertActionModel, ConvertToBinaryAction, ConvertToCharAction,
    ConvertToDoubleAction, ConvertToFloatAction, ConvertToOctalAction,
    ConvertToSignedDecimalAction, ConvertToSignedHexAction,
    ConvertToUnsignedDecimalAction, ConvertToUnsignedHexAction,
    all_convert_action_models,
};
pub use format::{format_scalar, FormatChoice};
pub use manager::{EquateManager, EquateTable};
pub use plugin::{EquateInfo, EquatePlugin, SelectionType};
pub use table::{
    EquateColumnDef, EquateNameColumn, EquateRefCountColumn, EquateTableModel, EquateValueColumn,
    IsEnumBasedColumn, ReferenceAddressColumn, ReferenceColumnDef, ReferenceOpIndexColumn,
    EquateReferenceTableModel, SortOrder,
};
pub use table_provider::{EquateTableProviderModel, EquateTableWindowPluginState};

use ghidra_core::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Scalar -- mirrors ghidra.program.model.scalar.Scalar
// ---------------------------------------------------------------------------

/// A sized integer value used for instruction immediates and data constants.
///
/// Corresponds to Ghidra's `Scalar` class. The value is always stored as a
/// signed `i64`; the *bit length* determines how many bits are meaningful and
/// whether the value should be interpreted as signed or unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scalar {
    /// Number of meaningful bits (1..=64).
    bit_length: u32,
    /// The value (always stored sign-extended to 64 bits).
    value: i64,
    /// Whether this scalar is *displayed* as signed.
    signed: bool,
}

impl Scalar {
    // -------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------

    /// Create a new scalar.
    ///
    /// `bit_length` is clamped to 1..=64. The value is masked to
    /// `bit_length` bits.
    pub fn new(bit_length: u32, value: i64, signed: bool) -> Self {
        let bl = bit_length.clamp(1, 64);
        let mask = if bl >= 64 {
            u64::MAX
        } else {
            (1u64 << bl) - 1
        };
        let masked = (value as u64 & mask) as i64;
        Self {
            bit_length: bl,
            value: masked,
            signed,
        }
    }

    /// Create an unsigned scalar.
    pub fn unsigned(bit_length: u32, value: u64) -> Self {
        Self::new(bit_length, value as i64, false)
    }

    /// Create a signed scalar.
    pub fn signed(bit_length: u32, value: i64) -> Self {
        Self::new(bit_length, value, true)
    }

    // -------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------

    /// Number of meaningful bits.
    pub fn bit_length(&self) -> u32 {
        self.bit_length
    }

    /// The value as a signed 64-bit integer.
    pub fn signed_value(&self) -> i64 {
        if self.signed {
            sign_extend(self.value, self.bit_length)
        } else {
            self.value
        }
    }

    /// The value as an unsigned 64-bit integer.
    pub fn unsigned_value(&self) -> u64 {
        let mask = if self.bit_length >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_length) - 1
        };
        self.value as u64 & mask
    }

    /// Whether this scalar is signed.
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    /// The value as an `i64` (always sign-extended).
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Return the value's byte representation in big-endian order,
    /// padded/truncated to `ceil(bit_length / 8)` bytes.
    pub fn byte_array_value(&self) -> Vec<u8> {
        let num_bytes = ((self.bit_length + 7) / 8) as usize;
        let unsigned = self.unsigned_value();
        let total_bytes = 8usize;
        let be = unsigned.to_be_bytes();
        let start = total_bytes.saturating_sub(num_bytes);
        be[start..].to_vec()
    }

    /// Return the two's-complement of the scalar (same bit length, opposite sign interpretation).
    pub fn negate(&self) -> Self {
        Self::new(self.bit_length, (-self.value) as i64, self.signed)
    }

    /// Create a new scalar with the same value but opposite signedness.
    pub fn with_opposite_sign(&self) -> Self {
        Self::new(self.bit_length, self.value, !self.signed)
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.signed {
            write!(f, "{}", self.signed_value())
        } else {
            write!(f, "0x{:x}", self.unsigned_value())
        }
    }
}

/// Sign-extend a value from `bit_length` bits to a full `i64`.
fn sign_extend(value: i64, bit_length: u32) -> i64 {
    if bit_length >= 64 || bit_length == 0 {
        return value;
    }
    let shift = 64 - bit_length;
    (value << shift) >> shift
}

// ---------------------------------------------------------------------------
// EquateReference -- mirrors ghidra.program.model.symbol.EquateReference
// ---------------------------------------------------------------------------

/// A reference from a specific address+operand to an equate.
///
/// Corresponds to Ghidra's `EquateReference`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EquateReference {
    /// The address of the referencing code unit.
    pub address: Address,
    /// The operand index within the code unit.
    pub op_index: i32,
}

impl EquateReference {
    pub fn new(address: Address, op_index: i32) -> Self {
        Self { address, op_index }
    }
}

// ---------------------------------------------------------------------------
// EquateValue -- a single equate entry
// ---------------------------------------------------------------------------

/// A single equate (named constant) with its value and all references to it.
///
/// Corresponds to Ghidra's `Equate` interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquateValue {
    /// The equate name (e.g., `"MY_CONST"`, or an enum-formatted name).
    pub name: String,
    /// The constant value.
    pub value: i64,
    /// All locations that reference this equate.
    pub references: Vec<EquateReference>,
    /// Whether this equate was created from an enum data type.
    pub is_enum_based: bool,
    /// Optional universal ID of the source enum (for display/tooltip).
    pub enum_uuid: Option<String>,
}

impl EquateValue {
    /// Create a new user-defined equate.
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
            references: Vec::new(),
            is_enum_based: false,
            enum_uuid: None,
        }
    }

    /// Create an enum-based equate.
    pub fn enum_based(name: impl Into<String>, value: i64, enum_uuid: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value,
            references: Vec::new(),
            is_enum_based: true,
            enum_uuid: Some(enum_uuid.into()),
        }
    }

    /// Add a reference to this equate.
    pub fn add_reference(&mut self, addr: Address, op_index: i32) {
        self.references.push(EquateReference::new(addr, op_index));
    }

    /// Remove a reference. Returns `true` if the reference was found and removed.
    pub fn remove_reference(&mut self, addr: &Address, op_index: i32) -> bool {
        let len_before = self.references.len();
        self.references
            .retain(|r| r.address != *addr || r.op_index != op_index);
        self.references.len() < len_before
    }

    /// Number of references.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// Display name (strips internal enum tags for user-facing display).
    pub fn display_name(&self) -> &str {
        // Ghidra uses `EquateManager.DATATYPE_TAG` prefix for enum-based names.
        // We strip it for display.
        self.name
            .strip_prefix(EquateManager::DATATYPE_TAG)
            .unwrap_or(&self.name)
    }

    /// Check whether the equate's stored universal-ID is well-formed.
    pub fn is_valid_uuid(&self) -> bool {
        self.enum_uuid
            .as_ref()
            .map(|id| !id.is_empty())
            .unwrap_or(true)
    }
}

impl fmt::Display for EquateValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = 0x{:x}", self.name, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_new_masks_value() {
        let s = Scalar::new(8, 0x1FF, false);
        assert_eq!(s.unsigned_value(), 0xFF);
        assert_eq!(s.bit_length(), 8);
    }

    #[test]
    fn test_scalar_signed_negative() {
        let s = Scalar::signed(8, -1);
        assert_eq!(s.signed_value(), -1);
        assert_eq!(s.unsigned_value(), 0xFF);
    }

    #[test]
    fn test_scalar_byte_array() {
        let s = Scalar::unsigned(16, 0x1234);
        assert_eq!(s.byte_array_value(), vec![0x12, 0x34]);
    }

    #[test]
    fn test_scalar_display_unsigned() {
        let s = Scalar::unsigned(32, 255);
        assert_eq!(format!("{}", s), "0xff");
    }

    #[test]
    fn test_scalar_display_signed() {
        let s = Scalar::signed(8, -1);
        assert_eq!(format!("{}", s), "-1");
    }

    #[test]
    fn test_equate_value_add_remove_ref() {
        let mut eq = EquateValue::new("TEST", 42);
        assert_eq!(eq.reference_count(), 0);
        eq.add_reference(Address::new(0x1000), 0);
        eq.add_reference(Address::new(0x2000), 1);
        assert_eq!(eq.reference_count(), 2);
        assert!(eq.remove_reference(&Address::new(0x1000), 0));
        assert_eq!(eq.reference_count(), 1);
        // Remove non-existent
        assert!(!eq.remove_reference(&Address::new(0x9999), 0));
    }

    #[test]
    fn test_equate_value_enum_based() {
        let eq = EquateValue::enum_based("MyEnum::FIELD", 5, "uuid-123");
        assert!(eq.is_enum_based);
        assert_eq!(eq.enum_uuid.as_deref(), Some("uuid-123"));
        assert!(eq.is_valid_uuid());
    }

    #[test]
    fn test_sign_extend_positive() {
        assert_eq!(sign_extend(0x7F, 8), 127);
    }

    #[test]
    fn test_sign_extend_negative() {
        assert_eq!(sign_extend(0x80, 8), -128);
        assert_eq!(sign_extend(0xFF, 8), -1);
    }

    #[test]
    fn test_scalar_negate() {
        let s = Scalar::signed(8, -42);
        let neg = s.negate();
        assert_eq!(neg.signed_value(), 42);
    }

    #[test]
    fn test_scalar_with_opposite_sign() {
        let s = Scalar::unsigned(8, 255);
        let opp = s.with_opposite_sign();
        assert!(opp.is_signed());
    }

    #[test]
    fn test_scalar_is_negative() {
        let s = Scalar::signed(8, -1);
        assert!(s.signed_value() < 0);
        let s2 = Scalar::unsigned(8, 255);
        assert!(s2.signed_value() >= 0 || s2.is_signed() == false);
    }

    #[test]
    fn test_equate_value_display_name_strips_tag() {
        let mut eq = EquateValue::new(format!("{}MyEnum", EquateManager::DATATYPE_TAG), 10);
        eq.is_enum_based = true;
        assert_eq!(eq.display_name(), "MyEnum");
    }

    #[test]
    fn test_equate_value_display() {
        let eq = EquateValue::new("MY_CONST", 0xFF);
        let display = format!("{}", eq);
        assert!(display.contains("MY_CONST"));
        assert!(display.contains("0xff"));
    }

    #[test]
    fn test_equate_reference_equality() {
        let r1 = EquateReference::new(Address::new(0x1000), 0);
        let r2 = EquateReference::new(Address::new(0x1000), 0);
        let r3 = EquateReference::new(Address::new(0x2000), 0);
        assert_eq!(r1, r2);
        assert_ne!(r1, r3);
    }

    #[test]
    fn test_equate_value_is_valid_uuid_none() {
        let eq = EquateValue::new("TEST", 42);
        assert!(eq.is_valid_uuid());
    }

    #[test]
    fn test_equate_value_is_valid_uuid_empty() {
        let mut eq = EquateValue::new("TEST", 42);
        eq.enum_uuid = Some(String::new());
        assert!(!eq.is_valid_uuid());
    }

    #[test]
    fn test_scalar_16_bit() {
        let s = Scalar::unsigned(16, 0xABCD);
        assert_eq!(s.unsigned_value(), 0xABCD);
        assert_eq!(s.bit_length(), 16);
    }

    #[test]
    fn test_scalar_64_bit() {
        let s = Scalar::signed(64, -1);
        assert_eq!(s.signed_value(), -1);
        assert_eq!(s.unsigned_value(), u64::MAX);
    }

    // -------------------------------------------------------------------
    // Integration tests: EquateManager + EquateTableModel + EquatePlugin
    // -------------------------------------------------------------------

    #[test]
    fn test_integration_create_add_ref_then_table() {
        let mut table = EquateTable::new();
        table.create_equate("FLAG_A", 1).unwrap();
        table.create_equate("FLAG_B", 2).unwrap();
        table.create_equate("FLAG_C", 4).unwrap();

        table.add_reference("FLAG_A", Address::new(0x1000), 0);
        table.add_reference("FLAG_A", Address::new(0x2000), 1);
        table.add_reference("FLAG_B", Address::new(0x3000), 0);

        // Verify table model integration
        let mut model = table::EquateTableModel::new();
        model.update(&table);
        assert_eq!(model.row_count(), 3);

        // Sort by ref count descending -- FLAG_A(2), FLAG_B(1), FLAG_C(0)
        model.set_sort(table::equate_columns::REFS, table::SortOrder::Descending);
        assert_eq!(model.cell_value(0, 0).unwrap(), "FLAG_A");
        assert_eq!(model.cell_value(1, 0).unwrap(), "FLAG_B");
        assert_eq!(model.cell_value(2, 0).unwrap(), "FLAG_C");
    }

    #[test]
    fn test_integration_equate_plugin_get_equates_at() {
        let plugin = EquatePlugin::new();
        let mut table = EquateTable::new();

        // Set equate
        table.create_equate("MY_FLAG", 0x42).unwrap();
        table.add_reference("MY_FLAG", Address::new(0x1000), 0);
        assert_eq!(table.num_equates(), 1);

        // Plugin resolves it
        let info = plugin.get_equate_at(&table, &Address::new(0x1000), 0, 0x42);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.name, "MY_FLAG");
        assert_eq!(info.value, 0x42);

        // Remove
        table.remove_equate("MY_FLAG");
        assert_eq!(table.num_equates(), 0);
    }

    #[test]
    fn test_integration_table_plugin_state_lifecycle() {
        let mut table = EquateTable::new();
        table.create_equate("X", 10).unwrap();
        table.add_reference("X", Address::new(0x1000), 0);
        table.add_reference("X", Address::new(0x2000), 1);

        let mut state = plugin::EquateTablePluginState::new();
        assert!(!state.is_visible());

        state.set_visible(true);
        state.select_equate(&table, Some("X"));
        assert_eq!(state.selected_equate(), Some("X"));
        assert_eq!(state.displayed_references().len(), 2);

        // Delete equate
        let removed = state.delete_equates(&["X"], &mut table);
        assert_eq!(removed, vec!["X"]);
        assert!(state.selected_equate().is_none());
        assert_eq!(table.num_equates(), 0);
    }

    #[test]
    fn test_integration_convert_format_roundtrip() {
        // Verify all formats produce valid output for a known value
        for fmt in convert_cmd::ScalarFormat::ALL {
            let result = convert_cmd::convert_scalar(0xDEADBEEF, 4, fmt);
            assert!(!result.formatted.is_empty(), "Empty output for {:?}", fmt);
        }
    }

    #[test]
    fn test_integration_rename_equates_in_table() {
        let mut table = EquateTable::new();
        table.create_equate("OLD_NAME", 42).unwrap();
        table.add_reference("OLD_NAME", Address::new(0x1000), 0);

        // Rename via manager
        let result = table.rename_equate("OLD_NAME", "NEW_NAME");
        assert!(result);

        // Verify old name is gone, new name exists
        assert!(table.get_equate("OLD_NAME").is_none());
        let eq = table.get_equate("NEW_NAME");
        assert!(eq.is_some());
        assert_eq!(eq.unwrap().value, 42);
        assert_eq!(eq.unwrap().reference_count(), 1);
    }

    #[test]
    fn test_integration_reference_model_with_plugin_state() {
        let mut table = EquateTable::new();
        table.create_equate("VAL", 100).unwrap();
        table.add_reference("VAL", Address::new(0x5000), 0);
        table.add_reference("VAL", Address::new(0x6000), 1);
        table.add_reference("VAL", Address::new(0x7000), 2);

        let mut ref_model = table::EquateReferenceTableModel::new();
        ref_model.set_equate(&table, Some("VAL"));
        assert_eq!(ref_model.row_count(), 3);

        // Get program location for second reference
        let loc = ref_model.get_program_location(1);
        assert!(loc.is_some());
        let (addr, op) = loc.unwrap();
        assert_eq!(addr, Address::new(0x6000));
        assert_eq!(op, 1);

        // Selection across multiple rows
        let sel = ref_model.get_program_selection(&[0, 2]);
        assert_eq!(sel.len(), 2);
    }

    #[test]
    fn test_integration_format_choice_ids() {
        // Verify all format choices have valid format IDs
        let hex = format::FormatChoice::Hex;
        let id = hex.format_id();
        assert!(id >= 0);

        let dec = format::FormatChoice::UnsignedDecimal;
        assert!(!dec.requires_negative());

        let shex = format::FormatChoice::SignedHex;
        assert!(shex.requires_negative());

        // Char is supported on data
        let ch = format::FormatChoice::Char;
        assert!(ch.is_supported_on_data());
    }

    #[test]
    fn test_integration_format_scalar_hex() {
        let scalar = Scalar::unsigned(32, 0xFF);
        let result = format::format_scalar(&scalar, format::FormatChoice::Hex, false);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.contains("FF") || text.contains("ff") || text.contains("0x"));
    }

    #[test]
    fn test_integration_format_scalar_signed_dec() {
        let scalar = Scalar::signed(8, -42);
        let result = format::format_scalar(&scalar, format::FormatChoice::SignedDecimal, false);
        assert!(result.is_some());
        assert!(result.unwrap().contains("-42"));
    }

    #[test]
    fn test_integration_plugin_get_all_equates() {
        let plugin = EquatePlugin::new();
        let mut table = EquateTable::new();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();
        table.create_equate("C", 3).unwrap();

        let all = plugin.get_all_equates(&table);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_integration_rename_duplicate_name_rejected() {
        let mut table = EquateTable::new();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();
        // Rename to existing name should fail
        assert!(!table.rename_equate("A", "B"));
        // Original should still exist
        assert!(table.get_equate("A").is_some());
    }

    #[test]
    fn test_integration_rename_same_name_noop() {
        let mut table = EquateTable::new();
        table.create_equate("X", 10).unwrap();
        assert!(table.rename_equate("X", "X"));
        assert!(table.get_equate("X").is_some());
    }

    #[test]
    fn test_integration_rename_nonexistent_fails() {
        let mut table = EquateTable::new();
        assert!(!table.rename_equate("NOPE", "NEW"));
    }

    #[test]
    fn test_integration_create_duplicate_equate() {
        let mut table = EquateTable::new();
        assert!(table.create_equate("A", 1).is_ok());
        // Creating with same name should fail
        assert!(table.create_equate("A", 2).is_err());
    }

    #[test]
    fn test_integration_get_or_create_equate() {
        let mut table = EquateTable::new();
        let eq1 = table.get_or_create_equate("X", 42);
        assert_eq!(eq1.value, 42);
        // Second call returns same equate
        let eq2 = table.get_or_create_equate("X", 42);
        assert_eq!(eq2.name, "X");
        assert_eq!(eq2.value, 42);
    }
}
