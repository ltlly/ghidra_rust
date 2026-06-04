//! Operand management -- types, field locations, and editing actions.
//!
//! Ported from `ghidra.program.model.lang.OperandType` and
//! `ghidra.program.util.OperandFieldLocation` in Ghidra's Framework and
//! Features/Base.
//!
//! This module provides:
//! - [`OperandType`] -- bit-flags describing operand characteristics
//! - [`OperandFieldLocation`] -- identifies an operand's position in the listing
//! - [`SetOperandLabel`] -- sets a label at the target of an operand reference
//! - [`EditOperandName`] -- renames an operand's symbolic name (function
//!   parameter renaming)

use ghidra_core::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// OperandType -- mirrors ghidra.program.model.lang.OperandType
// ---------------------------------------------------------------------------

/// Bit-flags that describe the type and characteristics of an instruction
/// operand.
///
/// Corresponds to Ghidra's `OperandType` class. Multiple flags can be
/// combined with bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperandType(u32);

#[allow(dead_code)]
impl OperandType {
    // ---- Data-type flags ----

    /// The operand is a register.
    pub const REGISTER: Self = Self(0x0000_0001);
    /// The operand is an immediate scalar value.
    pub const SCALAR: Self = Self(0x0000_0002);
    /// The operand is an address (pointer).
    pub const ADDRESS: Self = Self(0x0000_0004);
    /// The operand is a relative offset (PC-relative).
    pub const RELATIVE: Self = Self(0x0000_0008);

    // ---- Context flags ----

    /// The operand is implied by the instruction (not explicit in encoding).
    pub const IMPLIED: Self = Self(0x0000_0010);
    /// The operand is a flag (condition code, status bit).
    pub const FLAG: Self = Self(0x0000_0020);
    /// The operand is a text string.
    pub const TEXT: Self = Self(0x0000_0040);
    /// The operand is an instruction context register.
    pub const CONTEXT_REG: Self = Self(0x0000_0080);

    // ---- Address-space flags ----

    /// The operand refers to code space (instruction addresses).
    pub const CODE: Self = Self(0x0000_0100);
    /// The operand refers to data space (data addresses).
    pub const DATA: Self = Self(0x0000_0200);

    // ---- Dereference flags ----

    /// The operand is a pointer dereference (indirect).
    pub const INDIRECT: Self = Self(0x0000_0400);
    /// The operand is an indirect reference via a register.
    pub const REG_INDIRECT: Self = Self(0x0000_0800);

    // ---- Read/Write flags ----

    /// The operand is read.
    pub const READ: Self = Self(0x0000_1000);
    /// The operand is written.
    pub const WRITE: Self = Self(0x0000_2000);
    /// The operand is both read and written.
    pub const READ_WRITE: Self = Self(0x0000_3000); // READ | WRITE

    // ---- Polymorphism flags ----

    /// The operand is a list of possible values (polymorphic).
    pub const LIST: Self = Self(0x0000_4000);
    /// The operand is dynamically determined at runtime.
    pub const DYNAMIC: Self = Self(0x0000_8000);

    // ---- Bit manipulation flags ----

    /// The operand is a bit-addressable location.
    pub const BIT: Self = Self(0x0001_0000);

    // ---- Port / I/O flags ----

    /// The operand is a port (I/O register).
    pub const PORT: Self = Self(0x0002_0000);

    // ---- Macro / custom flags ----

    /// Custom flag for user-defined operand type.
    pub const CUSTOM: Self = Self(0x8000_0000);

    // ---- Compound masks ----

    /// Mask for data-type classification bits.
    pub const DATA_TYPE_MASK: Self = Self(0x0000_000F);
    /// Mask for context classification bits.
    pub const CONTEXT_MASK: Self = Self(0x0000_00F0);
    /// Mask for address-space bits.
    pub const SPACE_MASK: Self = Self(0x0000_0300);

    // -------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Create an empty (no flags) operand type.
    pub const fn none() -> Self {
        Self(0)
    }

    // -------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------

    /// The raw bit value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if `flag` is set in this operand type.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Returns `true` if any of the given flags are set.
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Combine two operand types (bitwise OR).
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove flags (bitwise AND NOT).
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    // -------------------------------------------------------------------
    // Convenience predicates
    // -------------------------------------------------------------------

    /// Is this a register operand?
    pub fn is_register(self) -> bool {
        self.contains(Self::REGISTER)
    }

    /// Is this an immediate scalar?
    pub fn is_scalar(self) -> bool {
        self.contains(Self::SCALAR)
    }

    /// Is this an address operand?
    pub fn is_address(self) -> bool {
        self.contains(Self::ADDRESS)
    }

    /// Is this a relative offset?
    pub fn is_relative(self) -> bool {
        self.contains(Self::RELATIVE)
    }

    /// Is this operand implied (not explicitly encoded)?
    pub fn is_implied(self) -> bool {
        self.contains(Self::IMPLIED)
    }

    /// Is this a flag/condition-code operand?
    pub fn is_flag(self) -> bool {
        self.contains(Self::FLAG)
    }

    /// Is this a code-space reference?
    pub fn is_code(self) -> bool {
        self.contains(Self::CODE)
    }

    /// Is this a data-space reference?
    pub fn is_data_space(self) -> bool {
        self.contains(Self::DATA)
    }

    /// Is this an indirect (dereference) operand?
    pub fn is_indirect(self) -> bool {
        self.contains(Self::INDIRECT)
    }

    /// Is this a register-indirect operand?
    pub fn is_register_indirect(self) -> bool {
        self.contains(Self::REG_INDIRECT)
    }

    /// Is this operand read?
    pub fn is_read(self) -> bool {
        self.contains(Self::READ)
    }

    /// Is this operand written?
    pub fn is_write(self) -> bool {
        self.contains(Self::WRITE)
    }

    /// Is this operand read-write?
    pub fn is_read_write(self) -> bool {
        self.contains(Self::READ_WRITE)
    }

    /// Is this a dynamic operand?
    pub fn is_dynamic(self) -> bool {
        self.contains(Self::DYNAMIC)
    }

    /// Is this a port operand?
    pub fn is_port(self) -> bool {
        self.contains(Self::PORT)
    }

    // -------------------------------------------------------------------
    // Display
    // -------------------------------------------------------------------

    /// Return a human-readable string listing all set flags.
    pub fn flag_names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.contains(Self::REGISTER) { names.push("REGISTER"); }
        if self.contains(Self::SCALAR) { names.push("SCALAR"); }
        if self.contains(Self::ADDRESS) { names.push("ADDRESS"); }
        if self.contains(Self::RELATIVE) { names.push("RELATIVE"); }
        if self.contains(Self::IMPLIED) { names.push("IMPLIED"); }
        if self.contains(Self::FLAG) { names.push("FLAG"); }
        if self.contains(Self::TEXT) { names.push("TEXT"); }
        if self.contains(Self::CONTEXT_REG) { names.push("CONTEXT_REG"); }
        if self.contains(Self::CODE) { names.push("CODE"); }
        if self.contains(Self::DATA) { names.push("DATA"); }
        if self.contains(Self::INDIRECT) { names.push("INDIRECT"); }
        if self.contains(Self::REG_INDIRECT) { names.push("REG_INDIRECT"); }
        if self.contains(Self::READ) { names.push("READ"); }
        if self.contains(Self::WRITE) { names.push("WRITE"); }
        if self.contains(Self::LIST) { names.push("LIST"); }
        if self.contains(Self::DYNAMIC) { names.push("DYNAMIC"); }
        if self.contains(Self::BIT) { names.push("BIT"); }
        if self.contains(Self::PORT) { names.push("PORT"); }
        if self.contains(Self::CUSTOM) { names.push("CUSTOM"); }
        names
    }
}

impl fmt::Display for OperandType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.flag_names();
        if names.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", names.join("|"))
        }
    }
}

impl std::ops::BitOr for OperandType {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for OperandType {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::Not for OperandType {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

// ---------------------------------------------------------------------------
// OperandFieldLocation -- mirrors ghidra.program.util.OperandFieldLocation
// ---------------------------------------------------------------------------

/// Identifies a specific operand position within a code unit in the listing.
///
/// Corresponds to Ghidra's `OperandFieldLocation`. Used to locate an operand
/// for equate application, label setting, or renaming.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperandFieldLocation {
    /// The address of the code unit.
    pub address: Address,
    /// The operand index (0..num_operands).
    pub operand_index: i32,
    /// The sub-operand index within a complex operand representation.
    pub sub_operand_index: i32,
    /// The character offset within the operand representation string.
    pub character_offset: i32,
}

impl OperandFieldLocation {
    /// Create a new operand field location.
    pub fn new(
        address: Address,
        operand_index: i32,
        sub_operand_index: i32,
        character_offset: i32,
    ) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index,
            character_offset,
        }
    }

    /// Simple location with just address and operand index.
    pub fn simple(address: Address, operand_index: i32) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index: 0,
            character_offset: 0,
        }
    }

    /// The address of the code unit.
    pub fn get_address(&self) -> Address {
        self.address
    }

    /// The operand index.
    pub fn get_operand_index(&self) -> i32 {
        self.operand_index
    }

    /// The sub-operand index.
    pub fn get_sub_operand_index(&self) -> i32 {
        self.sub_operand_index
    }

    /// The character offset.
    pub fn get_character_offset(&self) -> i32 {
        self.character_offset
    }

    /// Returns `true` if this location refers to a valid operand (index >= 0).
    pub fn is_valid(&self) -> bool {
        self.operand_index >= 0
    }
}

impl fmt::Display for OperandFieldLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OperandField({:x}, op={}, sub={}, char={})",
            self.address.offset, self.operand_index, self.sub_operand_index, self.character_offset
        )
    }
}

// ---------------------------------------------------------------------------
// SetOperandLabel -- mirrors ghidra.app.plugin.core.label.SetOperandLabelAction
// ---------------------------------------------------------------------------

/// Action to set a label at the address referenced by an operand.
///
/// When an operand contains an address reference (e.g., a jump target or
/// data pointer), this action creates or renames the label at that target
/// address.
#[derive(Debug, Clone)]
pub struct SetOperandLabel {
    /// The address of the code unit containing the operand.
    pub source_address: Address,
    /// The operand index.
    pub operand_index: i32,
    /// The target address to label.
    pub target_address: Address,
    /// The new label name.
    pub new_label: String,
}

impl SetOperandLabel {
    pub fn new(
        source_address: Address,
        operand_index: i32,
        target_address: Address,
        new_label: impl Into<String>,
    ) -> Self {
        Self {
            source_address,
            operand_index,
            target_address,
            new_label: new_label.into(),
        }
    }

    /// Apply the label. Returns `Ok(())` on success.
    ///
    /// In a full implementation this would interact with the SymbolTable;
    /// here we return the operation description for downstream consumers.
    pub fn describe(&self) -> String {
        format!(
            "Set label '{}' at {:x} (from operand {} at {:x})",
            self.new_label,
            self.target_address.offset,
            self.operand_index,
            self.source_address.offset
        )
    }
}

// ---------------------------------------------------------------------------
// EditOperandName -- mirrors ghidra.app.plugin.core.function.EditOperandNameAction
// ---------------------------------------------------------------------------

/// Action to rename a function parameter by editing its operand
/// representation.
///
/// When the cursor is on a function parameter operand, this action allows
/// the user to change the parameter's name.
#[derive(Debug, Clone)]
pub struct EditOperandName {
    /// The address of the call instruction (or function entry).
    pub address: Address,
    /// The operand index where the parameter appears.
    pub operand_index: i32,
    /// The function entry point address.
    pub function_address: Address,
    /// The parameter ordinal (0-based).
    pub parameter_ordinal: usize,
    /// The new parameter name.
    pub new_name: String,
}

impl EditOperandName {
    pub fn new(
        address: Address,
        operand_index: i32,
        function_address: Address,
        parameter_ordinal: usize,
        new_name: impl Into<String>,
    ) -> Self {
        Self {
            address,
            operand_index,
            function_address,
            parameter_ordinal,
            new_name: new_name.into(),
        }
    }

    /// Describe this operation.
    pub fn describe(&self) -> String {
        format!(
            "Rename param {} to '{}' in function at {:x} (operand {} at {:x})",
            self.parameter_ordinal,
            self.new_name,
            self.function_address.offset,
            self.operand_index,
            self.address.offset
        )
    }
}

// ---------------------------------------------------------------------------
// OperandTypeAnalysis -- helper for analyzing operand types from
// instruction semantics
// ---------------------------------------------------------------------------

/// Determines the [`OperandType`] flags for a scalar operand based on
/// context.
///
/// This mirrors the logic used by Ghidra's analyzers and listing to
/// classify operand types.
pub fn classify_scalar_operand(
    bit_length: u32,
    is_signed: bool,
    is_relative: bool,
    is_data_ref: bool,
    is_code_ref: bool,
) -> OperandType {
    let mut ot = OperandType::SCALAR | OperandType::READ;
    if is_relative {
        ot = ot.union(OperandType::RELATIVE);
    }
    if is_data_ref {
        ot = ot.union(OperandType::DATA);
    }
    if is_code_ref {
        ot = ot.union(OperandType::CODE);
    }
    // Mark as address if it looks like a pointer-sized value.
    if bit_length >= 16 && (is_data_ref || is_code_ref) {
        ot = ot.union(OperandType::ADDRESS);
    }
    let _ = is_signed; // signedness doesn't affect OperandType flags in Ghidra
    ot
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- OperandType tests ----

    #[test]
    fn test_operand_type_contains() {
        let ot = OperandType::REGISTER | OperandType::READ;
        assert!(ot.is_register());
        assert!(ot.is_read());
        assert!(!ot.is_scalar());
        assert!(!ot.is_write());
    }

    #[test]
    fn test_operand_type_read_write() {
        let ot = OperandType::READ_WRITE;
        assert!(ot.is_read());
        assert!(ot.is_write());
        assert!(ot.is_read_write());
    }

    #[test]
    fn test_operand_type_display() {
        let ot = OperandType::REGISTER | OperandType::READ;
        assert_eq!(format!("{}", ot), "REGISTER|READ");
    }

    #[test]
    fn test_operand_type_display_none() {
        let ot = OperandType::none();
        assert_eq!(format!("{}", ot), "NONE");
    }

    #[test]
    fn test_operand_type_union() {
        let a = OperandType::SCALAR;
        let b = OperandType::CODE;
        let c = a | b;
        assert!(c.is_scalar());
        assert!(c.is_code());
    }

    #[test]
    fn test_operand_type_difference() {
        let a = OperandType::READ_WRITE;
        let b = a.difference(OperandType::WRITE);
        assert!(b.is_read());
        assert!(!b.is_write());
    }

    #[test]
    fn test_operand_type_flag_names() {
        let ot = OperandType::REGISTER | OperandType::CODE | OperandType::DYNAMIC;
        let names = ot.flag_names();
        assert!(names.contains(&"REGISTER"));
        assert!(names.contains(&"CODE"));
        assert!(names.contains(&"DYNAMIC"));
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn test_operand_type_bits_roundtrip() {
        let ot = OperandType::SCALAR | OperandType::RELATIVE;
        let bits = ot.bits();
        let ot2 = OperandType::from_bits(bits);
        assert_eq!(ot, ot2);
    }

    // ---- OperandFieldLocation tests ----

    #[test]
    fn test_operand_field_location_new() {
        let loc = OperandFieldLocation::new(Address::new(0x401000), 1, 0, 5);
        assert_eq!(loc.get_address(), Address::new(0x401000));
        assert_eq!(loc.get_operand_index(), 1);
        assert_eq!(loc.get_sub_operand_index(), 0);
        assert_eq!(loc.get_character_offset(), 5);
        assert!(loc.is_valid());
    }

    #[test]
    fn test_operand_field_location_simple() {
        let loc = OperandFieldLocation::simple(Address::new(0x1000), 0);
        assert_eq!(loc.get_operand_index(), 0);
        assert_eq!(loc.get_sub_operand_index(), 0);
        assert_eq!(loc.get_character_offset(), 0);
    }

    #[test]
    fn test_operand_field_location_invalid() {
        let loc = OperandFieldLocation::new(Address::new(0x1000), -1, 0, 0);
        assert!(!loc.is_valid());
    }

    #[test]
    fn test_operand_field_location_display() {
        let loc = OperandFieldLocation::new(Address::new(0x1000), 2, 1, 3);
        let s = format!("{}", loc);
        assert!(s.contains("1000"));
        assert!(s.contains("op=2"));
        assert!(s.contains("sub=1"));
    }

    // ---- SetOperandLabel tests ----

    #[test]
    fn test_set_operand_label_describe() {
        let action = SetOperandLabel::new(
            Address::new(0x401000),
            0,
            Address::new(0x402000),
            "my_label",
        );
        let desc = action.describe();
        assert!(desc.contains("my_label"));
        assert!(desc.contains("402000"));
    }

    // ---- EditOperandName tests ----

    #[test]
    fn test_edit_operand_name_describe() {
        let action = EditOperandName::new(
            Address::new(0x401000),
            0,
            Address::new(0x400000),
            2,
            "new_param_name",
        );
        let desc = action.describe();
        assert!(desc.contains("new_param_name"));
        assert!(desc.contains("param 2"));
    }

    // ---- classify_scalar_operand tests ----

    #[test]
    fn test_classify_scalar_basic() {
        let ot = classify_scalar_operand(32, false, false, false, false);
        assert!(ot.is_scalar());
        assert!(ot.is_read());
        assert!(!ot.is_address());
    }

    #[test]
    fn test_classify_scalar_code_ref() {
        let ot = classify_scalar_operand(32, false, true, false, true);
        assert!(ot.is_code());
        assert!(ot.is_relative());
        assert!(ot.is_address()); // >= 16 bits and code_ref
    }

    #[test]
    fn test_classify_scalar_data_ref() {
        let ot = classify_scalar_operand(64, true, false, true, false);
        assert!(ot.is_data_space());
        assert!(ot.is_address());
    }

    #[test]
    fn test_classify_scalar_small_no_address() {
        // 8-bit scalar is not promoted to ADDRESS even if it's a code ref.
        let ot = classify_scalar_operand(8, false, false, false, true);
        assert!(!ot.is_address());
    }
}
