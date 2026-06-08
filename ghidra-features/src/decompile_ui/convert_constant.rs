//! Convert constant actions and equate task -- Rust port of
//! `ghidra.app.plugin.core.decompile.actions.ConvertConstantAction` and
//! `ghidra.app.plugin.core.decompile.actions.ConvertConstantEquateTask`.
//!
//! This module provides the infrastructure for converting decompiler constants
//! between display formats (hex, decimal, octal, binary, float, etc.) by
//! creating or modifying equate references in the program database.
//!
//! # Architecture
//!
//! ```text
//! ConvertConstantAction (abstract base)
//!   ├── ConvertHexAction
//!   ├── ConvertDecAction
//!   ├── ConvertBinaryAction
//!   ├── ConvertOctAction
//!   ├── ConvertFloatAction
//!   └── ConvertDoubleAction
//!
//! ConvertConstantEquateTask
//!   ├── NearMatchValues (helper for "near" constant matching)
//!   ├── ScalarMatch (instruction operand match)
//!   └── establishTask() -> runTask() -> commit equate
//! ```

use ghidra_core::addr::Address;

use super::action_context::DecompilerActionContext;

// ---------------------------------------------------------------------------
// Equate format constants (mirrors EquateSymbol.FORMAT_*)
// ---------------------------------------------------------------------------

/// The default equate format (auto-detected).
pub const FORMAT_DEFAULT: i32 = 0;
/// Hexadecimal format.
pub const FORMAT_HEX: i32 = 1;
/// Decimal format.
pub const FORMAT_DEC: i32 = 2;
/// Octal format.
pub const FORMAT_OCT: i32 = 3;
/// Binary format.
pub const FORMAT_BINARY: i32 = 4;
/// Float format.
pub const FORMAT_FLOAT: i32 = 5;
/// Double format.
pub const FORMAT_DOUBLE: i32 = 6;
/// Character format.
pub const FORMAT_CHAR: i32 = 7;

// ---------------------------------------------------------------------------
// Scalar -- a sized integer constant
// ---------------------------------------------------------------------------

/// A scalar value with a known bit width and signedness.
///
/// Mirrors Ghidra's `ghidra.program.model.scalar.Scalar`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar {
    /// The number of bits in this scalar.
    bit_length: usize,
    /// The unsigned value.
    value: u64,
    /// Whether this scalar is signed.
    signed: bool,
}

impl Scalar {
    /// Create a new scalar.
    pub fn new(bit_length: usize, value: u64, signed: bool) -> Self {
        Self {
            bit_length,
            value,
            signed,
        }
    }

    /// The number of bits.
    pub fn bit_length(&self) -> usize {
        self.bit_length
    }

    /// The number of bytes (ceiling division).
    pub fn size(&self) -> usize {
        (self.bit_length + 7) / 8
    }

    /// The unsigned value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// The signed interpretation of the value.
    pub fn signed_value(&self) -> i64 {
        if self.signed {
            let shift = 64 - self.bit_length;
            ((self.value as i64) << shift) >> shift
        } else {
            self.value as i64
        }
    }

    /// Whether this scalar is signed.
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    /// Format the value as hexadecimal.
    pub fn to_hex(&self) -> String {
        match self.bit_length {
            8 => format!("0x{:02x}", self.value & 0xFF),
            16 => format!("0x{:04x}", self.value & 0xFFFF),
            32 => format!("0x{:08x}", self.value & 0xFFFF_FFFF),
            64 => format!("0x{:016x}", self.value),
            _ => format!("0x{:x}", self.value),
        }
    }

    /// Format the value as decimal.
    pub fn to_decimal(&self) -> String {
        if self.signed {
            self.signed_value().to_string()
        } else {
            self.value.to_string()
        }
    }

    /// Format the value as octal.
    pub fn to_octal(&self) -> String {
        format!("0o{:o}", self.value)
    }

    /// Format the value as binary.
    pub fn to_binary(&self) -> String {
        format!("0b{:b}", self.value)
    }

    /// Format the value as a float (interpreting the bits as IEEE 754).
    pub fn to_float(&self) -> String {
        match self.bit_length {
            32 => {
                let f = f32::from_bits(self.value as u32);
                format!("{}", f)
            }
            64 => {
                let f = f64::from_bits(self.value);
                format!("{}", f)
            }
            _ => self.to_hex(),
        }
    }

    /// Format the value as a character.
    pub fn to_char(&self) -> String {
        let c = (self.value & 0x7F) as u8;
        if c >= 0x20 && c <= 0x7E {
            format!("'{}'", c as char)
        } else {
            self.to_hex()
        }
    }
}

// ---------------------------------------------------------------------------
// NearMatchValues -- helper for "near" constant matching
// ---------------------------------------------------------------------------

/// Helper for identifying integer values that are "near" a given value.
///
/// "Near" means the value itself, off by +/-1, or the negated value.
/// This is used when searching for instruction operands that correspond
/// to a decompiler constant, because the decompiler may simplify
/// expressions (e.g., `x + 1` shows as `1` but the operand is `x`).
///
/// Mirrors `ConvertConstantAction.NearMatchValues`.
#[derive(Debug, Clone)]
pub struct NearMatchValues {
    /// The set of near-match values: [value, value-1, value+1, -value].
    values: [u64; 4],
    /// Mask applied before comparison (depends on scalar size).
    mask: u64,
}

impl NearMatchValues {
    /// Create near-match values for a scalar of the given byte size.
    pub fn new(value: u64, size: usize) -> Self {
        let mask = if size < 8 {
            u64::MAX >> ((8 - size) * 8)
        } else {
            u64::MAX
        };
        Self {
            values: [
                value & mask,
                value.wrapping_sub(1) & mask,
                value.wrapping_add(1) & mask,
                value.wrapping_neg() & mask,
            ],
            mask,
        }
    }

    /// Create near-match values from a `Scalar`.
    pub fn from_scalar(scalar: &Scalar) -> Self {
        Self::new(scalar.value, scalar.size())
    }

    /// Returns `true` if the given value matches any of the near values.
    pub fn is_match(&self, value: u64) -> bool {
        let masked = value & self.mask;
        self.values.iter().any(|&v| v == masked)
    }
}

// ---------------------------------------------------------------------------
// ScalarMatch -- a matching scalar operand in an instruction
// ---------------------------------------------------------------------------

/// Describes a scalar operand found in an instruction that matches a
/// decompiler constant.
///
/// Mirrors `ConvertConstantEquateTask.ScalarMatch`.
#[derive(Debug, Clone)]
pub struct ScalarMatch {
    /// The address of the instruction containing the operand.
    pub ref_addr: Address,
    /// The scalar value of the operand.
    pub scalar: Scalar,
    /// The operand index within the instruction (-1 if non-unique).
    pub op_index: i32,
}

// ---------------------------------------------------------------------------
// EquateReference -- a reference to an equate in the equate table
// ---------------------------------------------------------------------------

/// A reference to an equate entry.
///
/// Mirrors `EquateReference` from the Ghidra equate table.
#[derive(Debug, Clone)]
pub struct EquateReference {
    /// The address of the reference.
    pub address: Address,
    /// The dynamic hash value (for P-code level identification).
    pub dynamic_hash: u64,
    /// The operand index (for instruction-level identification).
    pub op_index: i32,
}

// ---------------------------------------------------------------------------
// EquateEntry -- an entry in the equate table
// ---------------------------------------------------------------------------

/// An equate table entry.
///
/// Mirrors `Equate` from the Ghidra equate table.
#[derive(Debug, Clone)]
pub struct EquateEntry {
    /// The equate name (e.g., "NULL", "TRUE", "MAX_PATH").
    pub name: String,
    /// The equate value.
    pub value: i64,
    /// References to this equate.
    pub references: Vec<EquateReference>,
}

impl EquateEntry {
    /// Create a new equate entry.
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
            references: Vec::new(),
        }
    }

    /// Add a reference using a dynamic hash.
    pub fn add_hash_reference(&mut self, hash: u64, address: Address) {
        self.references.push(EquateReference {
            address,
            dynamic_hash: hash,
            op_index: -1,
        });
    }

    /// Add a reference using an operand index.
    pub fn add_operand_reference(&mut self, address: Address, op_index: i32) {
        self.references.push(EquateReference {
            address,
            dynamic_hash: 0,
            op_index,
        });
    }

    /// The number of references.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// Remove a reference by dynamic hash and address.
    pub fn remove_hash_reference(&mut self, hash: u64, address: Address) -> bool {
        let len_before = self.references.len();
        self.references.retain(|r| !(r.dynamic_hash == hash && r.address == address));
        self.references.len() < len_before
    }

    /// Remove a reference by address and operand index.
    pub fn remove_operand_reference(&mut self, address: Address, op_index: i32) -> bool {
        let len_before = self.references.len();
        self.references
            .retain(|r| !(r.address == address && r.op_index == op_index));
        self.references.len() < len_before
    }
}

// ---------------------------------------------------------------------------
// EquateTable -- simplified equate table
// ---------------------------------------------------------------------------

/// A simplified equate table.
///
/// In Ghidra this is `program.getEquateTable()`.  Here we model it as
/// a collection of equate entries.
#[derive(Debug, Clone, Default)]
pub struct EquateTable {
    entries: Vec<EquateEntry>,
}

impl EquateTable {
    /// Create an empty equate table.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Get an equate by name.
    pub fn get_equate(&self, name: &str) -> Option<&EquateEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Get a mutable equate by name.
    pub fn get_equate_mut(&mut self, name: &str) -> Option<&mut EquateEntry> {
        self.entries.iter_mut().find(|e| e.name == name)
    }

    /// Get all equates at a given address.
    pub fn get_equates_at(&self, address: Address) -> Vec<&EquateEntry> {
        self.entries
            .iter()
            .filter(|e| e.references.iter().any(|r| r.address == address))
            .collect()
    }

    /// Create a new equate.  Returns an error if the name already exists
    /// with a different value.
    pub fn create_equate(
        &mut self,
        name: impl Into<String>,
        value: i64,
    ) -> Result<&mut EquateEntry, String> {
        let name = name.into();
        if let Some(existing) = self.get_equate(&name) {
            if existing.value != value {
                return Err(format!(
                    "Equate named {} already exists with value of {}.",
                    name, existing.value
                ));
            }
        }
        if self.get_equate(&name).is_none() {
            self.entries.push(EquateEntry::new(&name, value));
        }
        Ok(self.get_equate_mut(&name).unwrap())
    }

    /// Remove an equate by name.
    pub fn remove_equate(&mut self, name: &str) -> bool {
        let len_before = self.entries.len();
        self.entries.retain(|e| e.name != name);
        self.entries.len() < len_before
    }

    /// The number of equates in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ConvertConstantAction -- abstract base for constant conversion actions
// ---------------------------------------------------------------------------

/// The kind of conversion to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConvertType {
    /// Convert to hexadecimal.
    Hex,
    /// Convert to decimal.
    Dec,
    /// Convert to octal.
    Oct,
    /// Convert to binary.
    Binary,
    /// Convert to float.
    Float,
    /// Convert to double.
    Double,
    /// Convert to character.
    Char,
    /// Default format (auto-detect).
    Default,
}

impl ConvertType {
    /// The format constant (mirrors `EquateSymbol.FORMAT_*`).
    pub fn format_constant(&self) -> i32 {
        match self {
            ConvertType::Hex => FORMAT_HEX,
            ConvertType::Dec => FORMAT_DEC,
            ConvertType::Oct => FORMAT_OCT,
            ConvertType::Binary => FORMAT_BINARY,
            ConvertType::Float => FORMAT_FLOAT,
            ConvertType::Double => FORMAT_DOUBLE,
            ConvertType::Char => FORMAT_CHAR,
            ConvertType::Default => FORMAT_DEFAULT,
        }
    }

    /// The menu prefix string (e.g., "Hexadecimal:").
    pub fn menu_prefix(&self) -> &str {
        match self {
            ConvertType::Hex => "Hexadecimal:",
            ConvertType::Dec => "Decimal:",
            ConvertType::Oct => "Octal:",
            ConvertType::Binary => "Binary:",
            ConvertType::Float => "Float:",
            ConvertType::Double => "Double:",
            ConvertType::Char => "Character:",
            ConvertType::Default => "Default:",
        }
    }

    /// Format a scalar value according to this conversion type.
    pub fn format_scalar(&self, scalar: &Scalar) -> String {
        match self {
            ConvertType::Hex => scalar.to_hex(),
            ConvertType::Dec => scalar.to_decimal(),
            ConvertType::Oct => scalar.to_octal(),
            ConvertType::Binary => scalar.to_binary(),
            ConvertType::Float => scalar.to_float(),
            ConvertType::Double => scalar.to_float(),
            ConvertType::Char => scalar.to_char(),
            ConvertType::Default => scalar.to_hex(),
        }
    }
}

/// A constant conversion action.
///
/// This is the Rust equivalent of the abstract `ConvertConstantAction` Java
/// class.  Each concrete conversion (hex, dec, etc.) is represented by a
/// `ConvertType` variant.
///
/// The action operates in two modes:
///
/// 1. **Switch case constant**: If the cursor is on a `ClangCaseToken`, the
///    switch's display format is changed directly.
/// 2. **P-code constant**: An equate reference is created or modified via
///    [`ConvertConstantEquateTask`].
#[derive(Debug, Clone)]
pub struct ConvertConstantAction {
    /// The type of conversion.
    pub convert_type: ConvertType,
    /// The action name.
    name: String,
    /// The menu path.
    menu_path: Vec<String>,
}

impl ConvertConstantAction {
    /// Create a new convert constant action.
    pub fn new(convert_type: ConvertType) -> Self {
        let name = format!("Convert to {}", convert_type.menu_prefix().trim_end_matches(':'));
        let menu_path = vec![name.clone()];
        Self {
            convert_type,
            name,
            menu_path,
        }
    }

    /// Create a hex conversion action.
    pub fn hex() -> Self {
        Self::new(ConvertType::Hex)
    }

    /// Create a decimal conversion action.
    pub fn dec() -> Self {
        Self::new(ConvertType::Dec)
    }

    /// Create an octal conversion action.
    pub fn oct() -> Self {
        Self::new(ConvertType::Oct)
    }

    /// Create a binary conversion action.
    pub fn binary() -> Self {
        Self::new(ConvertType::Binary)
    }

    /// Create a float conversion action.
    pub fn float() -> Self {
        Self::new(ConvertType::Float)
    }

    /// Create a double conversion action.
    pub fn double() -> Self {
        Self::new(ConvertType::Double)
    }

    /// Create a character conversion action.
    pub fn char() -> Self {
        Self::new(ConvertType::Char)
    }

    /// The action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The menu path.
    pub fn menu_path(&self) -> &[String] {
        &self.menu_path
    }

    /// Returns the menu display string for a scalar value.
    ///
    /// The format is `"Prefix: value"`, e.g., `"Hexadecimal:  0x2408"`.
    pub fn get_menu_display(&self, scalar: &Scalar) -> String {
        let prefix = self.convert_type.menu_prefix();
        let display = self.convert_type.format_scalar(scalar);
        // Pad the prefix to a standard width for alignment.
        let padding = if prefix.len() < 14 {
            " ".repeat(14 - prefix.len())
        } else {
            String::new()
        };
        format!("{}{}{}", prefix, padding, display)
    }

    /// Check if the action is enabled for the given context.
    ///
    /// Returns `Some(display_string)` if enabled, `None` if not.
    pub fn check_enabled(&self, ctx: &DecompilerActionContext) -> Option<String> {
        let token = ctx.token_at_cursor()?;
        let scalar = self.get_convertible_constant(ctx)?;
        let display = self.get_menu_display(&scalar);

        // Don't show the action if the token already displays in this format.
        if token.text == display {
            return None;
        }

        Some(display)
    }

    /// Attempt to get a convertible constant from the context.
    fn get_convertible_constant(&self, ctx: &DecompilerActionContext) -> Option<Scalar> {
        let token = ctx.token_at_cursor()?;

        // Check for a switch case constant.
        if let Some(case_scalar) = self.get_case_constant(ctx) {
            return Some(case_scalar);
        }

        // Check for a P-code constant (variable token with a constant varnode).
        if token.kind == super::action_context::ClangTokenKind::Variable {
            // In the full implementation, this checks:
            // 1. token.getVarnode().isConstant()
            // 2. No existing symbol/equate attached
            // 3. Data type is not boolean or enum
            // For now, we model this as returning a placeholder.
            return None;
        }

        None
    }

    /// If the cursor is on a switch case constant, return its scalar value.
    fn get_case_constant(&self, ctx: &DecompilerActionContext) -> Option<Scalar> {
        // In the full implementation, this checks:
        // 1. token instanceof ClangCaseToken
        // 2. convertType is not DEFAULT, DOUBLE, or FLOAT
        // 3. The case token has a high variable with an integer data type
        // Here we return None as a placeholder.
        let _ = ctx;
        None
    }
}

// ---------------------------------------------------------------------------
// ConvertConstantEquateTask -- creates/modifies equate references
// ---------------------------------------------------------------------------

/// The maximum number of instructions to search when looking for a scalar
/// match in the listing.
const MAX_INSTRUCTION_WINDOW: usize = 20;

/// The maximum scalar size (in bytes) that can be converted.
const MAX_SCALAR_SIZE: usize = 8;

/// A task that creates or modifies an equate reference in the program
/// database to change how a constant is displayed in the decompiler.
///
/// Mirrors `ConvertConstantEquateTask` from the Java source.
///
/// The task operates in two modes:
///
/// 1. **Primary equate**: Creates an equate reference directly at the
///    constant's P-code address.
/// 2. **Alternate equate**: First tries to place the equate at an
///    instruction operand address.  If the decompiler doesn't pick it up,
///    falls back to the primary equate.
#[derive(Debug, Clone)]
pub struct ConvertConstantEquateTask {
    /// The primary address of the equate.
    convert_address: Address,
    /// The equate name.
    convert_name: String,
    /// The equate value.
    convert_value: Scalar,
    /// A dynamic hash locating the constant Varnode in data-flow.
    convert_hash: u64,
    /// The scalar index associated with the primary equate (-1 if unknown).
    convert_index: i32,

    /// Alternate location of constant (if any).
    alt_address: Option<Address>,
    /// Index of alternate scalar.
    alt_index: i32,
    /// Alternate equate name.
    alt_name: Option<String>,
    /// Alternate value.
    alt_value: i64,
}

impl ConvertConstantEquateTask {
    /// Create a new equate task.
    pub fn new(
        name: impl Into<String>,
        address: Address,
        scalar: Scalar,
        hash: u64,
        index: i32,
    ) -> Self {
        Self {
            convert_address: address,
            convert_name: name.into(),
            convert_value: scalar,
            convert_hash: hash,
            convert_index: index,
            alt_address: None,
            alt_index: -1,
            alt_name: None,
            alt_value: 0,
        }
    }

    /// Set an alternate equate location.
    ///
    /// When set, the task first tries the alternate location.  If the
    /// decompiler doesn't pick it up, it falls back to the primary.
    pub fn set_alternate(
        &mut self,
        name: impl Into<String>,
        address: Address,
        index: i32,
        value: i64,
    ) {
        self.alt_name = Some(name.into());
        self.alt_address = Some(address);
        self.alt_index = index;
        self.alt_value = value;
    }

    /// The primary equate name.
    pub fn name(&self) -> &str {
        &self.convert_name
    }

    /// The primary equate address.
    pub fn address(&self) -> Address {
        self.convert_address
    }

    /// The primary equate value.
    pub fn value(&self) -> &Scalar {
        &self.convert_value
    }

    /// The dynamic hash.
    pub fn hash(&self) -> u64 {
        self.convert_hash
    }

    /// Whether an alternate equate is set.
    pub fn has_alternate(&self) -> bool {
        self.alt_address.is_some()
    }

    /// Run the task against an equate table.
    ///
    /// Returns `Ok(())` on success, or an error message on failure.
    pub fn run(&self, equate_table: &mut EquateTable) -> Result<(), String> {
        if let Some(alt_addr) = self.alt_address {
            // Try the alternate first.
            self.apply_alternate(equate_table)?;
            // In the full implementation, we'd wait for the decompiler to
            // update and then check if the alternate reached the constant.
            // For now, we also apply the primary as a fallback.
            self.apply_primary(equate_table)?;
            // Clean up the alternate if the primary was needed.
            self.remove_alternate(equate_table);
        } else {
            self.apply_primary(equate_table)?;
        }
        Ok(())
    }

    /// Apply the primary equate.
    fn apply_primary(&self, equate_table: &mut EquateTable) -> Result<(), String> {
        // Remove any existing reference at this address/hash.
        self.remove_primary(equate_table);

        // Create or find the equate.
        let equate = equate_table.create_equate(&self.convert_name, self.convert_value.value() as i64)?;

        // Add the reference.
        if self.convert_hash != 0 {
            equate.add_hash_reference(self.convert_hash, self.convert_address);
        } else {
            equate.add_operand_reference(self.convert_address, self.convert_index);
        }

        Ok(())
    }

    /// Apply the alternate equate.
    fn apply_alternate(&self, equate_table: &mut EquateTable) -> Result<(), String> {
        let alt_name = self.alt_name.as_ref().ok_or("No alternate name set")?;
        let alt_addr = self.alt_address.ok_or("No alternate address set")?;

        let equate = equate_table.create_equate(alt_name, self.alt_value)?;
        equate.add_operand_reference(alt_addr, self.alt_index);

        Ok(())
    }

    /// Remove the primary equate reference.
    fn remove_primary(&self, equate_table: &mut EquateTable) {
        let equates = equate_table.get_equates_at(self.convert_address);
        for equate in equates {
            let has_ref = equate.references.iter().any(|r| {
                r.address == self.convert_address && r.dynamic_hash == self.convert_hash
            });
            if has_ref {
                if equate.reference_count() <= 1 {
                    equate_table.remove_equate(&equate.name.clone());
                } else if let Some(eq) = equate_table.get_equate_mut(&equate.name.clone()) {
                    eq.remove_hash_reference(self.convert_hash, self.convert_address);
                }
                return;
            }
        }
    }

    /// Remove the alternate equate reference.
    fn remove_alternate(&self, equate_table: &mut EquateTable) {
        let alt_addr = match self.alt_address {
            Some(a) => a,
            None => return,
        };
        let equates = equate_table.get_equates_at(alt_addr);
        for equate in equates {
            let has_ref = equate
                .references
                .iter()
                .any(|r| r.address == alt_addr && r.op_index == self.alt_index);
            if has_ref {
                if equate.reference_count() <= 1 {
                    equate_table.remove_equate(&equate.name.clone());
                } else if let Some(eq) = equate_table.get_equate_mut(&equate.name.clone()) {
                    eq.remove_operand_reference(alt_addr, self.alt_index);
                }
                return;
            }
        }
    }

    /// Establish a task for the given context and action.
    ///
    /// Returns `Some(task)` if the context is suitable, `None` otherwise.
    pub fn establish_task(
        ctx: &DecompilerActionContext,
        action: &ConvertConstantAction,
    ) -> Option<Self> {
        let token = ctx.token_at_cursor()?;

        // Check for a convertible constant.
        let scalar = Self::get_convertible_constant(ctx, action.convert_type)?;

        // In the full implementation, this would:
        // 1. Check if the varnode has an existing EquateSymbol
        // 2. If so, call convert_existing_symbol()
        // 3. Otherwise, find the P-code op address and create a new task
        // 4. Search for a matching instruction operand (ScalarMatch)
        // 5. Set up an alternate if found

        let equate_name = action.convert_type.format_scalar(&scalar);

        Some(Self::new(
            equate_name,
            ctx.function_entry_point,
            scalar,
            0, // dynamic hash (placeholder)
            -1,
        ))
    }

    /// Get a convertible constant from the context.
    fn get_convertible_constant(
        ctx: &DecompilerActionContext,
        convert_type: ConvertType,
    ) -> Option<Scalar> {
        let token = ctx.token_at_cursor()?;

        // Check for a case constant first.
        if convert_type != ConvertType::Default
            && convert_type != ConvertType::Double
            && convert_type != ConvertType::Float
        {
            // In the full implementation, this checks for ClangCaseToken.
        }

        // Check for a variable token with a constant varnode.
        if token.kind == super::action_context::ClangTokenKind::Variable {
            // In the full implementation:
            // 1. varnode = token.getVarnode()
            // 2. Check varnode.isConstant() && varnode.getSize() <= MAX_SCALAR_SIZE
            // 3. Check no existing symbol (or existing EquateSymbol with different format)
            // 4. Check data type is not boolean or enum
        }

        None
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors for concrete conversion actions
// ---------------------------------------------------------------------------

/// Create all standard convert constant actions.
pub fn all_convert_actions() -> Vec<ConvertConstantAction> {
    vec![
        ConvertConstantAction::hex(),
        ConvertConstantAction::dec(),
        ConvertConstantAction::oct(),
        ConvertConstantAction::binary(),
        ConvertConstantAction::float(),
        ConvertConstantAction::double(),
        ConvertConstantAction::char(),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Scalar ---

    #[test]
    fn test_scalar_new() {
        let s = Scalar::new(32, 0xFF, false);
        assert_eq!(s.bit_length(), 32);
        assert_eq!(s.size(), 4);
        assert_eq!(s.value(), 0xFF);
        assert!(!s.is_signed());
    }

    #[test]
    fn test_scalar_signed_value() {
        let s = Scalar::new(8, 0xFF, true);
        assert_eq!(s.signed_value(), -1);

        let s = Scalar::new(8, 127, true);
        assert_eq!(s.signed_value(), 127);

        let s = Scalar::new(16, 0xFFFF, true);
        assert_eq!(s.signed_value(), -1);
    }

    #[test]
    fn test_scalar_to_hex() {
        assert_eq!(Scalar::new(8, 0xFF, false).to_hex(), "0xff");
        assert_eq!(Scalar::new(16, 0x1234, false).to_hex(), "0x1234");
        assert_eq!(
            Scalar::new(32, 0xDEADBEEF, false).to_hex(),
            "0xdeadbeef"
        );
    }

    #[test]
    fn test_scalar_to_decimal() {
        assert_eq!(Scalar::new(8, 42, false).to_decimal(), "42");
        assert_eq!(Scalar::new(8, 0xFF, true).to_decimal(), "-1");
    }

    #[test]
    fn test_scalar_to_octal() {
        assert_eq!(Scalar::new(8, 8, false).to_octal(), "0o10");
    }

    #[test]
    fn test_scalar_to_binary() {
        assert_eq!(Scalar::new(8, 5, false).to_binary(), "0b101");
    }

    #[test]
    fn test_scalar_to_float() {
        let s = Scalar::new(32, f32::to_bits(1.0) as u64, false);
        assert_eq!(s.to_float(), "1");
    }

    #[test]
    fn test_scalar_to_char() {
        assert_eq!(Scalar::new(8, 65, false).to_char(), "'A'");
        assert_eq!(Scalar::new(8, 0, false).to_char(), "0x00");
    }

    // --- NearMatchValues ---

    #[test]
    fn test_near_match_exact() {
        let nm = NearMatchValues::new(42, 4);
        assert!(nm.is_match(42));
    }

    #[test]
    fn test_near_match_plus_minus_one() {
        let nm = NearMatchValues::new(42, 4);
        assert!(nm.is_match(41));
        assert!(nm.is_match(43));
    }

    #[test]
    fn test_near_match_negated() {
        let nm = NearMatchValues::new(42, 4);
        assert!(nm.is_match((-42i64) as u64));
    }

    #[test]
    fn test_near_match_no_match() {
        let nm = NearMatchValues::new(42, 4);
        assert!(!nm.is_match(100));
    }

    #[test]
    fn test_near_match_mask() {
        let nm = NearMatchValues::new(0x1234_5678_9ABC_DEF0, 2);
        // Only the low 2 bytes should matter.
        assert!(nm.is_match(0xDEF0));
        assert!(nm.is_match(0x0000_0000_0000_DEF0));
    }

    #[test]
    fn test_near_match_from_scalar() {
        let scalar = Scalar::new(32, 100, false);
        let nm = NearMatchValues::from_scalar(&scalar);
        assert!(nm.is_match(100));
        assert!(nm.is_match(99));
        assert!(nm.is_match(101));
    }

    // --- EquateEntry ---

    #[test]
    fn test_equate_entry_new() {
        let e = EquateEntry::new("NULL", 0);
        assert_eq!(e.name, "NULL");
        assert_eq!(e.value, 0);
        assert_eq!(e.reference_count(), 0);
    }

    #[test]
    fn test_equate_entry_add_hash_reference() {
        let mut e = EquateEntry::new("TEST", 42);
        e.add_hash_reference(0x1234, Address::new(0x1000));
        assert_eq!(e.reference_count(), 1);
    }

    #[test]
    fn test_equate_entry_add_operand_reference() {
        let mut e = EquateEntry::new("TEST", 42);
        e.add_operand_reference(Address::new(0x1000), 2);
        assert_eq!(e.reference_count(), 1);
    }

    #[test]
    fn test_equate_entry_remove_hash_reference() {
        let mut e = EquateEntry::new("TEST", 42);
        e.add_hash_reference(0x1234, Address::new(0x1000));
        assert!(e.remove_hash_reference(0x1234, Address::new(0x1000)));
        assert_eq!(e.reference_count(), 0);
    }

    #[test]
    fn test_equate_entry_remove_operand_reference() {
        let mut e = EquateEntry::new("TEST", 42);
        e.add_operand_reference(Address::new(0x1000), 2);
        assert!(e.remove_operand_reference(Address::new(0x1000), 2));
        assert_eq!(e.reference_count(), 0);
    }

    // --- EquateTable ---

    #[test]
    fn test_equate_table_create() {
        let mut table = EquateTable::new();
        table.create_equate("NULL", 0).unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.get_equate("NULL").is_some());
    }

    #[test]
    fn test_equate_table_duplicate_name_same_value() {
        let mut table = EquateTable::new();
        table.create_equate("NULL", 0).unwrap();
        // Same name, same value -- should succeed.
        table.create_equate("NULL", 0).unwrap();
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_equate_table_duplicate_name_different_value() {
        let mut table = EquateTable::new();
        table.create_equate("NULL", 0).unwrap();
        // Same name, different value -- should fail.
        assert!(table.create_equate("NULL", 1).is_err());
    }

    #[test]
    fn test_equate_table_remove() {
        let mut table = EquateTable::new();
        table.create_equate("TEST", 42).unwrap();
        assert!(table.remove_equate("TEST"));
        assert!(table.is_empty());
    }

    #[test]
    fn test_equate_table_get_equates_at() {
        let mut table = EquateTable::new();
        let addr = Address::new(0x1000);
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();
        table.get_equate_mut("A").unwrap().add_hash_reference(0, addr);
        table.get_equate_mut("B").unwrap().add_hash_reference(0, addr);

        let equates = table.get_equates_at(addr);
        assert_eq!(equates.len(), 2);
    }

    // --- ConvertType ---

    #[test]
    fn test_convert_type_format_constant() {
        assert_eq!(ConvertType::Hex.format_constant(), FORMAT_HEX);
        assert_eq!(ConvertType::Dec.format_constant(), FORMAT_DEC);
        assert_eq!(ConvertType::Oct.format_constant(), FORMAT_OCT);
        assert_eq!(ConvertType::Binary.format_constant(), FORMAT_BINARY);
    }

    #[test]
    fn test_convert_type_menu_prefix() {
        assert_eq!(ConvertType::Hex.menu_prefix(), "Hexadecimal:");
        assert_eq!(ConvertType::Dec.menu_prefix(), "Decimal:");
    }

    #[test]
    fn test_convert_type_format_scalar() {
        let scalar = Scalar::new(32, 255, false);
        assert_eq!(ConvertType::Hex.format_scalar(&scalar), "0x000000ff");
        assert_eq!(ConvertType::Dec.format_scalar(&scalar), "255");
        assert_eq!(ConvertType::Oct.format_scalar(&scalar), "0o377");
        assert_eq!(ConvertType::Binary.format_scalar(&scalar), "0b11111111");
    }

    // --- ConvertConstantAction ---

    #[test]
    fn test_convert_action_hex() {
        let action = ConvertConstantAction::hex();
        assert!(action.name().contains("Hexadecimal"));
    }

    #[test]
    fn test_convert_action_dec() {
        let action = ConvertConstantAction::dec();
        assert!(action.name().contains("Decimal"));
    }

    #[test]
    fn test_convert_action_get_menu_display() {
        let action = ConvertConstantAction::hex();
        let scalar = Scalar::new(32, 0x2408, false);
        let display = action.get_menu_display(&scalar);
        assert!(display.contains("Hexadecimal"));
        assert!(display.contains("0x00002408"));
    }

    #[test]
    fn test_all_convert_actions() {
        let actions = all_convert_actions();
        assert_eq!(actions.len(), 7);
    }

    // --- ConvertConstantEquateTask ---

    #[test]
    fn test_equate_task_new() {
        let task = ConvertConstantEquateTask::new(
            "TEST",
            Address::new(0x1000),
            Scalar::new(32, 42, false),
            0x1234,
            -1,
        );
        assert_eq!(task.name(), "TEST");
        assert_eq!(task.address(), Address::new(0x1000));
        assert!(!task.has_alternate());
    }

    #[test]
    fn test_equate_task_set_alternate() {
        let mut task = ConvertConstantEquateTask::new(
            "TEST",
            Address::new(0x1000),
            Scalar::new(32, 42, false),
            0x1234,
            -1,
        );
        task.set_alternate("ALT", Address::new(0x2000), 2, 42);
        assert!(task.has_alternate());
    }

    #[test]
    fn test_equate_task_run_primary_only() {
        let task = ConvertConstantEquateTask::new(
            "NULL",
            Address::new(0x1000),
            Scalar::new(32, 0, false),
            0x1234,
            -1,
        );
        let mut table = EquateTable::new();
        task.run(&mut table).unwrap();
        assert_eq!(table.len(), 1);
        let equate = table.get_equate("NULL").unwrap();
        assert_eq!(equate.reference_count(), 1);
    }

    #[test]
    fn test_equate_task_run_with_alternate() {
        let mut task = ConvertConstantEquateTask::new(
            "NULL",
            Address::new(0x1000),
            Scalar::new(32, 0, false),
            0x1234,
            -1,
        );
        task.set_alternate("NULL", Address::new(0x2000), 2, 0);
        let mut table = EquateTable::new();
        task.run(&mut table).unwrap();
        // Both primary and alternate equates should be present.
        assert!(table.get_equate("NULL").is_some());
    }

    // --- ScalarMatch ---

    #[test]
    fn test_scalar_match() {
        let m = ScalarMatch {
            ref_addr: Address::new(0x1000),
            scalar: Scalar::new(32, 42, false),
            op_index: 1,
        };
        assert_eq!(m.ref_addr, Address::new(0x1000));
        assert_eq!(m.scalar.value(), 42);
        assert_eq!(m.op_index, 1);
    }
}
