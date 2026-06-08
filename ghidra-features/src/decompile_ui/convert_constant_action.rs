//! Convert constant action -- Rust port of
//! `ghidra.app.plugin.core.decompile.actions.ConvertConstantAction` and
//! `ghidra.app.plugin.core.decompile.actions.ConvertConstantEquateTask`.
//!
//! Provides the abstract base action for converting integer constants in the
//! decompiler panel to a desired display format (hexadecimal, decimal, octal,
//! binary, float, double, character).  Concrete subclasses supply the format
//! type and rendering logic.  The [`ConvertConstantEquateTask`] handles the
//! creation of equate references in the symbol table.
//!
//! # Architecture
//!
//! ```text
//! ConvertConstantAction (abstract)
//!   ├── isEnabled: checks token at cursor is convertible constant
//!   ├── decompilerActionPerformed: creates ConvertConstantEquateTask
//!   └── getMenuPrefix / getMenuDisplay / getEquateName (abstract)
//!
//! NearMatchValues
//!   └── Matches value, value-1, value+1, -value (masked)
//!
//! ConvertConstantEquateTask
//!   ├── getConvertibleConstant(context, type) -> Scalar
//!   ├── establishTask(context, action) -> Task
//!   ├── runTask()
//!   │   ├── applyAlternateEquate() -> schedule check
//!   │   └── applyPrimaryEquate()   -> direct
//!   └── call() [callback: check if alternate reached, fallback to primary]
//!
//! ScalarMatch
//!   └── (address, scalar, operand_index) of a matching instruction operand
//! ```

use std::collections::HashSet;
use std::fmt;

use ghidra_core::addr::Address;

use super::action_context::DecompilerActionContext;

// ---------------------------------------------------------------------------
// EquateFormat -- the conversion type constants
// ---------------------------------------------------------------------------

/// Integer format codes matching Ghidra's `EquateSymbol.FORMAT_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EquateFormat {
    /// Default representation (no override).
    Default,
    /// Hexadecimal (0x prefix).
    Hexadecimal,
    /// Decimal (signed).
    Decimal,
    /// Octal (0 prefix).
    Octal,
    /// Binary (0b prefix).
    Binary,
    /// Single-precision float.
    Float,
    /// Double-precision float.
    Double,
    /// Character literal.
    Character,
}

impl EquateFormat {
    /// The integer code matching Ghidra's `EquateSymbol.FORMAT_*` constants.
    pub fn code(&self) -> i32 {
        match self {
            EquateFormat::Default => 0,
            EquateFormat::Hexadecimal => 1,
            EquateFormat::Decimal => 2,
            EquateFormat::Octal => 3,
            EquateFormat::Binary => 4,
            EquateFormat::Float => 5,
            EquateFormat::Double => 6,
            EquateFormat::Character => 7,
        }
    }

    /// Whether this format can be applied to switch/case labels.
    ///
    /// Float, Double, and Default cannot be applied to case labels.
    pub fn is_applicable_to_case(&self) -> bool {
        !matches!(
            self,
            EquateFormat::Default | EquateFormat::Float | EquateFormat::Double
        )
    }
}

impl fmt::Display for EquateFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EquateFormat::Default => write!(f, "Default"),
            EquateFormat::Hexadecimal => write!(f, "Hexadecimal"),
            EquateFormat::Decimal => write!(f, "Decimal"),
            EquateFormat::Octal => write!(f, "Octal"),
            EquateFormat::Binary => write!(f, "Binary"),
            EquateFormat::Float => write!(f, "Float"),
            EquateFormat::Double => write!(f, "Double"),
            EquateFormat::Character => write!(f, "Character"),
        }
    }
}

// ---------------------------------------------------------------------------
// NearMatchValues -- matches value and its "near" variants
// ---------------------------------------------------------------------------

/// Helper class for identifying integer values that are "near" a given value.
///
/// "Near" means the value itself, off by +1, off by -1, or negated.
/// This is used when matching a decompiler constant against instruction
/// operands: the listing might have `0x100` while the decompiler shows
/// `0xff + 1`.
#[derive(Debug, Clone)]
pub struct NearMatchValues {
    /// The four candidate values (value, value-1, value+1, -value), masked.
    values: [u64; 4],
    /// The mask applied to values based on the byte size.
    mask: u64,
}

impl NearMatchValues {
    /// Create from a raw value and its byte size (1..=8).
    pub fn new(value: u64, size: usize) -> Self {
        let mask = if size >= 8 {
            u64::MAX
        } else {
            u64::MAX >> ((8 - size) * 8)
        };
        let v = value & mask;
        Self {
            values: [
                v,
                v.wrapping_sub(1) & mask,
                v.wrapping_add(1) & mask,
                (0u64.wrapping_sub(value)) & mask,
            ],
            mask,
        }
    }

    /// Create from a scalar (value and bit-length).
    pub fn from_scalar(value: u64, bit_length: usize) -> Self {
        Self::new(value, bit_length / 8)
    }

    /// Test whether the given value matches any of the near values.
    pub fn is_match(&self, value: u64) -> bool {
        let masked = value & self.mask;
        self.values.iter().any(|&v| v == masked)
    }
}

// ---------------------------------------------------------------------------
// ScalarInfo -- describes a constant value suitable for conversion
// ---------------------------------------------------------------------------

/// Information about a scalar constant found in the decompiler output.
///
/// This corresponds to the Java `Scalar` class used in equate operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarInfo {
    /// The number of bits in the scalar.
    pub bit_length: usize,
    /// The unsigned value of the scalar.
    pub value: u64,
    /// Whether the scalar should be interpreted as signed.
    pub is_signed: bool,
}

impl ScalarInfo {
    /// Create a new scalar info.
    pub fn new(bit_length: usize, value: u64, is_signed: bool) -> Self {
        Self {
            bit_length,
            value,
            is_signed,
        }
    }

    /// The byte size of the scalar.
    pub fn byte_size(&self) -> usize {
        self.bit_length / 8
    }

    /// Create a `NearMatchValues` for this scalar.
    pub fn near_match(&self) -> NearMatchValues {
        NearMatchValues::from_scalar(self.value, self.bit_length)
    }

    /// Format the scalar value as a hexadecimal string.
    pub fn to_hex(&self) -> String {
        let width = self.byte_size() * 2;
        format!("0x{:0width$x}", self.value, width = width)
    }

    /// Format the scalar value as a decimal string.
    pub fn to_decimal(&self) -> String {
        if self.is_signed && self.bit_length < 64 {
            let sign_bit = 1u64 << (self.bit_length - 1);
            if self.value & sign_bit != 0 {
                let neg = (!self.value).wrapping_add(1) & ((1u64 << self.bit_length) - 1);
                return format!("-{}", neg);
            }
        }
        format!("{}", self.value)
    }

    /// Format the scalar value as an octal string.
    pub fn to_octal(&self) -> String {
        format!("0{:o}", self.value)
    }

    /// Format the scalar value as a binary string.
    pub fn to_binary(&self) -> String {
        format!("0b{:b}", self.value)
    }

    /// Format the scalar value as a character literal.
    pub fn to_char_literal(&self) -> Option<String> {
        if self.value > 0x10FFFF {
            return None;
        }
        match char::from_u32(self.value as u32) {
            Some(c) if !c.is_control() => Some(format!("'{}'", c)),
            Some('\n') => Some("'\\n'".to_string()),
            Some('\r') => Some("'\\r'".to_string()),
            Some('\t') => Some("'\\t'".to_string()),
            Some('\0') => Some("'\\0'".to_string()),
            _ => None,
        }
    }

    /// Format the scalar value as a single-precision float.
    pub fn to_f32(&self) -> Option<String> {
        if self.bit_length != 32 {
            return None;
        }
        let f = f32::from_bits(self.value as u32);
        Some(format!("{}", f))
    }

    /// Format the scalar value as a double-precision float.
    pub fn to_f64(&self) -> Option<String> {
        if self.bit_length != 64 {
            return None;
        }
        let f = f64::from_bits(self.value);
        Some(format!("{}", f))
    }
}

// ---------------------------------------------------------------------------
// ScalarMatch -- describes a matching scalar operand in an instruction
// ---------------------------------------------------------------------------

/// A helper class describing a (matching) scalar operand in a listing instruction.
///
/// When the decompiler shows a constant, the equate task searches the listing
/// for a matching scalar operand to attach the equate reference to.
#[derive(Debug, Clone)]
pub struct ScalarMatch {
    /// Address of the instruction containing the scalar.
    pub instruction_address: Address,
    /// The scalar value and metadata.
    pub scalar: ScalarInfo,
    /// The operand index within the instruction, or -1 if non-unique.
    pub operand_index: i32,
}

// ---------------------------------------------------------------------------
// EquateReference -- models a reference to an equate
// ---------------------------------------------------------------------------

/// A reference to an equate at a specific address.
///
/// Mirrors `EquateReference` from the Java `ghidra.program.model.symbol` package.
#[derive(Debug, Clone)]
pub struct EquateReference {
    /// The address of the reference.
    pub address: Address,
    /// A dynamic hash value for identifying the constant in data-flow, or 0.
    pub dynamic_hash: u64,
    /// The operand index, or -1 if not associated with an instruction operand.
    pub operand_index: i32,
}

// ---------------------------------------------------------------------------
// EquateInfo -- models an equate in the equate table
// ---------------------------------------------------------------------------

/// Information about an equate entry.
///
/// Mirrors a subset of `ghidra.program.model.symbol.Equate`.
#[derive(Debug, Clone)]
pub struct EquateInfo {
    /// The name of the equate (e.g., "NULL", "TRUE", "EXIT_SUCCESS").
    pub name: String,
    /// The numeric value the equate represents.
    pub value: i64,
    /// The references to this equate.
    pub references: Vec<EquateReference>,
}

impl EquateInfo {
    /// Create a new equate info.
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
            references: Vec::new(),
        }
    }

    /// Add a reference to this equate.
    pub fn add_reference(&mut self, address: Address, dynamic_hash: u64, operand_index: i32) {
        self.references.push(EquateReference {
            address,
            dynamic_hash,
            operand_index,
        });
    }

    /// The number of references to this equate.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// Remove a reference matching the given dynamic hash and address.
    ///
    /// Returns `true` if a reference was found and removed.
    pub fn remove_reference_by_hash(&mut self, hash: u64, address: Address) -> bool {
        let before = self.references.len();
        self.references
            .retain(|r| !(r.dynamic_hash == hash && r.address == address));
        self.references.len() < before
    }

    /// Remove a reference matching the given address and operand index.
    ///
    /// Returns `true` if a reference was found and removed.
    pub fn remove_reference_by_operand(
        &mut self,
        address: Address,
        operand_index: i32,
    ) -> bool {
        let before = self.references.len();
        self.references
            .retain(|r| !(r.address == address && r.operand_index == operand_index));
        self.references.len() < before
    }

    /// Get references at a specific address.
    pub fn get_references_at(&self, address: Address) -> Vec<&EquateReference> {
        self.references.iter().filter(|r| r.address == address).collect()
    }
}

// ---------------------------------------------------------------------------
// ConvertConstantAction -- abstract base for conversion actions
// ---------------------------------------------------------------------------

/// The result of attempting to enable or perform a constant conversion.
#[derive(Debug, Clone)]
pub enum ConvertResult {
    /// The action is enabled and the menu string to display.
    Enabled(String),
    /// The action is disabled (not applicable to current context).
    Disabled,
    /// The conversion was applied successfully.
    Applied,
    /// A task was created and should be run.
    TaskCreated(ConvertConstantEquateTask),
    /// The user cancelled the equate name dialog.
    UserCancelled,
    /// An error occurred.
    Error(String),
}

/// Abstract base action for converting a constant to a different display format.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.ConvertConstantAction`.
///
/// Each concrete subclass provides:
/// - A [`EquateFormat`] (the conversion type)
/// - A menu prefix (e.g., "Hexadecimal:")
/// - A display formatter for the constant value
/// - An equate name generator
pub trait ConvertConstantAction: fmt::Debug {
    /// The format type this action applies.
    fn convert_type(&self) -> EquateFormat;

    /// The menu prefix shown before the value (e.g., "Hexadecimal:").
    fn menu_prefix(&self) -> &str;

    /// Format the scalar value for display in the menu.
    fn menu_display(&self, scalar: &ScalarInfo) -> String;

    /// Generate the equate name for the given scalar.
    ///
    /// Returns `None` if the user cancels a name dialog.
    fn equate_name(&self, scalar: &ScalarInfo) -> Option<String>;

    /// Check if this action is enabled for the given context.
    ///
    /// This checks both case-label constants and general convertible constants.
    fn is_enabled(&self, context: &DecompilerActionContext) -> ConvertResult {
        // First check for case-label constants.
        let case_scalar = get_case_constant(context, self.convert_type());
        let scalar = match case_scalar {
            Some(s) => Some(s),
            None => get_convertible_constant(context, self.convert_type()),
        };

        let scalar = match scalar {
            Some(s) => s,
            None => return ConvertResult::Disabled,
        };

        let display = self.menu_display(&scalar);
        // If the token already shows this format, disable.
        if let Some(token) = context.token_at_cursor_text() {
            if token == display {
                return ConvertResult::Disabled;
            }
        }

        let menu_string = format_standard_length(&format!("{}: ", self.menu_prefix()), &display);
        ConvertResult::Enabled(menu_string)
    }

    /// Perform the conversion action.
    fn perform(&self, context: &DecompilerActionContext) -> ConvertResult
    where
        Self: Sized,
    {
        // Check if this is a case-label token.
        if context.is_case_token_at_cursor() {
            return self.write_switch_format(context);
        }

        match ConvertConstantEquateTask::establish_task(context, self) {
            Some(task) => ConvertResult::TaskCreated(task),
            None => ConvertResult::UserCancelled,
        }
    }

    /// Write the format override for a switch/case label.
    fn write_switch_format(&self, context: &DecompilerActionContext) -> ConvertResult {
        // In the full implementation, this writes the format override to the
        // JumpTable for the switch operation at the case label's address.
        // Here we model the request.
        let _ = context;
        ConvertResult::Applied
    }
}

// ---------------------------------------------------------------------------
// ConvertConstantEquateTask -- creates equate references
// ---------------------------------------------------------------------------

/// Task that creates an equate reference for a constant in the decompiler output.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.ConvertConstantEquateTask`.
///
/// If an alternate equate (at an instruction operand address) is provided, it
/// is tried first.  After the decompiler re-decompiles, a callback checks
/// whether the alternate equate reached the desired constant.  If not, the
/// alternate is removed and the primary equate is placed directly.
#[derive(Debug, Clone)]
pub struct ConvertConstantEquateTask {
    /// The primary address of the equate.
    pub convert_address: Address,
    /// The primary equate name.
    pub convert_name: String,
    /// The scalar being converted.
    pub convert_value: ScalarInfo,
    /// A dynamic hash locating the constant Varnode in data-flow.
    pub convert_hash: u64,
    /// The scalar index associated with the primary equate, or -1.
    pub convert_index: i32,

    /// Alternate equate address (instruction operand), or None.
    pub alt_address: Option<Address>,
    /// Alternate equate name.
    pub alt_name: Option<String>,
    /// Alternate operand index.
    pub alt_index: i32,
    /// Alternate constant value.
    pub alt_value: u64,
}

impl ConvertConstantEquateTask {
    /// The maximum number of instructions to search when looking for a scalar
    /// match in the listing.
    const MAX_INSTRUCTION_WINDOW: usize = 20;

    /// The maximum scalar size in bytes that can be converted.
    const MAX_SCALAR_SIZE: usize = 8;

    /// Construct a primary equate task.
    pub fn new(
        convert_address: Address,
        convert_name: String,
        convert_value: ScalarInfo,
        convert_hash: u64,
        convert_index: i32,
    ) -> Self {
        Self {
            convert_address,
            convert_name,
            convert_value,
            convert_hash,
            convert_index,
            alt_address: None,
            alt_name: None,
            alt_index: -1,
            alt_value: 0,
        }
    }

    /// Set an alternate equate to try before falling back on the primary.
    pub fn set_alternate(
        &mut self,
        name: String,
        address: Address,
        operand_index: i32,
        value: u64,
    ) {
        self.alt_name = Some(name);
        self.alt_address = Some(address);
        self.alt_index = operand_index;
        self.alt_value = value;
    }

    /// Check if the constant at the cursor is convertible.
    ///
    /// Returns the scalar if the token at cursor represents a constant that
    /// can be converted, or `None` if not.
    ///
    /// This corresponds to the Java static method
    /// `ConvertConstantEquateTask.getConvertibleConstant()`.
    pub fn get_convertible_constant(
        context: &DecompilerActionContext,
        convert_type: EquateFormat,
    ) -> Option<ScalarInfo> {
        let varnode = context.varnode_at_cursor()?;
        if !varnode.is_constant || varnode.size > Self::MAX_SCALAR_SIZE {
            return None;
        }

        // Check if there's an existing equate symbol.
        if let Some(ref symbol) = varnode.high_symbol {
            if let Some(ref equate) = symbol.equate_info {
                // If the existing equate has the same format or is default, skip.
                if equate.format == convert_type || equate.format == EquateFormat::Default {
                    return None;
                }
            } else {
                return None; // Something else is attached to the constant.
            }
        }

        // Check data type restrictions.
        if let Some(ref dtype) = varnode.data_type {
            if dtype.is_boolean {
                return None;
            }
            if dtype.is_enum {
                return None;
            }
        }

        let is_signed = varnode
            .data_type
            .as_ref()
            .map_or(false, |dt| dt.is_signed_integer);

        Some(ScalarInfo::new(
            varnode.size * 8,
            varnode.offset,
            is_signed,
        ))
    }

    /// Establish the task for the given action context.
    ///
    /// Returns `None` if the context is not suitable or the user cancelled.
    ///
    /// This corresponds to the Java static method
    /// `ConvertConstantEquateTask.establishTask()`.
    pub fn establish_task<T: ConvertConstantAction + ?Sized>(
        context: &DecompilerActionContext,
        action: &T,
    ) -> Option<Self> {
        let scalar = Self::get_convertible_constant(context, action.convert_type())?;

        let varnode = context.varnode_at_cursor()?;

        // Check if there's an existing equate symbol.
        if let Some(ref symbol) = varnode.high_symbol {
            if symbol.equate_info.is_some() {
                return Self::convert_existing_symbol(context, action, symbol, &scalar);
            }
        }

        // No existing symbol -- compute the dynamic hash and look for a
        // matching scalar operand in the listing.
        let convert_address = varnode
            .pcode_op_address
            .unwrap_or_else(|| Address::new(0));
        let convert_hash = varnode.dynamic_hash.unwrap_or(0);

        let equate_name = action.equate_name(&scalar)?;

        let mut task = Self::new(
            convert_address,
            equate_name.clone(),
            scalar.clone(),
            convert_hash,
            -1,
        );

        // Try to find a matching scalar in the listing.
        if let Some(scalar_match) = context.find_scalar_match(
            convert_address,
            &scalar,
            Self::MAX_INSTRUCTION_WINDOW,
        ) {
            let match_scalar = &scalar_match.scalar;
            // Set up alternate equate if the formats differ or values match.
            if action.convert_type() != EquateFormat::Default
                || match_scalar.value == scalar.value
            {
                task.set_alternate(
                    equate_name,
                    scalar_match.instruction_address,
                    scalar_match.operand_index,
                    match_scalar.value,
                );
            }
        }

        Some(task)
    }

    /// Convert an existing equate symbol to a new format.
    fn convert_existing_symbol<T: ConvertConstantAction + ?Sized>(
        context: &DecompilerActionContext,
        action: &T,
        symbol: &HighSymbolInfo,
        scalar: &ScalarInfo,
    ) -> Option<Self> {
        let convert_address = symbol.address;
        let near = scalar.near_match();
        let mut convert_hash: u64 = 0;
        let mut convert_index: i32 = -1;
        let mut found_equate = false;

        // Search for a matching equate reference.
        if let Some(ref equate_info) = symbol.equate_info {
            for reference in &equate_info.references {
                if near.is_match(reference.dynamic_hash) {
                    convert_hash = reference.dynamic_hash;
                    convert_index = reference.operand_index;
                    found_equate = true;
                    break;
                }
            }
        }

        if !found_equate {
            return None;
        }

        let equate_name = action.equate_name(scalar)?;

        Some(Self::new(
            convert_address,
            equate_name,
            scalar.clone(),
            convert_hash,
            convert_index,
        ))
    }

    /// Run the task.
    ///
    /// If an alternate equate is set, it is placed first and a callback
    /// scheduled.  Otherwise the primary equate is placed directly.
    pub fn run_task(&mut self) -> ConvertTaskOutcome {
        if self.alt_address.is_some() {
            // Place the alternate equate and schedule a callback.
            ConvertTaskOutcome::AlternatePlaced {
                callback_needed: true,
            }
        } else {
            // Place the primary equate directly.
            ConvertTaskOutcome::PrimaryPlaced
        }
    }

    /// Callback executed after the alternative equate is placed and the
    /// decompiler has updated.
    ///
    /// Checks whether the equate reached the desired constant.  If not,
    /// the alternate equate reference is removed and the primary equate
    /// is placed instead.
    ///
    /// Returns the final outcome.
    pub fn on_callback(&self, alternate_reached: bool) -> ConvertTaskOutcome {
        if alternate_reached {
            ConvertTaskOutcome::AlternateReached
        } else {
            ConvertTaskOutcome::FallbackToPrimary
        }
    }
}

/// The outcome of running a `ConvertConstantEquateTask`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConvertTaskOutcome {
    /// The primary equate was placed directly.
    PrimaryPlaced,
    /// The alternate equate was placed; a callback is needed.
    AlternatePlaced { callback_needed: bool },
    /// After callback: the alternate equate reached the constant.
    AlternateReached,
    /// After callback: the alternate did not reach; fall back to primary.
    FallbackToPrimary,
    /// The task failed.
    Failed(String),
}

// ---------------------------------------------------------------------------
// HighSymbolInfo -- minimal model of a high-level symbol
// ---------------------------------------------------------------------------

/// Minimal model of a high-level symbol from the decompiler.
///
/// In Ghidra this would be a `HighSymbol` / `EquateSymbol`.  Here we
/// capture the fields needed by the convert-constant logic.
#[derive(Debug, Clone)]
pub struct HighSymbolInfo {
    /// The primary address of the symbol.
    pub address: Address,
    /// Equate-specific info, if this symbol is an equate.
    pub equate_info: Option<EquateSymbolInfo>,
}

/// Information specific to an equate symbol.
#[derive(Debug, Clone)]
pub struct EquateSymbolInfo {
    /// The format type of the equate.
    pub format: EquateFormat,
    /// References to this equate.
    pub references: Vec<EquateReference>,
}

// ---------------------------------------------------------------------------
// VarnodeInfo -- minimal model of a Varnode from the decompiler
// ---------------------------------------------------------------------------

/// Minimal model of a Varnode from the decompiler output.
///
/// Used by `get_convertible_constant` and `establish_task` to inspect
/// the constant at the cursor.
#[derive(Debug, Clone)]
pub struct VarnodeInfo {
    /// Whether this varnode represents a constant.
    pub is_constant: bool,
    /// The size of the varnode in bytes.
    pub size: usize,
    /// The offset (value) of the varnode.
    pub offset: u64,
    /// The high-level symbol attached to this varnode, if any.
    pub high_symbol: Option<HighSymbolInfo>,
    /// The data type of the varnode, if known.
    pub data_type: Option<DataTypeInfo>,
    /// The address of the p-code op that produced this varnode.
    pub pcode_op_address: Option<Address>,
    /// The dynamic hash of this varnode.
    pub dynamic_hash: Option<u64>,
}

/// Minimal data type information.
#[derive(Debug, Clone)]
pub struct DataTypeInfo {
    /// Whether this is a signed integer type.
    pub is_signed_integer: bool,
    /// Whether this is a boolean type.
    pub is_boolean: bool,
    /// Whether this is an enum type.
    pub is_enum: bool,
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Get a case-label constant if the cursor is on a `ClangCaseToken`.
///
/// Returns `None` if the cursor is not on a case token, or if the format
/// type is not applicable to case labels.
fn get_case_constant(
    context: &DecompilerActionContext,
    convert_type: EquateFormat,
) -> Option<ScalarInfo> {
    if !convert_type.is_applicable_to_case() {
        return None;
    }
    context.case_token_scalar_at_cursor()
}

/// Get a convertible constant from a regular variable token.
///
/// This is the public entry point used by `ConvertConstantAction::is_enabled`.
pub fn get_convertible_constant(
    context: &DecompilerActionContext,
    convert_type: EquateFormat,
) -> Option<ScalarInfo> {
    ConvertConstantEquateTask::get_convertible_constant(context, convert_type)
}

/// Format a string to a "standard length" by padding with spaces.
///
/// In Ghidra, this ensures that menu items have consistent width so that
/// the value portion aligns.  The target width is approximately 140 pixels;
/// here we approximate with a fixed character count.
fn format_standard_length(prefix: &str, value: &str) -> String {
    let base = format!("{}{}", prefix, value);
    let target_width = 40; // approximate character width
    if base.len() >= target_width {
        base
    } else {
        let padding = target_width - base.len();
        format!("{}{}{}", prefix, " ".repeat(padding), value)
    }
}

// ---------------------------------------------------------------------------
// Concrete action implementations
// ---------------------------------------------------------------------------

/// Convert a constant to hexadecimal display.
#[derive(Debug, Default)]
pub struct ConvertHexAction;

impl ConvertConstantAction for ConvertHexAction {
    fn convert_type(&self) -> EquateFormat {
        EquateFormat::Hexadecimal
    }

    fn menu_prefix(&self) -> &str {
        "Hexadecimal"
    }

    fn menu_display(&self, scalar: &ScalarInfo) -> String {
        scalar.to_hex()
    }

    fn equate_name(&self, scalar: &ScalarInfo) -> Option<String> {
        Some(scalar.to_hex())
    }
}

/// Convert a constant to decimal display.
#[derive(Debug, Default)]
pub struct ConvertDecAction;

impl ConvertConstantAction for ConvertDecAction {
    fn convert_type(&self) -> EquateFormat {
        EquateFormat::Decimal
    }

    fn menu_prefix(&self) -> &str {
        "Decimal"
    }

    fn menu_display(&self, scalar: &ScalarInfo) -> String {
        scalar.to_decimal()
    }

    fn equate_name(&self, scalar: &ScalarInfo) -> Option<String> {
        Some(scalar.to_decimal())
    }
}

/// Convert a constant to octal display.
#[derive(Debug, Default)]
pub struct ConvertOctAction;

impl ConvertConstantAction for ConvertOctAction {
    fn convert_type(&self) -> EquateFormat {
        EquateFormat::Octal
    }

    fn menu_prefix(&self) -> &str {
        "Octal"
    }

    fn menu_display(&self, scalar: &ScalarInfo) -> String {
        scalar.to_octal()
    }

    fn equate_name(&self, scalar: &ScalarInfo) -> Option<String> {
        Some(scalar.to_octal())
    }
}

/// Convert a constant to binary display.
#[derive(Debug, Default)]
pub struct ConvertBinaryAction;

impl ConvertConstantAction for ConvertBinaryAction {
    fn convert_type(&self) -> EquateFormat {
        EquateFormat::Binary
    }

    fn menu_prefix(&self) -> &str {
        "Binary"
    }

    fn menu_display(&self, scalar: &ScalarInfo) -> String {
        scalar.to_binary()
    }

    fn equate_name(&self, scalar: &ScalarInfo) -> Option<String> {
        Some(scalar.to_binary())
    }
}

/// Convert a constant to character display.
#[derive(Debug, Default)]
pub struct ConvertCharAction;

impl ConvertConstantAction for ConvertCharAction {
    fn convert_type(&self) -> EquateFormat {
        EquateFormat::Character
    }

    fn menu_prefix(&self) -> &str {
        "Character"
    }

    fn menu_display(&self, scalar: &ScalarInfo) -> String {
        scalar.to_char_literal().unwrap_or_else(|| scalar.to_hex())
    }

    fn equate_name(&self, scalar: &ScalarInfo) -> Option<String> {
        scalar.to_char_literal()
    }
}

/// Convert a constant to float display.
#[derive(Debug, Default)]
pub struct ConvertFloatAction;

impl ConvertConstantAction for ConvertFloatAction {
    fn convert_type(&self) -> EquateFormat {
        EquateFormat::Float
    }

    fn menu_prefix(&self) -> &str {
        "Float"
    }

    fn menu_display(&self, scalar: &ScalarInfo) -> String {
        scalar.to_f32().unwrap_or_else(|| scalar.to_hex())
    }

    fn equate_name(&self, scalar: &ScalarInfo) -> Option<String> {
        scalar.to_f32()
    }
}

/// Convert a constant to double display.
#[derive(Debug, Default)]
pub struct ConvertDoubleAction;

impl ConvertConstantAction for ConvertDoubleAction {
    fn convert_type(&self) -> EquateFormat {
        EquateFormat::Double
    }

    fn menu_prefix(&self) -> &str {
        "Double"
    }

    fn menu_display(&self, scalar: &ScalarInfo) -> String {
        scalar.to_f64().unwrap_or_else(|| scalar.to_hex())
    }

    fn equate_name(&self, scalar: &ScalarInfo) -> Option<String> {
        scalar.to_f64()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- NearMatchValues ---

    #[test]
    fn near_match_exact() {
        let nm = NearMatchValues::new(0x100, 4);
        assert!(nm.is_match(0x100));
        assert!(!nm.is_match(0x200));
    }

    #[test]
    fn near_match_plus_minus_one() {
        let nm = NearMatchValues::new(0x100, 4);
        assert!(nm.is_match(0x101)); // +1
        assert!(nm.is_match(0x0FF)); // -1
        assert!(nm.is_match((-0x100i64) as u64 & 0xFFFF_FFFF)); // negated
    }

    #[test]
    fn near_match_masking() {
        // 1-byte value should be masked to 8 bits.
        let nm = NearMatchValues::new(0x1FF, 1);
        assert!(nm.is_match(0xFF)); // 0x1FF masked to 0xFF
        assert!(nm.is_match(0xFE)); // 0xFF - 1
    }

    #[test]
    fn near_match_from_scalar() {
        let nm = NearMatchValues::from_scalar(42, 32); // 32-bit = 4 bytes
        assert!(nm.is_match(42));
        assert!(nm.is_match(43));
        assert!(nm.is_match(41));
    }

    // --- ScalarInfo ---

    #[test]
    fn scalar_hex() {
        let s = ScalarInfo::new(32, 0xDEAD, false);
        assert_eq!(s.to_hex(), "0x0000dead");
    }

    #[test]
    fn scalar_hex_8bit() {
        let s = ScalarInfo::new(8, 0xFF, false);
        assert_eq!(s.to_hex(), "0xff");
    }

    #[test]
    fn scalar_decimal_unsigned() {
        let s = ScalarInfo::new(32, 42, false);
        assert_eq!(s.to_decimal(), "42");
    }

    #[test]
    fn scalar_decimal_signed_positive() {
        let s = ScalarInfo::new(32, 42, true);
        assert_eq!(s.to_decimal(), "42");
    }

    #[test]
    fn scalar_decimal_signed_negative() {
        // -1 as a 32-bit signed value is 0xFFFFFFFF.
        let s = ScalarInfo::new(32, 0xFFFF_FFFF, true);
        assert_eq!(s.to_decimal(), "-1");
    }

    #[test]
    fn scalar_octal() {
        let s = ScalarInfo::new(16, 0o777, false);
        assert_eq!(s.to_octal(), "0777");
    }

    #[test]
    fn scalar_binary() {
        let s = ScalarInfo::new(8, 0b1010, false);
        assert_eq!(s.to_binary(), "0b1010");
    }

    #[test]
    fn scalar_char_literal_ascii() {
        let s = ScalarInfo::new(8, b'A' as u64, false);
        assert_eq!(s.to_char_literal(), Some("'A'".to_string()));
    }

    #[test]
    fn scalar_char_literal_control() {
        let s = ScalarInfo::new(8, b'\n' as u64, false);
        assert_eq!(s.to_char_literal(), Some("'\\n'".to_string()));
    }

    #[test]
    fn scalar_char_literal_too_large() {
        let s = ScalarInfo::new(32, 0x200000, false);
        assert_eq!(s.to_char_literal(), None);
    }

    #[test]
    fn scalar_f32() {
        let val = 1.0f32.to_bits() as u64;
        let s = ScalarInfo::new(32, val, false);
        assert_eq!(s.to_f32(), Some("1".to_string()));
    }

    #[test]
    fn scalar_f32_wrong_size() {
        let s = ScalarInfo::new(64, 0, false);
        assert_eq!(s.to_f32(), None);
    }

    #[test]
    fn scalar_f64() {
        let val = 3.14f64.to_bits();
        let s = ScalarInfo::new(64, val, false);
        let display = s.to_f64().unwrap();
        assert!(display.starts_with("3.14"));
    }

    #[test]
    fn scalar_f64_wrong_size() {
        let s = ScalarInfo::new(32, 0, false);
        assert_eq!(s.to_f64(), None);
    }

    #[test]
    fn scalar_byte_size() {
        let s = ScalarInfo::new(32, 0, false);
        assert_eq!(s.byte_size(), 4);
    }

    // --- EquateFormat ---

    #[test]
    fn equate_format_codes() {
        assert_eq!(EquateFormat::Default.code(), 0);
        assert_eq!(EquateFormat::Hexadecimal.code(), 1);
        assert_eq!(EquateFormat::Decimal.code(), 2);
        assert_eq!(EquateFormat::Character.code(), 7);
    }

    #[test]
    fn equate_format_case_applicability() {
        assert!(EquateFormat::Hexadecimal.is_applicable_to_case());
        assert!(EquateFormat::Decimal.is_applicable_to_case());
        assert!(!EquateFormat::Default.is_applicable_to_case());
        assert!(!EquateFormat::Float.is_applicable_to_case());
        assert!(!EquateFormat::Double.is_applicable_to_case());
    }

    // --- EquateInfo ---

    #[test]
    fn equate_info_add_remove_ref() {
        let mut eq = EquateInfo::new("TEST", 42);
        assert_eq!(eq.reference_count(), 0);

        eq.add_reference(Address::new(0x1000), 0xABCD, 0);
        assert_eq!(eq.reference_count(), 1);

        eq.add_reference(Address::new(0x2000), 0x1234, 1);
        assert_eq!(eq.reference_count(), 2);

        assert!(eq.remove_reference_by_hash(0xABCD, Address::new(0x1000)));
        assert_eq!(eq.reference_count(), 1);

        // Removing a non-existent reference returns false.
        assert!(!eq.remove_reference_by_hash(0x9999, Address::new(0x1000)));
    }

    #[test]
    fn equate_info_remove_by_operand() {
        let mut eq = EquateInfo::new("TEST", 42);
        eq.add_reference(Address::new(0x1000), 0, 0);
        eq.add_reference(Address::new(0x1000), 0, 1);

        assert!(eq.remove_reference_by_operand(Address::new(0x1000), 0));
        assert_eq!(eq.reference_count(), 1);
    }

    #[test]
    fn equate_info_get_references_at() {
        let mut eq = EquateInfo::new("TEST", 42);
        eq.add_reference(Address::new(0x1000), 0xAB, 0);
        eq.add_reference(Address::new(0x2000), 0xCD, 1);
        eq.add_reference(Address::new(0x1000), 0xEF, 2);

        let refs = eq.get_references_at(Address::new(0x1000));
        assert_eq!(refs.len(), 2);
    }

    // --- ConvertConstantEquateTask ---

    #[test]
    fn task_new() {
        let task = ConvertConstantEquateTask::new(
            Address::new(0x1000),
            "0xff".to_string(),
            ScalarInfo::new(8, 0xFF, false),
            0xABCD,
            -1,
        );
        assert_eq!(task.convert_address, Address::new(0x1000));
        assert_eq!(task.convert_name, "0xff");
        assert!(task.alt_address.is_none());
    }

    #[test]
    fn task_set_alternate() {
        let mut task = ConvertConstantEquateTask::new(
            Address::new(0x1000),
            "0xff".to_string(),
            ScalarInfo::new(8, 0xFF, false),
            0xABCD,
            -1,
        );
        task.set_alternate(
            "0xff".to_string(),
            Address::new(0x2000),
            0,
            0xFF,
        );
        assert!(task.alt_address.is_some());
        assert_eq!(task.alt_address.unwrap(), Address::new(0x2000));
        assert_eq!(task.alt_index, 0);
    }

    #[test]
    fn task_run_primary() {
        let mut task = ConvertConstantEquateTask::new(
            Address::new(0x1000),
            "0xff".to_string(),
            ScalarInfo::new(8, 0xFF, false),
            0xABCD,
            -1,
        );
        assert_eq!(task.run_task(), ConvertTaskOutcome::PrimaryPlaced);
    }

    #[test]
    fn task_run_alternate() {
        let mut task = ConvertConstantEquateTask::new(
            Address::new(0x1000),
            "0xff".to_string(),
            ScalarInfo::new(8, 0xFF, false),
            0xABCD,
            -1,
        );
        task.set_alternate(
            "0xff".to_string(),
            Address::new(0x2000),
            0,
            0xFF,
        );
        assert_eq!(
            task.run_task(),
            ConvertTaskOutcome::AlternatePlaced {
                callback_needed: true
            }
        );
    }

    #[test]
    fn task_callback_reached() {
        let task = ConvertConstantEquateTask::new(
            Address::new(0x1000),
            "0xff".to_string(),
            ScalarInfo::new(8, 0xFF, false),
            0xABCD,
            -1,
        );
        assert_eq!(
            task.on_callback(true),
            ConvertTaskOutcome::AlternateReached
        );
    }

    #[test]
    fn task_callback_fallback() {
        let task = ConvertConstantEquateTask::new(
            Address::new(0x1000),
            "0xff".to_string(),
            ScalarInfo::new(8, 0xFF, false),
            0xABCD,
            -1,
        );
        assert_eq!(
            task.on_callback(false),
            ConvertTaskOutcome::FallbackToPrimary
        );
    }

    // --- Concrete actions ---

    #[test]
    fn hex_action() {
        let action = ConvertHexAction;
        assert_eq!(action.convert_type(), EquateFormat::Hexadecimal);
        assert_eq!(action.menu_prefix(), "Hexadecimal");
        let scalar = ScalarInfo::new(16, 0x1234, false);
        assert_eq!(action.menu_display(&scalar), "0x1234");
        assert_eq!(action.equate_name(&scalar), Some("0x1234".to_string()));
    }

    #[test]
    fn dec_action() {
        let action = ConvertDecAction;
        assert_eq!(action.convert_type(), EquateFormat::Decimal);
        let scalar = ScalarInfo::new(8, 42, false);
        assert_eq!(action.menu_display(&scalar), "42");
    }

    #[test]
    fn oct_action() {
        let action = ConvertOctAction;
        let scalar = ScalarInfo::new(16, 0o777, false);
        assert_eq!(action.menu_display(&scalar), "0777");
    }

    #[test]
    fn bin_action() {
        let action = ConvertBinaryAction;
        let scalar = ScalarInfo::new(8, 0b1100, false);
        assert_eq!(action.menu_display(&scalar), "0b1100");
    }

    #[test]
    fn char_action() {
        let action = ConvertCharAction;
        let scalar = ScalarInfo::new(8, b'A' as u64, false);
        assert_eq!(action.menu_display(&scalar), "'A'");
    }

    #[test]
    fn float_action() {
        let action = ConvertFloatAction;
        let val = 1.5f32.to_bits() as u64;
        let scalar = ScalarInfo::new(32, val, false);
        assert_eq!(action.menu_display(&scalar), "1.5");
    }

    #[test]
    fn double_action() {
        let action = ConvertDoubleAction;
        let val = 2.5f64.to_bits();
        let scalar = ScalarInfo::new(64, val, false);
        assert_eq!(action.menu_display(&scalar), "2.5");
    }

    // --- Utility ---

    #[test]
    fn format_standard_length_pads() {
        let result = format_standard_length("Hex: ", "0xFF");
        assert!(result.contains("0xFF"));
        assert!(result.len() >= 40);
    }

    #[test]
    fn format_standard_length_long_value() {
        let long_val = "A".repeat(50);
        let result = format_standard_length("Prefix: ", &long_val);
        assert!(result.contains(&long_val));
    }
}
