//! SLEIGH operand symbol: abstract operands in constructor templates.
//!
//! An [`OperandSymbol`] represents an abstract operand within a constructor.
//! When a constructor matches, the operand is resolved to a concrete value
//! by extracting bits from the instruction stream.
//!
//! Operands can be:
//! - **Immediate values** -- constants extracted from the instruction
//! - **Register references** -- named registers resolved through a subtable
//! - **Address references** -- memory addresses computed from fields
//! - **Code addresses** -- branch/call targets
//!
//! # Key Types
//! - [`OperandSymbol`] -- an abstract operand with index, flags, and defining info
//! - [`OperandFlags`] -- bitflags for operand properties

use serde::{Deserialize, Serialize};
use std::fmt;

use super::sleigh_symbol::{Location, SymbolType};

// ---------------------------------------------------------------------------
// OperandFlags
// ---------------------------------------------------------------------------

/// Bitflags for operand properties.
///
/// These flags are set during SLEIGH compilation to indicate special
/// properties of an operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperandFlags(u32);

impl OperandFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// This operand is a code address (branch/call target).
    pub const CODE_ADDRESS: Self = Self(1);
    /// The offset is irrelevant for this operand.
    pub const OFFSET_IRREL: Self = Self(2);
    /// This operand has variable length.
    pub const VARIABLE_LEN: Self = Self(4);
    /// This operand has been marked (for traversal).
    pub const MARKED: Self = Self(8);

    /// Create flags from a raw u32.
    pub fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw u32 value.
    pub fn raw(&self) -> u32 {
        self.0
    }

    /// Returns `true` if the code address flag is set.
    pub fn is_code_address(&self) -> bool {
        self.0 & Self::CODE_ADDRESS.0 != 0
    }

    /// Returns `true` if the offset irrelevant flag is set.
    pub fn is_offset_irrelevant(&self) -> bool {
        self.0 & Self::OFFSET_IRREL.0 != 0
    }

    /// Returns `true` if the variable length flag is set.
    pub fn is_variable_length(&self) -> bool {
        self.0 & Self::VARIABLE_LEN.0 != 0
    }

    /// Returns `true` if the marked flag is set.
    pub fn is_marked(&self) -> bool {
        self.0 & Self::MARKED.0 != 0
    }

    /// Set a flag.
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Clear a flag.
    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }
}

impl Default for OperandFlags {
    fn default() -> Self {
        Self::NONE
    }
}

impl fmt::Display for OperandFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.is_code_address() {
            flags.push("code");
        }
        if self.is_offset_irrelevant() {
            flags.push("off_irrel");
        }
        if self.is_variable_length() {
            flags.push("var_len");
        }
        if self.is_marked() {
            flags.push("marked");
        }
        if flags.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", flags.join("|"))
        }
    }
}

// ---------------------------------------------------------------------------
// OperandSymbol
// ---------------------------------------------------------------------------

/// An abstract operand within a constructor.
///
/// `OperandSymbol` is a `SpecificSymbol` that resolves to a concrete varnode
/// when the parent constructor matches. It has:
///
/// - An **index** (handle index) that identifies this operand within the
///   constructor's operand list
/// - A **local expression** that extracts the operand's value from the
///   instruction stream
/// - A **defining symbol** or **defining expression** that determines the
///   operand's final value
/// - **Flags** indicating special properties
///
/// # Lifecycle
///
/// 1. Created during `.slaspec` parsing with an index and parent constructor
/// 2. `define_operand()` is called to set the defining symbol or expression
/// 3. During disassembly, the operand is resolved by evaluating the local
///    expression and then the defining expression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperandSymbol {
    /// Symbol name
    pub name: String,
    /// Symbol id
    pub id: usize,
    /// Scope id
    pub scope_id: usize,
    /// Source location
    pub location: Location,
    /// Handle index (position in the constructor's operand list)
    pub index: usize,
    /// Relative offset within the instruction
    pub relative_offset: i32,
    /// Base operand for relative offset (-1 = constructor start)
    pub offset_base: i32,
    /// Minimum size of this operand in bytes (within instruction tokens)
    pub minimum_length: usize,
    /// Operand flags
    pub flags: OperandFlags,
    /// Id of the local expression (extracts raw value from instruction)
    pub local_exp_id: Option<usize>,
    /// Id of the defining symbol (TripleSymbol that resolves the operand)
    pub defining_symbol_id: Option<usize>,
    /// Id of the defining expression (PatternExpression for the final value)
    pub defining_exp_id: Option<usize>,
}

impl OperandSymbol {
    /// Create a new operand symbol.
    pub fn new(
        name: impl Into<String>,
        location: Location,
        index: usize,
    ) -> Self {
        Self {
            name: name.into(),
            id: 0,
            scope_id: 0,
            location,
            index,
            relative_offset: 0,
            offset_base: -1,
            minimum_length: 0,
            flags: OperandFlags::NONE,
            local_exp_id: None,
            defining_symbol_id: None,
            defining_exp_id: None,
        }
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::Operand
    }

    /// Set the code address flag.
    pub fn set_code_address(&mut self) {
        self.flags.set(OperandFlags::CODE_ADDRESS);
    }

    /// Returns `true` if this operand is a code address.
    pub fn is_code_address(&self) -> bool {
        self.flags.is_code_address()
    }

    /// Set the offset irrelevant flag.
    pub fn set_offset_irrelevant(&mut self) {
        self.flags.set(OperandFlags::OFFSET_IRREL);
    }

    /// Returns `true` if the offset is irrelevant.
    pub fn is_offset_irrelevant(&self) -> bool {
        self.flags.is_offset_irrelevant()
    }

    /// Set the variable length flag.
    pub fn set_variable_length(&mut self) {
        self.flags.set(OperandFlags::VARIABLE_LEN);
    }

    /// Returns `true` if this operand has variable length.
    pub fn is_variable_length(&self) -> bool {
        self.flags.is_variable_length()
    }

    /// Mark this operand.
    pub fn set_mark(&mut self) {
        self.flags.set(OperandFlags::MARKED);
    }

    /// Clear the mark on this operand.
    pub fn clear_mark(&mut self) {
        self.flags.clear(OperandFlags::MARKED);
    }

    /// Returns `true` if this operand is marked.
    pub fn is_marked(&self) -> bool {
        self.flags.is_marked()
    }

    /// Define this operand with a defining symbol.
    pub fn define_with_symbol(&mut self, symbol_id: usize) {
        self.defining_symbol_id = Some(symbol_id);
    }

    /// Define this operand with a defining expression.
    pub fn define_with_expression(&mut self, exp_id: usize) {
        self.defining_exp_id = Some(exp_id);
    }

    /// Returns `true` if this operand has a defining symbol.
    pub fn has_defining_symbol(&self) -> bool {
        self.defining_symbol_id.is_some()
    }

    /// Returns `true` if this operand has a defining expression.
    pub fn has_defining_expression(&self) -> bool {
        self.defining_exp_id.is_some()
    }

    /// Returns `true` if this operand is defined (has symbol or expression).
    pub fn is_defined(&self) -> bool {
        self.defining_symbol_id.is_some() || self.defining_exp_id.is_some()
    }
}

impl fmt::Display for OperandSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[idx={}, minlen={}, flags={}]",
            self.name, self.index, self.minimum_length, self.flags
        )
    }
}

impl PartialEq for OperandSymbol {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.index == other.index
    }
}

impl Eq for OperandSymbol {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operand_symbol_new() {
        let sym = OperandSymbol::new("src", Location::unknown(), 0);
        assert_eq!(sym.name, "src");
        assert_eq!(sym.index, 0);
        assert_eq!(sym.relative_offset, 0);
        assert_eq!(sym.offset_base, -1);
        assert!(!sym.is_code_address());
    }

    #[test]
    fn test_operand_symbol_type() {
        let sym = OperandSymbol::new("op", Location::unknown(), 0);
        assert_eq!(sym.symbol_type(), SymbolType::Operand);
    }

    #[test]
    fn test_operand_flags() {
        let mut sym = OperandSymbol::new("target", Location::unknown(), 0);
        assert!(!sym.is_code_address());

        sym.set_code_address();
        assert!(sym.is_code_address());
        assert!(!sym.is_variable_length());

        sym.set_variable_length();
        assert!(sym.is_code_address());
        assert!(sym.is_variable_length());
    }

    #[test]
    fn test_operand_flags_mark() {
        let mut sym = OperandSymbol::new("op", Location::unknown(), 0);
        assert!(!sym.is_marked());

        sym.set_mark();
        assert!(sym.is_marked());

        sym.clear_mark();
        assert!(!sym.is_marked());
    }

    #[test]
    fn test_operand_define_with_symbol() {
        let mut sym = OperandSymbol::new("reg", Location::unknown(), 0);
        assert!(!sym.is_defined());

        sym.define_with_symbol(42);
        assert!(sym.is_defined());
        assert!(sym.has_defining_symbol());
        assert!(!sym.has_defining_expression());
        assert_eq!(sym.defining_symbol_id, Some(42));
    }

    #[test]
    fn test_operand_define_with_expression() {
        let mut sym = OperandSymbol::new("imm", Location::unknown(), 1);
        assert!(!sym.is_defined());

        sym.define_with_expression(10);
        assert!(sym.is_defined());
        assert!(!sym.has_defining_symbol());
        assert!(sym.has_defining_expression());
        assert_eq!(sym.defining_exp_id, Some(10));
    }

    #[test]
    fn test_operand_flags_display() {
        assert_eq!(format!("{}", OperandFlags::NONE), "none");

        let mut flags = OperandFlags::NONE;
        flags.set(OperandFlags::CODE_ADDRESS);
        assert_eq!(format!("{}", flags), "code");

        flags.set(OperandFlags::VARIABLE_LEN);
        assert_eq!(format!("{}", flags), "code|var_len");
    }

    #[test]
    fn test_operand_flags_from_raw() {
        let flags = OperandFlags::from_raw(0b1010);
        assert!(flags.is_offset_irrelevant());
        assert!(!flags.is_code_address());
        assert!(flags.is_marked());
        assert!(!flags.is_variable_length());
    }

    #[test]
    fn test_operand_display() {
        let sym = OperandSymbol::new("src", Location::unknown(), 0);
        let s = format!("{}", sym);
        assert!(s.contains("src"));
        assert!(s.contains("idx=0"));
    }

    #[test]
    fn test_operand_equality() {
        let a = OperandSymbol::new("op", Location::unknown(), 0);
        let b = OperandSymbol::new("op", Location::unknown(), 0);
        let c = OperandSymbol::new("op", Location::unknown(), 1);
        let d = OperandSymbol::new("other", Location::unknown(), 0);

        assert_eq!(a, b);
        assert_ne!(a, c); // Different index
        assert_ne!(a, d); // Different name
    }
}
