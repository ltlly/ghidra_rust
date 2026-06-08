//! SLEIGH start and end symbols: instruction address references.
//!
//! These symbols represent references to the start and end addresses of
//! the current instruction during disassembly. They are used in P-code
//! templates to refer to:
//!
//! - [`StartSymbol`] -- the start address of the current instruction
//!   (`inst_start`, `inst_ref`, `inst_def`)
//! - [`EndSymbol`] -- the address of the next instruction (`inst_next`)
//!
//! These are `SpecificSymbol` variants that resolve to constant varnodes
//! with special offset types.
//!
//! # Example
//!
//! In a `.slaspec` file:
//! ```text
//! define token instr(4)
//!     offset  = (0, 31)       # signed offset
//! ;
//!
//! :BEQ offset is ... {
//!     # inst_start = address of this instruction
//!     # inst_next = address of next instruction
//!     # offset is relative to inst_next
//!     PC = inst_next + (offset << 2);
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

use super::sleigh_symbol::{Location, SymbolType};

// ---------------------------------------------------------------------------
// StartSymbol
// ---------------------------------------------------------------------------

/// A symbol representing the start address of the current instruction.
///
/// `StartSymbol` is a `PatternlessSymbol` (always evaluates to constant 0
/// in pattern expressions). Its semantic value is the address of the first
/// byte of the current instruction.
///
/// In P-code templates, `inst_start` resolves to a varnode with:
/// - Space: the instruction address space
/// - Offset type: `j_start` (resolved at runtime to the instruction address)
/// - Size: 0 (zero-size, meaning "address of")
///
/// # Built-in names
///
/// SLEIGH defines three built-in start symbols:
/// - `inst_start` -- the start of the current instruction
/// - `inst_ref` -- the reference address (same as inst_start for most cases)
/// - `inst_def` -- the definition address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartSymbol {
    /// Symbol name (e.g., "inst_start")
    pub name: String,
    /// Symbol id
    pub id: usize,
    /// Scope id
    pub scope_id: usize,
    /// Source location
    pub location: Location,
    /// The address space name (e.g., "ram")
    pub space_name: String,
    /// The address space index
    pub space_index: u32,
}

impl StartSymbol {
    /// Create a new start symbol.
    pub fn new(
        name: impl Into<String>,
        location: Location,
        space_name: impl Into<String>,
        space_index: u32,
    ) -> Self {
        Self {
            name: name.into(),
            id: 0,
            scope_id: 0,
            location,
            space_name: space_name.into(),
            space_index,
        }
    }

    /// Create the built-in `inst_start` symbol.
    pub fn inst_start(location: Location, space_name: impl Into<String>, space_index: u32) -> Self {
        Self::new("inst_start", location, space_name, space_index)
    }

    /// Create the built-in `inst_ref` symbol.
    pub fn inst_ref(location: Location, space_name: impl Into<String>, space_index: u32) -> Self {
        Self::new("inst_ref", location, space_name, space_index)
    }

    /// Create the built-in `inst_def` symbol.
    pub fn inst_def(location: Location, space_name: impl Into<String>, space_index: u32) -> Self {
        Self::new("inst_def", location, space_name, space_index)
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::Start
    }

    /// Returns the offset type for this symbol.
    ///
    /// In the P-code model, `j_start` indicates the start of the current
    /// instruction.
    pub fn offset_type(&self) -> &'static str {
        "j_start"
    }
}

impl fmt::Display for StartSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}[{}]",
            self.name, self.space_name, self.space_index
        )
    }
}

impl PartialEq for StartSymbol {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for StartSymbol {}

// ---------------------------------------------------------------------------
// EndSymbol
// ---------------------------------------------------------------------------

/// A symbol representing the end (next instruction) address.
///
/// `EndSymbol` is a `PatternlessSymbol` whose semantic value is the address
/// of the next instruction after the current one. This is typically used
/// for PC-relative addressing modes where offsets are relative to the end
/// of the current instruction.
///
/// In P-code templates, `inst_next` resolves to a varnode with:
/// - Space: the instruction address space
/// - Offset type: `j_next` (resolved at runtime to the next instruction address)
/// - Size: 0 (zero-size, meaning "address of")
///
/// # Example
///
/// On ARM, branch targets are typically encoded as PC-relative offsets:
/// ```text
/// :B offset is ... {
///     PC = inst_next + (offset << 2);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndSymbol {
    /// Symbol name (always "inst_next")
    pub name: String,
    /// Symbol id
    pub id: usize,
    /// Scope id
    pub scope_id: usize,
    /// Source location
    pub location: Location,
    /// The address space name (e.g., "ram")
    pub space_name: String,
    /// The address space index
    pub space_index: u32,
}

impl EndSymbol {
    /// Create a new end symbol.
    pub fn new(
        name: impl Into<String>,
        location: Location,
        space_name: impl Into<String>,
        space_index: u32,
    ) -> Self {
        Self {
            name: name.into(),
            id: 0,
            scope_id: 0,
            location,
            space_name: space_name.into(),
            space_index,
        }
    }

    /// Create the built-in `inst_next` symbol.
    pub fn inst_next(location: Location, space_name: impl Into<String>, space_index: u32) -> Self {
        Self::new("inst_next", location, space_name, space_index)
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::End
    }

    /// Returns the offset type for this symbol.
    ///
    /// In the P-code model, `j_next` indicates the next instruction address.
    pub fn offset_type(&self) -> &'static str {
        "j_next"
    }
}

impl fmt::Display for EndSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}[{}]",
            self.name, self.space_name, self.space_index
        )
    }
}

impl PartialEq for EndSymbol {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for EndSymbol {}

// ---------------------------------------------------------------------------
// Next2Symbol
// ---------------------------------------------------------------------------

/// A symbol representing the address of the instruction after next.
///
/// `Next2Symbol` is similar to `EndSymbol` but refers to `inst_next2`,
/// which is the address two instructions ahead. This is used on some
/// architectures where branch targets are relative to `inst_next2`.
///
/// In P-code templates, `inst_next2` resolves to a varnode with:
/// - Space: the instruction address space
/// - Offset type: `j_next2`
/// - Size: 0
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Next2Symbol {
    /// Symbol name (always "inst_next2")
    pub name: String,
    /// Symbol id
    pub id: usize,
    /// Scope id
    pub scope_id: usize,
    /// Source location
    pub location: Location,
    /// The address space name
    pub space_name: String,
    /// The address space index
    pub space_index: u32,
}

impl Next2Symbol {
    /// Create a new next2 symbol.
    pub fn new(
        name: impl Into<String>,
        location: Location,
        space_name: impl Into<String>,
        space_index: u32,
    ) -> Self {
        Self {
            name: name.into(),
            id: 0,
            scope_id: 0,
            location,
            space_name: space_name.into(),
            space_index,
        }
    }

    /// Create the built-in `inst_next2` symbol.
    pub fn inst_next2(location: Location, space_name: impl Into<String>, space_index: u32) -> Self {
        Self::new("inst_next2", location, space_name, space_index)
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::Next2
    }

    /// Returns the offset type for this symbol.
    pub fn offset_type(&self) -> &'static str {
        "j_next2"
    }
}

impl fmt::Display for Next2Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}[{}]",
            self.name, self.space_name, self.space_index
        )
    }
}

impl PartialEq for Next2Symbol {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Next2Symbol {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_symbol_new() {
        let sym = StartSymbol::new("inst_start", Location::unknown(), "ram", 1);
        assert_eq!(sym.name, "inst_start");
        assert_eq!(sym.space_name, "ram");
        assert_eq!(sym.space_index, 1);
    }

    #[test]
    fn test_start_symbol_builtin() {
        let start = StartSymbol::inst_start(Location::unknown(), "ram", 1);
        assert_eq!(start.name, "inst_start");

        let ref_sym = StartSymbol::inst_ref(Location::unknown(), "ram", 1);
        assert_eq!(ref_sym.name, "inst_ref");

        let def_sym = StartSymbol::inst_def(Location::unknown(), "ram", 1);
        assert_eq!(def_sym.name, "inst_def");
    }

    #[test]
    fn test_start_symbol_type() {
        let sym = StartSymbol::inst_start(Location::unknown(), "ram", 1);
        assert_eq!(sym.symbol_type(), SymbolType::Start);
    }

    #[test]
    fn test_start_symbol_offset_type() {
        let sym = StartSymbol::inst_start(Location::unknown(), "ram", 1);
        assert_eq!(sym.offset_type(), "j_start");
    }

    #[test]
    fn test_end_symbol_new() {
        let sym = EndSymbol::new("inst_next", Location::unknown(), "ram", 1);
        assert_eq!(sym.name, "inst_next");
        assert_eq!(sym.space_name, "ram");
    }

    #[test]
    fn test_end_symbol_builtin() {
        let sym = EndSymbol::inst_next(Location::unknown(), "ram", 1);
        assert_eq!(sym.name, "inst_next");
    }

    #[test]
    fn test_end_symbol_type() {
        let sym = EndSymbol::inst_next(Location::unknown(), "ram", 1);
        assert_eq!(sym.symbol_type(), SymbolType::End);
    }

    #[test]
    fn test_end_symbol_offset_type() {
        let sym = EndSymbol::inst_next(Location::unknown(), "ram", 1);
        assert_eq!(sym.offset_type(), "j_next");
    }

    #[test]
    fn test_next2_symbol_new() {
        let sym = Next2Symbol::new("inst_next2", Location::unknown(), "ram", 1);
        assert_eq!(sym.name, "inst_next2");
    }

    #[test]
    fn test_next2_symbol_builtin() {
        let sym = Next2Symbol::inst_next2(Location::unknown(), "ram", 1);
        assert_eq!(sym.name, "inst_next2");
    }

    #[test]
    fn test_next2_symbol_type() {
        let sym = Next2Symbol::inst_next2(Location::unknown(), "ram", 1);
        assert_eq!(sym.symbol_type(), SymbolType::Next2);
    }

    #[test]
    fn test_next2_symbol_offset_type() {
        let sym = Next2Symbol::inst_next2(Location::unknown(), "ram", 1);
        assert_eq!(sym.offset_type(), "j_next2");
    }

    #[test]
    fn test_start_symbol_display() {
        let sym = StartSymbol::inst_start(Location::unknown(), "ram", 1);
        let s = format!("{}", sym);
        assert!(s.contains("inst_start"));
        assert!(s.contains("ram"));
    }

    #[test]
    fn test_end_symbol_display() {
        let sym = EndSymbol::inst_next(Location::unknown(), "ram", 1);
        let s = format!("{}", sym);
        assert!(s.contains("inst_next"));
        assert!(s.contains("ram"));
    }

    #[test]
    fn test_next2_symbol_display() {
        let sym = Next2Symbol::inst_next2(Location::unknown(), "ram", 1);
        let s = format!("{}", sym);
        assert!(s.contains("inst_next2"));
        assert!(s.contains("ram"));
    }

    #[test]
    fn test_start_symbol_equality() {
        let a = StartSymbol::inst_start(Location::unknown(), "ram", 1);
        let b = StartSymbol::inst_start(Location::unknown(), "ram", 1);
        let c = StartSymbol::inst_ref(Location::unknown(), "ram", 1);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_end_symbol_equality() {
        let a = EndSymbol::inst_next(Location::unknown(), "ram", 1);
        let b = EndSymbol::inst_next(Location::unknown(), "ram", 2);
        assert_eq!(a, b); // Same name
    }
}
