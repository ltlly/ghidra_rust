//! Base SLEIGH symbol types and the symbol type enumeration.
//!
//! In the SLEIGH compiler, every named entity (registers, instructions,
//! subtables, operands, etc.) is represented as a [`SleighSymbol`]. The
//! [`SymbolType`] enum discriminates between the various concrete symbol
//! kinds.
//!
//! # Key Types
//! - [`SleighSymbol`] -- base struct holding name, id, scope, and source location
//! - [`SymbolType`] -- discriminant for concrete symbol variants
//! - [`Location`] -- source file / line reference for error reporting

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Location
// ---------------------------------------------------------------------------

/// Source location in a `.slaspec` file, used for error reporting.
///
/// Every symbol records where it was defined so that compiler diagnostics
/// can point back to the original source.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Location {
    /// Source file name (e.g., "x86.slaspec")
    pub filename: String,
    /// Line number (1-based)
    pub lineno: u32,
    /// Column number (1-based, 0 if unknown)
    pub colno: u32,
}

impl Location {
    /// Create a new source location.
    pub fn new(filename: impl Into<String>, lineno: u32, colno: u32) -> Self {
        Self {
            filename: filename.into(),
            lineno,
            colno,
        }
    }

    /// An internally generated location (not from a real source file).
    pub fn internally_defined() -> Self {
        Self {
            filename: "<internally defined>".to_string(),
            lineno: 0,
            colno: 0,
        }
    }

    /// An unknown location.
    pub fn unknown() -> Self {
        Self {
            filename: "<unknown>".to_string(),
            lineno: 0,
            colno: 0,
        }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lineno > 0 {
            write!(f, "{}:{}", self.filename, self.lineno)
        } else {
            write!(f, "{}", self.filename)
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolType
// ---------------------------------------------------------------------------

/// Discriminant for the various SLEIGH symbol kinds.
///
/// This mirrors the Java `symbol_type` enum. Each variant corresponds to a
/// concrete subclass of `SleighSymbol` in the original Java implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolType {
    /// Address space declaration
    Space,
    /// Instruction token definition
    Token,
    /// User-defined P-code operation
    UserOp,
    /// Value symbol (constant with pattern expression)
    Value,
    /// Value map symbol (maps values to names)
    ValueMap,
    /// Name symbol (named constant)
    Name,
    /// Global varnode (register or memory location)
    Varnode,
    /// List of varnodes
    VarnodeList,
    /// Operand within a constructor
    Operand,
    /// Instruction start reference (`inst_start`, `inst_ref`, `inst_def`)
    Start,
    /// Instruction end reference (`inst_next`)
    End,
    /// Second next-instruction reference (`inst_next2`)
    Next2,
    /// Subtable (hierarchical instruction table)
    Subtable,
    /// Macro definition
    Macro,
    /// Named section
    Section,
    /// Bitrange within a varnode
    Bitrange,
    /// Context variable
    Context,
    /// Epsilon symbol (zero-size)
    Epsilon,
    /// Label (code address)
    Label,
    /// Flow destination (for pcode snippets)
    FlowDest,
    /// Flow reference (for pcode snippets)
    FlowRef,
    /// Dummy / placeholder (should not appear in real output)
    Dummy,
}

impl SymbolType {
    /// Human-readable name for this symbol type.
    pub fn name(&self) -> &'static str {
        match self {
            SymbolType::Space => "space",
            SymbolType::Token => "token",
            SymbolType::UserOp => "userop",
            SymbolType::Value => "value",
            SymbolType::ValueMap => "valuemap",
            SymbolType::Name => "name",
            SymbolType::Varnode => "varnode",
            SymbolType::VarnodeList => "varnodelist",
            SymbolType::Operand => "operand",
            SymbolType::Start => "start",
            SymbolType::End => "end",
            SymbolType::Next2 => "next2",
            SymbolType::Subtable => "subtable",
            SymbolType::Macro => "macro",
            SymbolType::Section => "section",
            SymbolType::Bitrange => "bitrange",
            SymbolType::Context => "context",
            SymbolType::Epsilon => "epsilon",
            SymbolType::Label => "label",
            SymbolType::FlowDest => "flowdest",
            SymbolType::FlowRef => "flowref",
            SymbolType::Dummy => "dummy",
        }
    }

    /// Returns `true` if this is a TripleSymbol (has a pattern expression).
    pub fn is_triple(&self) -> bool {
        matches!(
            self,
            SymbolType::Value
                | SymbolType::ValueMap
                | SymbolType::Name
                | SymbolType::Varnode
                | SymbolType::VarnodeList
                | SymbolType::Operand
                | SymbolType::Start
                | SymbolType::End
                | SymbolType::Next2
                | SymbolType::Subtable
                | SymbolType::Context
                | SymbolType::Epsilon
                | SymbolType::FlowDest
                | SymbolType::FlowRef
                | SymbolType::Label
        )
    }

    /// Returns `true` if this is a SpecificSymbol (resolves to a concrete varnode).
    pub fn is_specific(&self) -> bool {
        matches!(
            self,
            SymbolType::Varnode
                | SymbolType::Operand
                | SymbolType::Start
                | SymbolType::End
                | SymbolType::Next2
                | SymbolType::Context
                | SymbolType::Epsilon
                | SymbolType::FlowDest
                | SymbolType::FlowRef
        )
    }

    /// Returns `true` if this is a FamilySymbol (has a pattern value).
    pub fn is_family(&self) -> bool {
        matches!(
            self,
            SymbolType::Value | SymbolType::ValueMap | SymbolType::Name
        )
    }
}

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// SleighSymbol
// ---------------------------------------------------------------------------

/// Base SLEIGH symbol: every named entity in a `.slaspec` file.
///
/// `SleighSymbol` is the root of the symbol hierarchy. It holds the
/// symbol's name, a unique id, the scope it belongs to, and the source
/// location where it was defined.
///
/// Concrete symbol types (varnode, operand, subtable, etc.) extend this
/// via enum variants or wrapper structs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleighSymbol {
    /// Symbol name (e.g., "EAX", "ADD", "instruction")
    pub name: String,
    /// Unique id across all symbols in the SLEIGH file
    pub id: usize,
    /// Unique id of the scope this symbol belongs to
    pub scope_id: usize,
    /// Source location where this symbol was defined
    pub location: Location,
    /// Whether this symbol was looked up during compilation
    was_sought: bool,
}

impl SleighSymbol {
    /// Create a new symbol with the given name and location.
    pub fn new(name: impl Into<String>, location: Location) -> Self {
        Self {
            name: name.into(),
            id: 0,
            scope_id: 0,
            location,
            was_sought: false,
        }
    }

    /// Create a symbol with a specific id and scope.
    pub fn with_id(
        name: impl Into<String>,
        id: usize,
        scope_id: usize,
        location: Location,
    ) -> Self {
        Self {
            name: name.into(),
            id,
            scope_id,
            location,
            was_sought: false,
        }
    }

    /// Mark this symbol as having been looked up.
    pub fn set_was_sought(&mut self, sought: bool) {
        self.was_sought = sought;
    }

    /// Returns `true` if this symbol was looked up during compilation.
    pub fn was_sought(&self) -> bool {
        self.was_sought
    }

    /// Detailed string representation including id and scope.
    pub fn to_detailed_string(&self) -> String {
        format!("{}-{}:{}", self.name, self.scope_id, self.id)
    }
}

impl fmt::Display for SleighSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl PartialEq for SleighSymbol {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for SleighSymbol {}

impl PartialOrd for SleighSymbol {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SleighSymbol {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_display() {
        let loc = Location::new("test.slaspec", 42, 10);
        assert_eq!(format!("{}", loc), "test.slaspec:42");

        let loc = Location::internally_defined();
        assert_eq!(format!("{}", loc), "<internally defined>");
    }

    #[test]
    fn test_symbol_type_properties() {
        assert!(SymbolType::Varnode.is_triple());
        assert!(SymbolType::Varnode.is_specific());
        assert!(!SymbolType::Varnode.is_family());

        assert!(SymbolType::Value.is_family());
        assert!(SymbolType::Value.is_triple());
        assert!(!SymbolType::Value.is_specific());

        assert!(!SymbolType::Space.is_triple());
        assert!(!SymbolType::Space.is_specific());
        assert!(!SymbolType::Space.is_family());
    }

    #[test]
    fn test_symbol_type_display() {
        assert_eq!(format!("{}", SymbolType::Varnode), "varnode");
        assert_eq!(format!("{}", SymbolType::Subtable), "subtable");
        assert_eq!(format!("{}", SymbolType::Dummy), "dummy");
    }

    #[test]
    fn test_sleigh_symbol_new() {
        let sym = SleighSymbol::new("EAX", Location::new("test.slaspec", 10, 5));
        assert_eq!(sym.name, "EAX");
        assert_eq!(sym.id, 0);
        assert_eq!(sym.scope_id, 0);
        assert!(!sym.was_sought());
    }

    #[test]
    fn test_sleigh_symbol_display() {
        let sym = SleighSymbol::new("ADD", Location::unknown());
        assert_eq!(format!("{}", sym), "ADD");
        assert_eq!(sym.to_detailed_string(), "ADD-0:0");
    }

    #[test]
    fn test_sleigh_symbol_ordering() {
        let a = SleighSymbol::new("AAA", Location::unknown());
        let b = SleighSymbol::new("BBB", Location::unknown());
        assert!(a < b);
    }
}
