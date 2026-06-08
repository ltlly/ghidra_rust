//! SLEIGH constructor symbol: the full compiler-side constructor.
//!
//! This module implements the `Constructor` type from the Java `slghsymbol` package.
//! It is distinct from the simplified `Constructor` in `construct.rs` -- this version
//! is used during SLEIGH compilation and contains the full set of fields needed for
//! encoding to `.sla` files.
//!
//! A Constructor represents a single instruction decoding rule. It maps a bit pattern
//! to a semantic template (P-code operations) and is associated with a parent subtable.
//!
//! # Key Fields
//! - `pattern` -- the token pattern that must match for this constructor to activate
//! - `pateq` -- the pattern equation tree (pre-resolved form of the pattern)
//! - `operands` -- the operand symbols for this constructor
//! - `printpiece` -- display format pieces for printing the instruction
//! - `context` -- context changes to apply when this constructor matches
//! - `templ` -- the semantic template (P-code to emit)
//! - `namedtempl` -- additional named P-code sections

use serde::{Deserialize, Serialize};
use std::fmt;

use super::sleigh_symbol::Location;

// ---------------------------------------------------------------------------
// Constructor (compiler-side)
// ---------------------------------------------------------------------------

/// A SLEIGH constructor used during compilation.
///
/// This is the full compiler-side representation, distinct from the runtime
/// `Constructor` in `construct.rs`. It holds the pattern equation, operand
/// definitions, display format, context changes, and semantic template.
///
/// Each constructor belongs to a parent [`SubtableSymbol`] and has a unique
/// id within that subtable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructorSymbol {
    /// Source location where this constructor was defined
    pub location: Location,
    /// Unique id within the parent subtable
    pub id: usize,
    /// Source file index (for multi-file compilations)
    pub source_file_index: i32,
    /// Minimum instruction length in bytes
    pub minimum_length: usize,
    /// Index of the first whitespace piece in printpiece
    pub first_whitespace: usize,
    /// If >= 0, print only a single operand (flow-through)
    pub flow_through_index: i32,
    /// Whether this constructor has an error
    pub in_error: bool,
    /// Display format pieces (alternating text and operand placeholders)
    pub print_pieces: Vec<PrintPiece>,
    /// Operand symbols for this constructor
    pub operands: Vec<usize>, // OperandSymbol ids
    /// Context changes to apply when this constructor matches
    pub context_changes: Vec<ContextChange>,
    /// The semantic template (P-code operations)
    pub templ: Option<usize>, // ConstructTpl id
    /// Named P-code sections (for multi-section constructors)
    pub named_templs: Vec<usize>, // ConstructTpl ids
}

/// A piece of the display format for a constructor.
///
/// Display format is a sequence of text literals and operand placeholders.
/// For example, `ADD r0, r1, r2` might have pieces:
/// - Text("ADD ")
/// - Operand(0)
/// - Text(", ")
/// - Operand(1)
/// - Text(", ")
/// - Operand(2)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrintPiece {
    /// Literal text
    Text(String),
    /// Operand placeholder (index into the constructor's operand list)
    Operand(usize),
}

/// A context change to apply when a constructor matches.
///
/// Context changes modify the context variable state after a constructor
/// is selected. This is used for things like ARM Thumb mode switching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContextChange {
    /// Set a context variable to a value
    Set {
        /// Name of the context variable
        name: String,
        /// Value to set
        value: u64,
    },
    /// Copy one context variable to another
    Copy {
        /// Source variable name
        src: String,
        /// Destination variable name
        dest: String,
    },
    /// Clear a context variable to its default
    Clear(String),
    /// Commit the current context state
    Commit {
        /// Number of bits to commit
        num_bits: usize,
        /// Current flow count
        current_flow: usize,
    },
}

impl ConstructorSymbol {
    /// Create a new constructor at the given location.
    pub fn new(location: Location) -> Self {
        Self {
            location,
            id: 0,
            source_file_index: -1,
            minimum_length: 0,
            first_whitespace: 0,
            flow_through_index: -1,
            in_error: false,
            print_pieces: Vec::new(),
            operands: Vec::new(),
            context_changes: Vec::new(),
            templ: None,
            named_templs: Vec::new(),
        }
    }

    /// Returns the source file name.
    pub fn filename(&self) -> &str {
        &self.location.filename
    }

    /// Returns the line number in the source file.
    pub fn lineno(&self) -> u32 {
        self.location.lineno
    }

    /// Returns the number of operands.
    pub fn num_operands(&self) -> usize {
        self.operands.len()
    }

    /// Returns the number of named P-code sections.
    pub fn num_sections(&self) -> usize {
        self.named_templs.len()
    }

    /// Add a print piece to the display format.
    pub fn add_print_piece(&mut self, piece: PrintPiece) {
        self.print_pieces.push(piece);
    }

    /// Add an operand symbol id.
    pub fn add_operand(&mut self, operand_id: usize) {
        self.operands.push(operand_id);
    }

    /// Add a context change.
    pub fn add_context_change(&mut self, change: ContextChange) {
        self.context_changes.push(change);
    }

    /// Set the semantic template.
    pub fn set_template(&mut self, templ_id: usize) {
        self.templ = Some(templ_id);
    }

    /// Format the display string from print pieces.
    pub fn format_display(&self, operands: &[&str]) -> String {
        let mut result = String::new();
        for piece in &self.print_pieces {
            match piece {
                PrintPiece::Text(text) => result.push_str(text),
                PrintPiece::Operand(idx) => {
                    if *idx < operands.len() {
                        result.push_str(operands[*idx]);
                    } else {
                        result.push_str(&format!("<op{}>", idx));
                    }
                }
            }
        }
        result
    }
}

impl fmt::Display for ConstructorSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Constructor(id={}, file={}, line={})",
            self.id,
            self.location.filename,
            self.location.lineno
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constructor_new() {
        let ct = ConstructorSymbol::new(Location::new("test.slaspec", 100, 5));
        assert_eq!(ct.id, 0);
        assert_eq!(ct.minimum_length, 0);
        assert!(!ct.in_error);
        assert_eq!(ct.num_operands(), 0);
    }

    #[test]
    fn test_constructor_add_operand() {
        let mut ct = ConstructorSymbol::new(Location::unknown());
        ct.add_operand(0);
        ct.add_operand(1);
        ct.add_operand(2);
        assert_eq!(ct.num_operands(), 3);
    }

    #[test]
    fn test_constructor_print_pieces() {
        let mut ct = ConstructorSymbol::new(Location::unknown());
        ct.add_print_piece(PrintPiece::Text("ADD ".to_string()));
        ct.add_print_piece(PrintPiece::Operand(0));
        ct.add_print_piece(PrintPiece::Text(", ".to_string()));
        ct.add_print_piece(PrintPiece::Operand(1));

        let display = ct.format_display(&["r0", "r1"]);
        assert_eq!(display, "ADD r0, r1");
    }

    #[test]
    fn test_constructor_format_display_missing_operand() {
        let mut ct = ConstructorSymbol::new(Location::unknown());
        ct.add_print_piece(PrintPiece::Text("MOV ".to_string()));
        ct.add_print_piece(PrintPiece::Operand(0));
        ct.add_print_piece(PrintPiece::Text(", ".to_string()));
        ct.add_print_piece(PrintPiece::Operand(5)); // out of range

        let display = ct.format_display(&["r0"]);
        assert_eq!(display, "MOV r0, <op5>");
    }

    #[test]
    fn test_context_change() {
        let change = ContextChange::Set {
            name: "TMode".to_string(),
            value: 1,
        };
        match change {
            ContextChange::Set { name, value } => {
                assert_eq!(name, "TMode");
                assert_eq!(value, 1);
            }
            _ => panic!("Expected Set variant"),
        }
    }

    #[test]
    fn test_print_piece_equality() {
        assert_eq!(
            PrintPiece::Text("ADD".to_string()),
            PrintPiece::Text("ADD".to_string())
        );
        assert_eq!(PrintPiece::Operand(0), PrintPiece::Operand(0));
        assert_ne!(
            PrintPiece::Text("ADD".to_string()),
            PrintPiece::Text("SUB".to_string())
        );
    }

    #[test]
    fn test_constructor_display() {
        let ct = ConstructorSymbol::new(Location::new("arm.slaspec", 42, 10));
        let s = format!("{}", ct);
        assert!(s.contains("arm.slaspec"));
        assert!(s.contains("42"));
    }
}
