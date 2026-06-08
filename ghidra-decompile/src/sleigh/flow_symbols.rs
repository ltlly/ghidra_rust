//! SLEIGH flow symbols: flow destination and reference address symbols.
//!
//! These symbols are used in P-code snippets to refer to the original
//! control flow addresses when injecting P-code at a call site.
//!
//! - [`FlowDestSymbol`] -- the original call destination address
//! - [`FlowRefSymbol`] -- the reference address at the injection site
//!
//! These are `SpecificSymbol` variants that resolve to constant varnodes
//! with special offset types. They are only usable in P-code snippets
//! (injected P-code) and not in normal instruction definitions.
//!
//! # Example
//!
//! In a P-code snippet:
//! ```text
//! define pcode snippet my_snippet(flowdest) {
//!     # flowdest = original call destination
//!     # flowref = reference address at injection site
//!     PC = flowdest;
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

use super::sleigh_symbol::{Location, SymbolType};

// ---------------------------------------------------------------------------
// FlowDestSymbol
// ---------------------------------------------------------------------------

/// A symbol representing the original call destination address.
///
/// `FlowDestSymbol` is a `SpecificSymbol` whose semantic value is the
/// original primary call destination address. It is only usable in P-code
/// snippets (injected P-code).
///
/// In P-code templates, `flowdest` resolves to a varnode with:
/// - Space: the instruction address space
/// - Offset type: `j_flowdest` (resolved at runtime)
/// - Size: 0 (zero-size, meaning "address of")
///
/// # Note
///
/// This symbol cannot be used in pattern expressions (`getPatternExpression()`
/// returns null).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDestSymbol {
    /// Symbol name (typically "flowdest")
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

impl FlowDestSymbol {
    /// Create a new flow destination symbol.
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

    /// Create the built-in `flowdest` symbol.
    pub fn flowdest(location: Location, space_name: impl Into<String>, space_index: u32) -> Self {
        Self::new("flowdest", location, space_name, space_index)
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::FlowDest
    }

    /// Returns the offset type for this symbol.
    pub fn offset_type(&self) -> &'static str {
        "j_flowdest"
    }

    /// Returns `false` -- flow dest symbols cannot be used in patterns.
    pub fn has_pattern_expression(&self) -> bool {
        false
    }
}

impl fmt::Display for FlowDestSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}[{}]",
            self.name, self.space_name, self.space_index
        )
    }
}

impl PartialEq for FlowDestSymbol {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for FlowDestSymbol {}

// ---------------------------------------------------------------------------
// FlowRefSymbol
// ---------------------------------------------------------------------------

/// A symbol representing the reference address at the injection site.
///
/// `FlowRefSymbol` is a `SpecificSymbol` whose semantic value is the
/// reference address at the P-code injection site. It is only usable
/// in P-code snippets (injected P-code).
///
/// In P-code templates, `flowref` resolves to a varnode with:
/// - Space: the instruction address space
/// - Offset type: `j_flowref` (resolved at runtime)
/// - Size: 0 (zero-size, meaning "address of")
///
/// # Note
///
/// This symbol cannot be used in pattern expressions (`getPatternExpression()`
/// returns null).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRefSymbol {
    /// Symbol name (typically "flowref")
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

impl FlowRefSymbol {
    /// Create a new flow reference symbol.
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

    /// Create the built-in `flowref` symbol.
    pub fn flowref(location: Location, space_name: impl Into<String>, space_index: u32) -> Self {
        Self::new("flowref", location, space_name, space_index)
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::FlowRef
    }

    /// Returns the offset type for this symbol.
    pub fn offset_type(&self) -> &'static str {
        "j_flowref"
    }

    /// Returns `false` -- flow ref symbols cannot be used in patterns.
    pub fn has_pattern_expression(&self) -> bool {
        false
    }
}

impl fmt::Display for FlowRefSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}[{}]",
            self.name, self.space_name, self.space_index
        )
    }
}

impl PartialEq for FlowRefSymbol {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for FlowRefSymbol {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_dest_symbol_new() {
        let sym = FlowDestSymbol::new("flowdest", Location::unknown(), "ram", 1);
        assert_eq!(sym.name, "flowdest");
        assert_eq!(sym.space_name, "ram");
        assert_eq!(sym.space_index, 1);
    }

    #[test]
    fn test_flow_dest_symbol_builtin() {
        let sym = FlowDestSymbol::flowdest(Location::unknown(), "ram", 1);
        assert_eq!(sym.name, "flowdest");
    }

    #[test]
    fn test_flow_dest_symbol_type() {
        let sym = FlowDestSymbol::flowdest(Location::unknown(), "ram", 1);
        assert_eq!(sym.symbol_type(), SymbolType::FlowDest);
    }

    #[test]
    fn test_flow_dest_symbol_offset_type() {
        let sym = FlowDestSymbol::flowdest(Location::unknown(), "ram", 1);
        assert_eq!(sym.offset_type(), "j_flowdest");
    }

    #[test]
    fn test_flow_dest_no_pattern() {
        let sym = FlowDestSymbol::flowdest(Location::unknown(), "ram", 1);
        assert!(!sym.has_pattern_expression());
    }

    #[test]
    fn test_flow_ref_symbol_new() {
        let sym = FlowRefSymbol::new("flowref", Location::unknown(), "ram", 1);
        assert_eq!(sym.name, "flowref");
        assert_eq!(sym.space_name, "ram");
        assert_eq!(sym.space_index, 1);
    }

    #[test]
    fn test_flow_ref_symbol_builtin() {
        let sym = FlowRefSymbol::flowref(Location::unknown(), "ram", 1);
        assert_eq!(sym.name, "flowref");
    }

    #[test]
    fn test_flow_ref_symbol_type() {
        let sym = FlowRefSymbol::flowref(Location::unknown(), "ram", 1);
        assert_eq!(sym.symbol_type(), SymbolType::FlowRef);
    }

    #[test]
    fn test_flow_ref_symbol_offset_type() {
        let sym = FlowRefSymbol::flowref(Location::unknown(), "ram", 1);
        assert_eq!(sym.offset_type(), "j_flowref");
    }

    #[test]
    fn test_flow_ref_no_pattern() {
        let sym = FlowRefSymbol::flowref(Location::unknown(), "ram", 1);
        assert!(!sym.has_pattern_expression());
    }

    #[test]
    fn test_flow_dest_display() {
        let sym = FlowDestSymbol::flowdest(Location::unknown(), "ram", 1);
        let s = format!("{}", sym);
        assert!(s.contains("flowdest"));
        assert!(s.contains("ram"));
    }

    #[test]
    fn test_flow_ref_display() {
        let sym = FlowRefSymbol::flowref(Location::unknown(), "ram", 1);
        let s = format!("{}", sym);
        assert!(s.contains("flowref"));
        assert!(s.contains("ram"));
    }

    #[test]
    fn test_flow_dest_equality() {
        let a = FlowDestSymbol::flowdest(Location::unknown(), "ram", 1);
        let b = FlowDestSymbol::flowdest(Location::unknown(), "ram", 1);
        let c = FlowDestSymbol::new("other", Location::unknown(), "ram", 1);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_flow_ref_equality() {
        let a = FlowRefSymbol::flowref(Location::unknown(), "ram", 1);
        let b = FlowRefSymbol::flowref(Location::unknown(), "ram", 1);
        let c = FlowRefSymbol::new("other", Location::unknown(), "ram", 1);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_flow_symbols_different_types() {
        let dest = FlowDestSymbol::flowdest(Location::unknown(), "ram", 1);
        let ref_sym = FlowRefSymbol::flowref(Location::unknown(), "ram", 1);

        assert_eq!(dest.symbol_type(), SymbolType::FlowDest);
        assert_eq!(ref_sym.symbol_type(), SymbolType::FlowRef);
        assert_ne!(dest.symbol_type(), ref_sym.symbol_type());
    }
}
