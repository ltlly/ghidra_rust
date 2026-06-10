//! S_END -- End symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EndMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// An end symbol (`S_END`).
///
/// This is a zero-length sentinel symbol that marks the end of a compound
/// symbol group. For example, it appears at the end of a procedure's local
/// symbol scope, after all local variable and parameter symbols.
///
/// The symbol carries no payload data.
///
/// This corresponds to `S_END` (0x0006) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SEnd;

impl SEnd {
    /// Create a new end symbol.
    pub fn new() -> Self {
        Self
    }

    /// Parse an S_END symbol from a byte slice.
    ///
    /// The S_END symbol has no payload; any data present is ignored.
    /// Always returns `Some(SEnd)`.
    pub fn parse(_data: &[u8]) -> Option<Self> {
        Some(Self)
    }
}

impl Default for SEnd {
    fn default() -> Self {
        Self::new()
    }
}

impl AbstractMsSymbol for SEnd {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_END
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_END"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "End")
    }
}

impl fmt::Display for SEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let data = [];
        let sym = SEnd::parse(&data).unwrap();
        assert_eq!(sym.pdb_id(), 0x0006);
    }

    #[test]
    fn test_parse_with_trailing_data() {
        // S_END has no payload; trailing bytes are ignored
        let data = [0xFF, 0xFF];
        let sym = SEnd::parse(&data).unwrap();
        assert_eq!(sym.pdb_id(), 0x0006);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SEnd::new();
        assert_eq!(sym.pdb_id(), 0x0006);
        assert_eq!(sym.symbol_type_name(), "S_END");
    }

    #[test]
    fn test_display() {
        let sym = SEnd::new();
        let s = format!("{}", sym);
        assert_eq!(s, "End");
    }

    #[test]
    fn test_default() {
        let sym = SEnd::default();
        assert_eq!(sym, SEnd::new());
    }

    #[test]
    fn test_clone_eq() {
        let a = SEnd::new();
        let b = a.clone();
        assert_eq!(a, b);
    }
}
