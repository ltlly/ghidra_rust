//! S_END -- End symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EndMsSymbol`.
//!
//! The same zero-length sentinel is used by `S_END` (0x0006), `S_ENDARG`
//! (0x000A), and `S_PROC_ID_END` (0x114F) -- all share the same binary
//! layout (no payload) and differ only in semantic context.

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
/// This corresponds to the following CodeView symbol types:
/// - `S_END` (0x0006) -- general end-of-scope marker
/// - `S_ENDARG` (0x000A) -- end of argument list
/// - `S_PROC_ID_END` (0x114F) -- end of procedure ID scope
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
    ///
    /// This parser is shared by `S_END`, `S_ENDARG`, and `S_PROC_ID_END`
    /// since all three have identical (empty) payloads.
    pub fn parse(_data: &[u8]) -> Option<Self> {
        Some(Self)
    }

    /// Create an S_END symbol for the `S_ENDARG` variant (0x000A).
    ///
    /// Semantically this marks the end of an argument list rather than
    /// a general scope, but the binary format is identical.
    pub fn endarg() -> Self {
        Self
    }

    /// Create an S_END symbol for the `S_PROC_ID_END` variant (0x114F).
    ///
    /// This marks the end of a procedure ID scope in PDB v70+ streams.
    pub fn proc_id_end() -> Self {
        Self
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
    fn test_endarg() {
        let sym = SEnd::endarg();
        // Same struct, same pdb_id -- semantic distinction is in the parser
        assert_eq!(sym.pdb_id(), 0x0006);
        assert_eq!(sym, SEnd::new());
    }

    #[test]
    fn test_proc_id_end() {
        let sym = SEnd::proc_id_end();
        assert_eq!(sym.pdb_id(), 0x0006);
        assert_eq!(sym, SEnd::new());
    }

    #[test]
    fn test_clone_eq() {
        let a = SEnd::new();
        let b = a.clone();
        assert_eq!(a, b);
    }
}
