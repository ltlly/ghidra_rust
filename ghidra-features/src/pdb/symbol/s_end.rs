//! S_END -- End symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EndMsSymbol`.
//!
//! The same zero-length sentinel is used by `S_END` (0x0006), `S_ENDARG`
//! (0x000A), and `S_PROC_ID_END` (0x1040) -- all share the same binary
//! layout (no payload) and differ only in semantic context.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// Which variant of the end symbol this represents.
///
/// All three share the same zero-payload binary format but carry different
/// semantic meaning in the PDB symbol stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndVariant {
    /// `S_END` (0x0006) -- general end-of-scope marker.
    End,
    /// `S_ENDARG` (0x000A) -- end of argument list.
    EndArg,
    /// `S_PROC_ID_END` (0x1040) -- end of procedure ID scope (PDB v70+).
    ProcIdEnd,
}

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
/// - `S_PROC_ID_END` (0x1040) -- end of procedure ID scope
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SEnd {
    /// Which variant was specified.
    variant: EndVariant,
}

impl SEnd {
    /// Create a new end symbol (S_END variant).
    pub fn new() -> Self {
        Self {
            variant: EndVariant::End,
        }
    }

    /// Parse an S_END symbol from a byte slice.
    ///
    /// The S_END symbol has no payload; any data present is ignored.
    /// Always returns `Some(SEnd)` with the `End` variant.
    ///
    /// To create other variants, use [`endarg()`](Self::endarg) or
    /// [`proc_id_end()`](Self::proc_id_end), or the `From<EndVariant>` impl.
    pub fn parse(_data: &[u8]) -> Option<Self> {
        Some(Self::new())
    }

    /// Create an S_END symbol for the `S_ENDARG` variant (0x000A).
    ///
    /// Semantically this marks the end of an argument list rather than
    /// a general scope, but the binary format is identical.
    pub fn endarg() -> Self {
        Self {
            variant: EndVariant::EndArg,
        }
    }

    /// Create an S_END symbol for the `S_PROC_ID_END` variant (0x1040).
    ///
    /// This marks the end of a procedure ID scope in PDB v70+ streams.
    pub fn proc_id_end() -> Self {
        Self {
            variant: EndVariant::ProcIdEnd,
        }
    }

    /// Return the variant of this end symbol.
    pub fn variant(&self) -> EndVariant {
        self.variant
    }
}

impl Default for SEnd {
    fn default() -> Self {
        Self::new()
    }
}

impl From<EndVariant> for SEnd {
    fn from(variant: EndVariant) -> Self {
        Self { variant }
    }
}

impl AbstractMsSymbol for SEnd {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            EndVariant::End => super::super::symbol_kind::S_END,
            EndVariant::EndArg => super::super::symbol_kind::S_ENDARG,
            EndVariant::ProcIdEnd => super::super::symbol_kind::S_PROC_ID_END,
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            EndVariant::End => "S_END",
            EndVariant::EndArg => "S_ENDARG",
            EndVariant::ProcIdEnd => "S_PROC_ID_END",
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.variant {
            EndVariant::End => write!(f, "End"),
            EndVariant::EndArg => write!(f, "EndArg"),
            EndVariant::ProcIdEnd => write!(f, "ProcIdEnd"),
        }
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
        assert_eq!(sym.variant(), EndVariant::End);
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
    fn test_display_endarg() {
        let sym = SEnd::endarg();
        let s = format!("{}", sym);
        assert_eq!(s, "EndArg");
    }

    #[test]
    fn test_display_proc_id_end() {
        let sym = SEnd::proc_id_end();
        let s = format!("{}", sym);
        assert_eq!(s, "ProcIdEnd");
    }

    #[test]
    fn test_default() {
        let sym = SEnd::default();
        assert_eq!(sym, SEnd::new());
    }

    #[test]
    fn test_endarg() {
        let sym = SEnd::endarg();
        assert_eq!(sym.pdb_id(), 0x000A);
        assert_eq!(sym.symbol_type_name(), "S_ENDARG");
        assert_eq!(sym.variant(), EndVariant::EndArg);
        assert_eq!(sym, SEnd::from(EndVariant::EndArg));
    }

    #[test]
    fn test_proc_id_end() {
        let sym = SEnd::proc_id_end();
        assert_eq!(sym.pdb_id(), 0x1040);
        assert_eq!(sym.symbol_type_name(), "S_PROC_ID_END");
        assert_eq!(sym.variant(), EndVariant::ProcIdEnd);
        assert_eq!(sym, SEnd::from(EndVariant::ProcIdEnd));
    }

    #[test]
    fn test_clone_eq() {
        let a = SEnd::new();
        let b = a.clone();
        assert_eq!(a, b);

        let a = SEnd::endarg();
        let b = a.clone();
        assert_eq!(a, b);

        let a = SEnd::proc_id_end();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_from_variant() {
        let sym: SEnd = EndVariant::End.into();
        assert_eq!(sym.pdb_id(), 0x0006);
        assert_eq!(sym.symbol_type_name(), "S_END");

        let sym: SEnd = EndVariant::EndArg.into();
        assert_eq!(sym.pdb_id(), 0x000A);

        let sym: SEnd = EndVariant::ProcIdEnd.into();
        assert_eq!(sym.pdb_id(), 0x1040);
    }

    #[test]
    fn test_variant_distinct() {
        assert_ne!(SEnd::new().variant(), SEnd::endarg().variant());
        assert_ne!(SEnd::new().variant(), SEnd::proc_id_end().variant());
        assert_ne!(SEnd::endarg().variant(), SEnd::proc_id_end().variant());
    }
}
