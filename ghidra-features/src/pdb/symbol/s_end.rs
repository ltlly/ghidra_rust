//! S_END -- End symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EndMsSymbol`
//! (0x0006), `EndArgumentsListMsSymbol` (0x000A), `ProcedureIdEndMsSymbol`
//! (0x1040 / 0x114F), and `InlinedFunctionEndMsSymbol` (0x114E).
//!
//! All share the same zero-length binary layout (no payload) and differ only
//! in semantic context.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// Which variant of the end symbol this represents.
///
/// All variants share the same zero-payload binary format but carry different
/// semantic meaning in the PDB symbol stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndVariant {
    /// `S_END` (0x0006) -- general end-of-scope marker.
    End,
    /// `S_ENDARG` (0x000A) -- end of argument list.
    EndArg,
    /// `S_PROC_ID_END` (0x1040) -- end of procedure ID scope (PDB v70+).
    ProcIdEnd,
    /// `S_INLINESITE_END` (0x103F) -- end of inline site.
    InlineSiteEnd,
    /// `S_INLINED_FUNCTION_END` (0x114E) -- end of inlined function.
    InlinedFunctionEnd,
    /// `S_PROCEDURE_ID_END` (0x114F) -- end of procedure ID (v7 variant).
    ProcedureIdEnd,
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
/// - `S_INLINESITE_END` (0x103F) -- end of inline site
/// - `S_INLINED_FUNCTION_END` (0x114E) -- end of inlined function
/// - `S_PROCEDURE_ID_END` (0x114F) -- end of procedure ID (v7 variant)
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

    /// Create an S_END symbol for the `S_INLINESITE_END` variant (0x103F).
    ///
    /// This marks the end of an inline site scope.
    pub fn inline_site_end() -> Self {
        Self {
            variant: EndVariant::InlineSiteEnd,
        }
    }

    /// Create an S_END symbol for the `S_INLINED_FUNCTION_END` variant (0x114E).
    ///
    /// This marks the end of an inlined function.
    pub fn inlined_function_end() -> Self {
        Self {
            variant: EndVariant::InlinedFunctionEnd,
        }
    }

    /// Create an S_END symbol for the `S_PROCEDURE_ID_END` variant (0x114F).
    ///
    /// This marks the end of a procedure ID (v7 variant).
    pub fn procedure_id_end() -> Self {
        Self {
            variant: EndVariant::ProcedureIdEnd,
        }
    }

    /// Return the variant of this end symbol.
    pub fn variant(&self) -> EndVariant {
        self.variant
    }

    /// Return `true` if this is a general end-of-scope marker (`S_END`).
    pub fn is_end(&self) -> bool {
        self.variant == EndVariant::End
    }

    /// Return `true` if this is an end-of-argument-list marker (`S_ENDARG`).
    pub fn is_endarg(&self) -> bool {
        self.variant == EndVariant::EndArg
    }

    /// Return `true` if this is a procedure ID end marker (`S_PROC_ID_END`).
    pub fn is_proc_id_end(&self) -> bool {
        self.variant == EndVariant::ProcIdEnd
    }

    /// Return `true` if this is an inline site end marker (`S_INLINESITE_END`).
    pub fn is_inline_site_end(&self) -> bool {
        self.variant == EndVariant::InlineSiteEnd
    }

    /// Return `true` if this is an inlined function end marker
    /// (`S_INLINED_FUNCTION_END`).
    pub fn is_inlined_function_end(&self) -> bool {
        self.variant == EndVariant::InlinedFunctionEnd
    }

    /// Return `true` if this is a procedure ID end marker (v7 variant,
    /// `S_PROCEDURE_ID_END`).
    pub fn is_procedure_id_end(&self) -> bool {
        self.variant == EndVariant::ProcedureIdEnd
    }

    /// Return `true` if this variant marks the end of a scope that began
    /// with a procedure symbol (S_END or S_PROC_ID_END).
    pub fn is_procedure_end(&self) -> bool {
        matches!(self.variant, EndVariant::End | EndVariant::ProcIdEnd | EndVariant::ProcedureIdEnd)
    }

    /// Return `true` if this variant marks the end of an inline site
    /// (S_INLINESITE_END or S_INLINED_FUNCTION_END).
    pub fn is_inline_end(&self) -> bool {
        matches!(self.variant, EndVariant::InlineSiteEnd | EndVariant::InlinedFunctionEnd)
    }

    /// Parse an S_ENDARG symbol from a byte slice.
    ///
    /// The S_ENDARG symbol has no payload; any data present is ignored.
    /// Always returns `Some(SEnd)` with the `EndArg` variant.
    pub fn parse_endarg(_data: &[u8]) -> Option<Self> {
        Some(Self::endarg())
    }

    /// Parse an S_PROC_ID_END symbol from a byte slice.
    ///
    /// The S_PROC_ID_END symbol has no payload; any data present is ignored.
    /// Always returns `Some(SEnd)` with the `ProcIdEnd` variant.
    pub fn parse_proc_id_end(_data: &[u8]) -> Option<Self> {
        Some(Self::proc_id_end())
    }

    /// Parse an S_INLINESITE_END symbol from a byte slice.
    ///
    /// Always returns `Some(SEnd)` with the `InlineSiteEnd` variant.
    pub fn parse_inline_site_end(_data: &[u8]) -> Option<Self> {
        Some(Self::inline_site_end())
    }

    /// Parse an S_INLINED_FUNCTION_END symbol from a byte slice.
    ///
    /// Always returns `Some(SEnd)` with the `InlinedFunctionEnd` variant.
    pub fn parse_inlined_function_end(_data: &[u8]) -> Option<Self> {
        Some(Self::inlined_function_end())
    }

    /// Parse an S_PROCEDURE_ID_END symbol from a byte slice.
    ///
    /// Always returns `Some(SEnd)` with the `ProcedureIdEnd` variant.
    pub fn parse_procedure_id_end(_data: &[u8]) -> Option<Self> {
        Some(Self::procedure_id_end())
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

impl fmt::Display for EndVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndVariant::End => write!(f, "End"),
            EndVariant::EndArg => write!(f, "EndArg"),
            EndVariant::ProcIdEnd => write!(f, "ProcIdEnd"),
            EndVariant::InlineSiteEnd => write!(f, "InlineSiteEnd"),
            EndVariant::InlinedFunctionEnd => write!(f, "InlinedFunctionEnd"),
            EndVariant::ProcedureIdEnd => write!(f, "ProcedureIdEnd"),
        }
    }
}

impl AbstractMsSymbol for SEnd {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            EndVariant::End => super::super::symbol_kind::S_END,
            EndVariant::EndArg => super::super::symbol_kind::S_ENDARG,
            EndVariant::ProcIdEnd => super::super::symbol_kind::S_PROC_ID_END,
            EndVariant::InlineSiteEnd => super::super::symbol_kind::S_INLINESITE_END,
            EndVariant::InlinedFunctionEnd => super::super::symbol_kind::S_INLINED_FUNCTION_END,
            EndVariant::ProcedureIdEnd => super::super::symbol_kind::S_PROCEDURE_ID_END,
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            EndVariant::End => "S_END",
            EndVariant::EndArg => "S_ENDARG",
            EndVariant::ProcIdEnd => "S_PROC_ID_END",
            EndVariant::InlineSiteEnd => "S_INLINESITE_END",
            EndVariant::InlinedFunctionEnd => "S_INLINED_FUNCTION_END",
            EndVariant::ProcedureIdEnd => "S_PROCEDURE_ID_END",
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.variant {
            EndVariant::End => write!(f, "End"),
            EndVariant::EndArg => write!(f, "EndArg"),
            EndVariant::ProcIdEnd => write!(f, "ProcIdEnd"),
            EndVariant::InlineSiteEnd => write!(f, "InlineSiteEnd"),
            EndVariant::InlinedFunctionEnd => write!(f, "InlinedFunctionEnd"),
            EndVariant::ProcedureIdEnd => write!(f, "ProcedureIdEnd"),
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

    #[test]
    fn test_is_end() {
        assert!(SEnd::new().is_end());
        assert!(!SEnd::endarg().is_end());
        assert!(!SEnd::proc_id_end().is_end());
    }

    #[test]
    fn test_is_endarg() {
        assert!(!SEnd::new().is_endarg());
        assert!(SEnd::endarg().is_endarg());
        assert!(!SEnd::proc_id_end().is_endarg());
    }

    #[test]
    fn test_is_proc_id_end() {
        assert!(!SEnd::new().is_proc_id_end());
        assert!(!SEnd::endarg().is_proc_id_end());
        assert!(SEnd::proc_id_end().is_proc_id_end());
    }

    #[test]
    fn test_parse_endarg() {
        let sym = SEnd::parse_endarg(&[]).unwrap();
        assert_eq!(sym.pdb_id(), 0x000A);
        assert_eq!(sym.symbol_type_name(), "S_ENDARG");
        assert!(sym.is_endarg());
    }

    #[test]
    fn test_parse_proc_id_end() {
        let sym = SEnd::parse_proc_id_end(&[]).unwrap();
        assert_eq!(sym.pdb_id(), 0x1040);
        assert_eq!(sym.symbol_type_name(), "S_PROC_ID_END");
        assert!(sym.is_proc_id_end());
    }

    #[test]
    fn test_parse_endarg_with_data() {
        // S_ENDARG has no payload; trailing bytes are ignored
        let data = [0xFF, 0xFF];
        let sym = SEnd::parse_endarg(&data).unwrap();
        assert_eq!(sym.pdb_id(), 0x000A);
    }

    #[test]
    fn test_inline_site_end() {
        let sym = SEnd::inline_site_end();
        assert_eq!(sym.pdb_id(), 0x103F);
        assert_eq!(sym.symbol_type_name(), "S_INLINESITE_END");
        assert_eq!(sym.variant(), EndVariant::InlineSiteEnd);
        assert!(sym.is_inline_site_end());
        assert!(!sym.is_end());
        let s = format!("{}", sym);
        assert_eq!(s, "InlineSiteEnd");
    }

    #[test]
    fn test_inlined_function_end() {
        let sym = SEnd::inlined_function_end();
        assert_eq!(sym.pdb_id(), 0x114E);
        assert_eq!(sym.symbol_type_name(), "S_INLINED_FUNCTION_END");
        assert_eq!(sym.variant(), EndVariant::InlinedFunctionEnd);
        assert!(sym.is_inlined_function_end());
        let s = format!("{}", sym);
        assert_eq!(s, "InlinedFunctionEnd");
    }

    #[test]
    fn test_procedure_id_end() {
        let sym = SEnd::procedure_id_end();
        assert_eq!(sym.pdb_id(), 0x114F);
        assert_eq!(sym.symbol_type_name(), "S_PROCEDURE_ID_END");
        assert_eq!(sym.variant(), EndVariant::ProcedureIdEnd);
        assert!(sym.is_procedure_id_end());
        let s = format!("{}", sym);
        assert_eq!(s, "ProcedureIdEnd");
    }

    #[test]
    fn test_parse_inline_site_end() {
        let sym = SEnd::parse_inline_site_end(&[]).unwrap();
        assert_eq!(sym.pdb_id(), 0x103F);
        assert!(sym.is_inline_site_end());
    }

    #[test]
    fn test_parse_inlined_function_end() {
        let sym = SEnd::parse_inlined_function_end(&[]).unwrap();
        assert_eq!(sym.pdb_id(), 0x114E);
        assert!(sym.is_inlined_function_end());
    }

    #[test]
    fn test_parse_procedure_id_end() {
        let sym = SEnd::parse_procedure_id_end(&[]).unwrap();
        assert_eq!(sym.pdb_id(), 0x114F);
        assert!(sym.is_procedure_id_end());
    }

    #[test]
    fn test_clone_eq_new_variants() {
        let a = SEnd::inline_site_end();
        let b = a.clone();
        assert_eq!(a, b);

        let a = SEnd::inlined_function_end();
        let b = a.clone();
        assert_eq!(a, b);

        let a = SEnd::procedure_id_end();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_from_variant_new() {
        let sym: SEnd = EndVariant::InlineSiteEnd.into();
        assert_eq!(sym.pdb_id(), 0x103F);

        let sym: SEnd = EndVariant::InlinedFunctionEnd.into();
        assert_eq!(sym.pdb_id(), 0x114E);

        let sym: SEnd = EndVariant::ProcedureIdEnd.into();
        assert_eq!(sym.pdb_id(), 0x114F);
    }

    #[test]
    fn test_variant_distinct_all() {
        let variants = [
            SEnd::new().variant(),
            SEnd::endarg().variant(),
            SEnd::proc_id_end().variant(),
            SEnd::inline_site_end().variant(),
            SEnd::inlined_function_end().variant(),
            SEnd::procedure_id_end().variant(),
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
    }

    #[test]
    fn test_is_procedure_end() {
        assert!(SEnd::new().is_procedure_end());
        assert!(!SEnd::endarg().is_procedure_end());
        assert!(SEnd::proc_id_end().is_procedure_end());
        assert!(!SEnd::inline_site_end().is_procedure_end());
        assert!(!SEnd::inlined_function_end().is_procedure_end());
        assert!(SEnd::procedure_id_end().is_procedure_end());
    }

    #[test]
    fn test_is_inline_end() {
        assert!(!SEnd::new().is_inline_end());
        assert!(!SEnd::endarg().is_inline_end());
        assert!(!SEnd::proc_id_end().is_inline_end());
        assert!(SEnd::inline_site_end().is_inline_end());
        assert!(SEnd::inlined_function_end().is_inline_end());
        assert!(!SEnd::procedure_id_end().is_inline_end());
    }

    #[test]
    fn test_end_variant_display() {
        assert_eq!(format!("{}", EndVariant::End), "End");
        assert_eq!(format!("{}", EndVariant::EndArg), "EndArg");
        assert_eq!(format!("{}", EndVariant::ProcIdEnd), "ProcIdEnd");
        assert_eq!(format!("{}", EndVariant::InlineSiteEnd), "InlineSiteEnd");
        assert_eq!(format!("{}", EndVariant::InlinedFunctionEnd), "InlinedFunctionEnd");
        assert_eq!(format!("{}", EndVariant::ProcedureIdEnd), "ProcedureIdEnd");
    }
}
