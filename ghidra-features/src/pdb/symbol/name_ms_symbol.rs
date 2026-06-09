//! NameMsSymbol -- trait for PDB symbols that carry a name.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.NameMsSymbol`.
//!
//! This file provides the [`NameMsSymbol`] trait definition. In the Rust port
//! the trait is also re-exported from [`super::address_ms_symbol`] alongside
//! [`AddressMsSymbol`] for convenience, since most address-bearing symbols
//! also have names.

/// Trait for PDB symbols that have a symbol name.
///
/// Many `S_*` symbol records include a name string. This trait provides a
/// uniform accessor for the name field.
///
/// # Implementors
///
/// - Data symbols (`S_GDATA32`, `S_LDATA32`, etc.)
/// - Procedure symbols (`S_GPROC32`, `S_LPROC32`, etc.)
/// - Public symbols (`S_PUB32`)
/// - Label symbols (`S_LABEL32`)
/// - UDT symbols (`S_UDT`)
/// - Constant symbols (`S_CONSTANT`)
/// - Register symbols (`S_REGISTER`)
/// - Register-relative symbols (`S_REGREL32`)
/// - Base-pointer-relative symbols (`S_BPREL32`)
/// - Thread storage symbols (`S_GTHREAD32`, `S_LTHREAD32`)
/// - Thunk symbols (`S_THUNK32`)
/// - Object name symbols (`S_OBJNAME`)
/// - Export symbols (`S_EXPORT`)
/// - VfTable symbols (`S_VFTABLE32`)
/// - COFF group symbols (`S_COFFGROUP`)
/// - Section symbols (`S_SECTION`)
/// - Annotation symbols (`S_ANNOTATION`)
pub trait NameMsSymbol {
    /// Return the name of this symbol.
    fn name(&self) -> &str;
}

/// A simple struct implementing [`NameMsSymbol`] for cases where a
/// name is carried alongside other data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSymbol {
    pub name: String,
}

impl NameMsSymbol for NamedSymbol {
    fn name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for NamedSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_named_symbol() {
        let sym = NamedSymbol {
            name: "my_variable".to_string(),
        };
        assert_eq!(sym.name(), "my_variable");
        assert_eq!(format!("{}", sym), "my_variable");
    }

    #[test]
    fn test_empty_name() {
        let sym = NamedSymbol {
            name: String::new(),
        };
        assert_eq!(sym.name(), "");
    }
}
