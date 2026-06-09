//! AbstractMsSymbol -- base trait for all PDB MS symbol records.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol`.

use std::fmt;

/// Base trait for all PDB MS (Microsoft) symbol records.
///
/// Every CodeView `S_*` symbol record in a PDB implements this trait. It
/// provides the common interface for obtaining the symbol's numeric kind
/// identifier (`pdb_id`) and its human-readable type name.
///
/// # Hierarchy Notes
///
/// In Ghidra's Java implementation, `AbstractMsSymbol` is the abstract base
/// class for the full symbol hierarchy. Sub-variants end in:
///
/// - `16MsSymbol` — 16-bit offsets, 16-bit type indices, ST-format strings.
/// - `StMsSymbol` / `32StMsSymbol` — 32-bit type indices, 16-bit offsets, ST strings.
/// - `3216MsSymbol` — 16-bit type indices, 32-bit offsets, NT strings.
/// - `MsSymbol` / `32MsSymbol` — 32-bit type indices, 32-bit offsets, NT strings.
///
/// This Rust port represents all variants through a single trait with
/// concrete struct implementations rather than an inheritance hierarchy.
pub trait AbstractMsSymbol: fmt::Debug {
    /// Return the unique numeric identifier (PDB ID / symbol kind) for this
    /// symbol type.
    ///
    /// This corresponds to the `S_*` constants (e.g., `S_GDATA32 = 0x0202`).
    fn pdb_id(&self) -> u16;

    /// Return the string name of this symbol type as documented in the
    /// Microsoft PDB API.
    ///
    /// For example, `"S_GDATA32"`, `"S_GPROC32"`, etc.
    fn symbol_type_name(&self) -> &'static str;

    /// Emit a human-readable description of this symbol into the formatter.
    ///
    /// The default implementation prints the symbol type name.
    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NotImplemented({})", self.symbol_type_name())
    }
}

/// A minimal concrete implementation of [`AbstractMsSymbol`] for symbols
/// whose kind is known but whose fields have not been fully parsed.
///
/// This is used as a placeholder when a symbol record is encountered with
/// a recognized kind but the full parsing is deferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownMsSymbol {
    /// The raw symbol kind (S_* value).
    pub kind: u16,
    /// The raw payload bytes.
    pub raw_data: Vec<u8>,
}

impl AbstractMsSymbol for UnknownMsSymbol {
    fn pdb_id(&self) -> u16 {
        self.kind
    }

    fn symbol_type_name(&self) -> &'static str {
        "UNKNOWN"
    }
}

impl fmt::Display for UnknownMsSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnknownMsSymbol(kind=0x{:04X})", self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestSymbol;

    impl AbstractMsSymbol for TestSymbol {
        fn pdb_id(&self) -> u16 {
            0x0202
        }
        fn symbol_type_name(&self) -> &'static str {
            "S_GDATA32"
        }
    }

    #[test]
    fn test_pdb_id() {
        let sym = TestSymbol;
        assert_eq!(sym.pdb_id(), 0x0202);
    }

    #[test]
    fn test_symbol_type_name() {
        let sym = TestSymbol;
        assert_eq!(sym.symbol_type_name(), "S_GDATA32");
    }

    #[test]
    fn test_unknown_ms_symbol() {
        let sym = UnknownMsSymbol {
            kind: 0xFFFF,
            raw_data: vec![0x01, 0x02, 0x03],
        };
        assert_eq!(sym.pdb_id(), 0xFFFF);
        assert_eq!(sym.symbol_type_name(), "UNKNOWN");
        assert_eq!(format!("{}", sym), "UnknownMsSymbol(kind=0xFFFF)");
    }
}
