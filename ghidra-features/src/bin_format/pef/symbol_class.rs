//! PEF symbol class values ported from Ghidra's `SymbolClass.java`.
//!
//! Imported and exported symbol classes for the PEF binary format.

/// Imported and exported symbol classes.
///
/// See Apple's PEFBinaryFormat.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SymbolClass {
    /// A code address.
    CodeSymbol = 0x00,
    /// A data address.
    DataSymbol = 0x01,
    /// A standard procedure pointer (transition vector).
    TVectSymbol = 0x02,
    /// A direct data area (table of contents) symbol.
    TOCSymbol = 0x03,
    /// A linker-inserted glue symbol.
    GlueSymbol = 0x04,
    /// An undefined symbol.
    UndefinedSymbol = 0x0f,
}

impl SymbolClass {
    /// Returns the numeric value of this symbol class.
    pub fn value(self) -> u8 {
        self as u8
    }

    /// Look up a `SymbolClass` by its numeric value.
    ///
    /// Returns `None` for unrecognized values.
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(SymbolClass::CodeSymbol),
            0x01 => Some(SymbolClass::DataSymbol),
            0x02 => Some(SymbolClass::TVectSymbol),
            0x03 => Some(SymbolClass::TOCSymbol),
            0x04 => Some(SymbolClass::GlueSymbol),
            0x0f => Some(SymbolClass::UndefinedSymbol),
            _ => None,
        }
    }

    /// Returns a human-readable name for this symbol class.
    pub fn name(self) -> &'static str {
        match self {
            SymbolClass::CodeSymbol => "CodeSymbol",
            SymbolClass::DataSymbol => "DataSymbol",
            SymbolClass::TVectSymbol => "TVectSymbol",
            SymbolClass::TOCSymbol => "TOCSymbol",
            SymbolClass::GlueSymbol => "GlueSymbol",
            SymbolClass::UndefinedSymbol => "UndefinedSymbol",
        }
    }
}

impl std::fmt::Display for SymbolClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_class_from_value() {
        assert_eq!(SymbolClass::from_value(0x00), Some(SymbolClass::CodeSymbol));
        assert_eq!(SymbolClass::from_value(0x01), Some(SymbolClass::DataSymbol));
        assert_eq!(SymbolClass::from_value(0x02), Some(SymbolClass::TVectSymbol));
        assert_eq!(SymbolClass::from_value(0x03), Some(SymbolClass::TOCSymbol));
        assert_eq!(SymbolClass::from_value(0x04), Some(SymbolClass::GlueSymbol));
        assert_eq!(
            SymbolClass::from_value(0x0f),
            Some(SymbolClass::UndefinedSymbol)
        );
        assert_eq!(SymbolClass::from_value(0x05), None);
        assert_eq!(SymbolClass::from_value(0x0e), None);
    }

    #[test]
    fn test_symbol_class_value_roundtrip() {
        for &val in &[0x00u8, 0x01, 0x02, 0x03, 0x04, 0x0f] {
            let class = SymbolClass::from_value(val).unwrap();
            assert_eq!(class.value(), val);
        }
    }

    #[test]
    fn test_symbol_class_name() {
        assert_eq!(SymbolClass::CodeSymbol.name(), "CodeSymbol");
        assert_eq!(SymbolClass::UndefinedSymbol.name(), "UndefinedSymbol");
    }

    #[test]
    fn test_symbol_class_display() {
        assert_eq!(format!("{}", SymbolClass::CodeSymbol), "CodeSymbol");
    }
}
