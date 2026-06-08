//! Unix a.out symbol entry ported from Ghidra's `UnixAoutSymbol.java`.

use std::fmt;

/// Symbol type constants for UNIX a.out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    /// Undefined symbol.
    N_UNDF,
    /// Absolute symbol.
    N_ABS,
    /// Text segment symbol.
    N_TEXT,
    /// Data segment symbol.
    N_DATA,
    /// BSS segment symbol.
    N_BSS,
    /// Indirect symbol.
    N_INDR,
    /// File name symbol.
    N_FN,
    /// STAB debugging symbol (type >= 0x20).
    N_STAB,
    /// Unknown/unrecognized symbol type.
    UNKNOWN,
}

impl SymbolType {
    /// Parse a symbol type from the raw type byte (with the external bit masked off).
    pub fn from_byte(type_byte: u8) -> Self {
        let masked = type_byte & 0xFE;
        match masked {
            0x00 => Self::N_UNDF,
            0x02 => Self::N_ABS,
            0x04 => Self::N_TEXT,
            0x06 => Self::N_DATA,
            0x08 => Self::N_BSS,
            0x0A => Self::N_INDR,
            _ if masked >= 0x20 => Self::N_STAB,
            _ => Self::UNKNOWN,
        }
    }
}

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::N_UNDF => write!(f, "N_UNDF"),
            Self::N_ABS => write!(f, "N_ABS"),
            Self::N_TEXT => write!(f, "N_TEXT"),
            Self::N_DATA => write!(f, "N_DATA"),
            Self::N_BSS => write!(f, "N_BSS"),
            Self::N_INDR => write!(f, "N_INDR"),
            Self::N_FN => write!(f, "N_FN"),
            Self::N_STAB => write!(f, "N_STAB"),
            Self::UNKNOWN => write!(f, "UNKNOWN"),
        }
    }
}

/// Symbol kind for auxiliary information in UNIX a.out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// Auxiliary object.
    AUX_OBJECT,
    /// Auxiliary function.
    AUX_FUNC,
    /// Auxiliary label.
    AUX_LABEL,
    /// Unknown auxiliary kind.
    UNKNOWN,
}

impl SymbolKind {
    /// Parse a symbol kind from the `n_other` byte (low 4 bits).
    pub fn from_byte(other_byte: u8) -> Self {
        match other_byte & 0x0F {
            1 => Self::AUX_OBJECT,
            2 => Self::AUX_FUNC,
            3 => Self::AUX_LABEL,
            _ => Self::UNKNOWN,
        }
    }
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AUX_OBJECT => write!(f, "AUX_OBJECT"),
            Self::AUX_FUNC => write!(f, "AUX_FUNC"),
            Self::AUX_LABEL => write!(f, "AUX_LABEL"),
            Self::UNKNOWN => write!(f, "UNKNOWN"),
        }
    }
}

/// Represents a single entry in the UNIX a.out symbol table.
///
/// Ported from `ghidra.app.util.bin.format.unixaout.UnixAoutSymbol`.
///
/// Each entry is 12 bytes:
/// ```text
/// DWORD  n_strx   // String table offset for symbol name
/// BYTE   n_type   // Symbol type (bit 0 = external)
/// BYTE   n_other  // Auxiliary info (low 4 bits = kind)
/// WORD   n_desc   // Description field
/// DWORD  n_value  // Symbol value
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixAoutSymbol {
    /// Offset into the string table for the symbol name.
    pub name_string_offset: u32,
    /// The resolved symbol name (populated from the string table).
    pub name: Option<String>,
    /// The symbol type.
    pub symbol_type: SymbolType,
    /// The auxiliary symbol kind.
    pub kind: SymbolKind,
    /// The raw `n_other` byte.
    pub other_byte: u8,
    /// The descriptor field.
    pub desc: i16,
    /// The symbol value (address).
    pub value: u32,
    /// True if this is an external symbol (bit 0 of type byte is set).
    pub is_ext: bool,
}

impl UnixAoutSymbol {
    /// Size of a single symbol table entry in bytes.
    pub const SIZE: usize = 12;

    /// Create a new symbol from the raw table fields.
    pub fn new(
        name_string_offset: u32,
        type_byte: u8,
        other_byte: u8,
        desc: i16,
        value: u32,
    ) -> Self {
        let is_ext = (type_byte & 1) == 1;
        let symbol_type = SymbolType::from_byte(type_byte);
        let kind = SymbolKind::from_byte(other_byte);

        Self {
            name_string_offset,
            name: None,
            symbol_type,
            kind,
            other_byte,
            desc,
            value,
            is_ext,
        }
    }

    /// Returns true if this symbol's type is recognized.
    pub fn is_known_type(&self) -> bool {
        self.symbol_type != SymbolType::UNKNOWN
    }

    /// Returns the symbol name, or an empty string if not set.
    pub fn name_str(&self) -> &str {
        self.name.as_deref().unwrap_or("")
    }
}

impl fmt::Display for UnixAoutSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UnixAoutSymbol {{ name={}, type={}, kind={}, ext={}, \
             value=0x{:08X} }}",
            self.name_str(),
            self.symbol_type,
            self.kind,
            self.is_ext,
            self.value
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
    fn test_symbol_type_parsing() {
        assert_eq!(SymbolType::from_byte(0x00), SymbolType::N_UNDF);
        assert_eq!(SymbolType::from_byte(0x01), SymbolType::N_UNDF); // ext bit set
        assert_eq!(SymbolType::from_byte(0x02), SymbolType::N_ABS);
        assert_eq!(SymbolType::from_byte(0x03), SymbolType::N_ABS); // ext
        assert_eq!(SymbolType::from_byte(0x04), SymbolType::N_TEXT);
        assert_eq!(SymbolType::from_byte(0x06), SymbolType::N_DATA);
        assert_eq!(SymbolType::from_byte(0x08), SymbolType::N_BSS);
        assert_eq!(SymbolType::from_byte(0x0A), SymbolType::N_INDR);
        assert_eq!(SymbolType::from_byte(0x20), SymbolType::N_STAB);
        assert_eq!(SymbolType::from_byte(0x24), SymbolType::N_STAB);
        assert_eq!(SymbolType::from_byte(0x0C), SymbolType::UNKNOWN);
    }

    #[test]
    fn test_symbol_kind_parsing() {
        assert_eq!(SymbolKind::from_byte(0x01), SymbolKind::AUX_OBJECT);
        assert_eq!(SymbolKind::from_byte(0x02), SymbolKind::AUX_FUNC);
        assert_eq!(SymbolKind::from_byte(0x03), SymbolKind::AUX_LABEL);
        assert_eq!(SymbolKind::from_byte(0x00), SymbolKind::UNKNOWN);
        assert_eq!(SymbolKind::from_byte(0x04), SymbolKind::UNKNOWN);
        assert_eq!(SymbolKind::from_byte(0xFF), SymbolKind::UNKNOWN);
    }

    #[test]
    fn test_symbol_creation() {
        let sym = UnixAoutSymbol::new(0x100, 0x05, 0x02, 0, 0x08048000);
        // type_byte=0x05 -> masked=0x04 -> N_TEXT, ext=true
        assert_eq!(sym.symbol_type, SymbolType::N_TEXT);
        assert!(sym.is_ext);
        assert_eq!(sym.kind, SymbolKind::AUX_FUNC);
        assert_eq!(sym.value, 0x08048000);
        assert_eq!(sym.name_string_offset, 0x100);
    }

    #[test]
    fn test_symbol_non_ext() {
        let sym = UnixAoutSymbol::new(0, 0x04, 0, 0, 0x1000);
        assert!(!sym.is_ext);
        assert_eq!(sym.symbol_type, SymbolType::N_TEXT);
    }

    #[test]
    fn test_symbol_name_default() {
        let sym = UnixAoutSymbol::new(0, 0, 0, 0, 0);
        assert_eq!(sym.name_str(), "");
        assert!(sym.name.is_none());
    }

    #[test]
    fn test_symbol_with_name() {
        let mut sym = UnixAoutSymbol::new(0, 0x02, 0, 0, 0x1000);
        sym.name = Some("main".to_string());
        assert_eq!(sym.name_str(), "main");
    }

    #[test]
    fn test_symbol_display() {
        let mut sym = UnixAoutSymbol::new(0x50, 0x05, 0x02, 0, 0x08048000);
        sym.name = Some("start".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("start"));
        assert!(s.contains("N_TEXT"));
        assert!(s.contains("AUX_FUNC"));
    }

    #[test]
    fn test_stab_symbol() {
        let sym = UnixAoutSymbol::new(0, 0x24, 0, 0, 0);
        assert_eq!(sym.symbol_type, SymbolType::N_STAB);
        assert!(sym.is_known_type());
    }

    #[test]
    fn test_unknown_symbol() {
        let sym = UnixAoutSymbol::new(0, 0x0C, 0, 0, 0);
        assert_eq!(sym.symbol_type, SymbolType::UNKNOWN);
        assert!(!sym.is_known_type());
    }
}
