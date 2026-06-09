//! StringParseType -- controls how symbol name strings are parsed from PDB byte streams.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.StringParseType`.

/// Controls how symbol name strings are parsed from PDB byte streams.
///
/// PDB symbol records use different string encodings depending on the symbol
/// version (16-bit, ST, 32-bit, etc.). This enum selects the correct parsing
/// strategy.
///
/// # Variants
///
/// - `StringSt` — An ST-format string: a 16-bit unsigned length prefix followed
///   by that many bytes of UTF-8 (or legacy codepage) data.
/// - `StringNt` — A null-terminated (NT) string with no length prefix.
/// - `StringUtf8St` — UTF-8 encoded ST-format string (16-bit length prefix).
/// - `StringUtf8Nt` — UTF-8 encoded null-terminated string.
/// - `StringWcharNt` — Wide-character null-terminated string (UTF-16LE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringParseType {
    /// ST-format string (16-bit length prefix, codepage bytes).
    StringSt,
    /// Null-terminated string (no length prefix).
    StringNt,
    /// UTF-8 ST-format string (16-bit length prefix, UTF-8 bytes).
    StringUtf8St,
    /// UTF-8 null-terminated string.
    StringUtf8Nt,
    /// Wide-character null-terminated string (UTF-16LE).
    StringWcharNt,
}

impl StringParseType {
    /// Returns `true` if this string type uses a 16-bit length prefix (ST format).
    pub fn is_st_format(&self) -> bool {
        matches!(self, StringParseType::StringSt | StringParseType::StringUtf8St)
    }

    /// Returns `true` if this string type is null-terminated (NT format).
    pub fn is_nt_format(&self) -> bool {
        matches!(
            self,
            StringParseType::StringNt
                | StringParseType::StringUtf8Nt
                | StringParseType::StringWcharNt
        )
    }

    /// Returns `true` if this string type is explicitly UTF-8 encoded.
    pub fn is_utf8(&self) -> bool {
        matches!(
            self,
            StringParseType::StringUtf8St | StringParseType::StringUtf8Nt
        )
    }

    /// Returns `true` if this string type uses wide characters (UTF-16LE).
    pub fn is_wchar(&self) -> bool {
        matches!(self, StringParseType::StringWcharNt)
    }
}

impl std::fmt::Display for StringParseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StringParseType::StringSt => write!(f, "StringSt"),
            StringParseType::StringNt => write!(f, "StringNt"),
            StringParseType::StringUtf8St => write!(f, "StringUtf8St"),
            StringParseType::StringUtf8Nt => write!(f, "StringUtf8Nt"),
            StringParseType::StringWcharNt => write!(f, "StringWcharNt"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_st_format() {
        assert!(StringParseType::StringSt.is_st_format());
        assert!(StringParseType::StringUtf8St.is_st_format());
        assert!(!StringParseType::StringNt.is_st_format());
        assert!(!StringParseType::StringUtf8Nt.is_st_format());
        assert!(!StringParseType::StringWcharNt.is_st_format());
    }

    #[test]
    fn test_nt_format() {
        assert!(StringParseType::StringNt.is_nt_format());
        assert!(StringParseType::StringUtf8Nt.is_nt_format());
        assert!(StringParseType::StringWcharNt.is_nt_format());
        assert!(!StringParseType::StringSt.is_nt_format());
        assert!(!StringParseType::StringUtf8St.is_nt_format());
    }

    #[test]
    fn test_utf8() {
        assert!(StringParseType::StringUtf8St.is_utf8());
        assert!(StringParseType::StringUtf8Nt.is_utf8());
        assert!(!StringParseType::StringSt.is_utf8());
        assert!(!StringParseType::StringNt.is_utf8());
    }

    #[test]
    fn test_wchar() {
        assert!(StringParseType::StringWcharNt.is_wchar());
        assert!(!StringParseType::StringSt.is_wchar());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", StringParseType::StringSt), "StringSt");
        assert_eq!(format!("{}", StringParseType::StringUtf8Nt), "StringUtf8Nt");
    }
}
