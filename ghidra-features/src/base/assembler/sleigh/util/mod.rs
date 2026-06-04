//! Utilities for the SLEIGH assembler.
//!
//! Corresponds to Java's `ghidra.app.plugin.assembler.sleigh.util`.

use std::fmt;

// ---------------------------------------------------------------------------
// TableEntry / TableEntryKey
// ---------------------------------------------------------------------------

/// An entry in the SLEIGH instruction table.
///
/// Corresponds to Java's `TableEntry`.
#[derive(Debug, Clone)]
pub struct TableEntry {
    /// The table name.
    pub table_name: String,
    /// The constructor index.
    pub constructor_index: usize,
    /// The constructor display name.
    pub display: String,
}

impl TableEntry {
    /// Create a new table entry.
    pub fn new(
        table_name: impl Into<String>,
        constructor_index: usize,
        display: impl Into<String>,
    ) -> Self {
        Self {
            table_name: table_name.into(),
            constructor_index,
            display: display.into(),
        }
    }
}

impl fmt::Display for TableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}]: {}",
            self.table_name, self.constructor_index, self.display
        )
    }
}

/// A key for looking up table entries.
///
/// Corresponds to Java's `TableEntryKey`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableEntryKey {
    /// The table name.
    pub table_name: String,
    /// The constructor index.
    pub constructor_index: usize,
}

impl TableEntryKey {
    /// Create a new key.
    pub fn new(table_name: impl Into<String>, constructor_index: usize) -> Self {
        Self {
            table_name: table_name.into(),
            constructor_index,
        }
    }
}

impl fmt::Display for TableEntryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", self.table_name, self.constructor_index)
    }
}

// ---------------------------------------------------------------------------
// AsmUtil
// ---------------------------------------------------------------------------

/// General-purpose utilities for the assembler.
///
/// Corresponds to Java's `AsmUtil`.
pub struct AsmUtil;

impl AsmUtil {
    /// Convert a hex string to bytes.
    pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
        let hex = hex.trim().trim_start_matches("0x").trim_start_matches("0X");
        if hex.len() % 2 != 0 {
            return None;
        }
        let mut bytes = Vec::new();
        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16).ok()?;
            bytes.push(byte);
        }
        Some(bytes)
    }

    /// Convert bytes to a hex string.
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    /// Convert a number to a hex string with a given width.
    pub fn to_hex_string(value: u64, width: usize) -> String {
        format!("{:0width$x}", value, width = width)
    }

    /// Parse a register name and return (name, optional bit range).
    pub fn parse_register_ref(text: &str) -> (&str, Option<(u32, u32)>) {
        if let Some(paren_pos) = text.find('(') {
            let name = &text[..paren_pos];
            let range_str = &text[paren_pos + 1..].trim_end_matches(')');
            let parts: Vec<&str> = range_str.split(',').collect();
            if parts.len() == 2 {
                if let (Ok(lsb), Ok(msb)) = (
                    parts[0].trim().parse::<u32>(),
                    parts[1].trim().parse::<u32>(),
                ) {
                    return (name, Some((lsb, msb)));
                }
            }
            (name, None)
        } else {
            (text, None)
        }
    }

    /// Escape special characters in assembly text.
    pub fn escape_assembly(text: &str) -> String {
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
    }

    /// Unescape special characters in assembly text.
    pub fn unescape_assembly(text: &str) -> String {
        let mut result = String::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('t') => result.push('\t'),
                    Some('"') => result.push('"'),
                    Some('\\') => result.push('\\'),
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(ch);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_conversion() {
        let bytes = AsmUtil::hex_to_bytes("DEADBEEF").unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let hex = AsmUtil::bytes_to_hex(&[0xCA, 0xFE]);
        assert_eq!(hex, "cafe");
    }

    #[test]
    fn test_hex_conversion_with_prefix() {
        let bytes = AsmUtil::hex_to_bytes("0xFF00").unwrap();
        assert_eq!(bytes, vec![0xFF, 0x00]);
    }

    #[test]
    fn test_to_hex_string() {
        assert_eq!(AsmUtil::to_hex_string(255, 2), "ff");
        assert_eq!(AsmUtil::to_hex_string(0xDEAD, 4), "dead");
        assert_eq!(AsmUtil::to_hex_string(0, 8), "00000000");
    }

    #[test]
    fn test_parse_register_ref() {
        let (name, range) = AsmUtil::parse_register_ref("R0");
        assert_eq!(name, "R0");
        assert_eq!(range, None);

        let (name, range) = AsmUtil::parse_register_ref("R0(0,7)");
        assert_eq!(name, "R0");
        assert_eq!(range, Some((0, 7)));
    }

    #[test]
    fn test_escape_unescape() {
        let original = "line1\nline2\t\"quoted\"";
        let escaped = AsmUtil::escape_assembly(original);
        assert_eq!(escaped, "line1\\nline2\\t\\\"quoted\\\"");
        let unescaped = AsmUtil::unescape_assembly(&escaped);
        assert_eq!(unescaped, original);
    }

    #[test]
    fn test_table_entry() {
        let entry = TableEntry::new("instruction", 0, "MOV reg, reg");
        assert_eq!(entry.table_name, "instruction");
        assert_eq!(entry.constructor_index, 0);
        assert_eq!(format!("{}", entry), "instruction[0]: MOV reg, reg");
    }

    #[test]
    fn test_table_entry_key() {
        let key1 = TableEntryKey::new("instruction", 0);
        let key2 = TableEntryKey::new("instruction", 0);
        assert_eq!(key1, key2);

        let key3 = TableEntryKey::new("instruction", 1);
        assert_ne!(key1, key3);
    }
}
