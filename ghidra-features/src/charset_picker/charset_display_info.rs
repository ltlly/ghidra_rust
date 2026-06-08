//! Charset display information.
//!
//! Ported from `ghidra.util.charset.CharsetInfo` -- provides metadata about
//! a character encoding: name, description, fixed-length flag, bytes-per-char
//! range, alignment, and supported Unicode scripts.

use super::UnicodeScript;

/// Display information for a charset.
///
/// Ported from `ghidra.util.charset.CharsetInfo`. Each instance describes a
/// single character encoding with its properties and the Unicode scripts it
/// can represent.
#[derive(Debug, Clone)]
pub struct CharsetDisplayInfo {
    /// Charset name (e.g. "UTF-8", "ISO-8859-1").
    pub name: String,
    /// Human-readable description.
    pub comment: String,
    /// Whether every character uses exactly the same number of bytes.
    pub fixed_length: bool,
    /// Minimum bytes per character (0 = unknown).
    pub min_bytes_per_char: u32,
    /// Maximum bytes per char (0 = unknown).
    pub max_bytes_per_char: u32,
    /// Byte alignment for starting a character.
    pub alignment: u32,
    /// Unicode scripts this charset can represent.
    pub scripts: Vec<UnicodeScript>,
}

impl CharsetDisplayInfo {
    /// Create a new charset display info.
    pub fn new(
        name: impl Into<String>,
        comment: impl Into<String>,
        fixed_length: bool,
        min_bytes: u32,
        max_bytes: u32,
        alignment: u32,
    ) -> Self {
        Self {
            name: name.into(),
            comment: comment.into(),
            fixed_length,
            min_bytes_per_char: min_bytes,
            max_bytes_per_char: max_bytes,
            alignment,
            scripts: Vec::new(),
        }
    }

    /// Create a new charset display info with scripts.
    pub fn with_scripts(
        name: impl Into<String>,
        comment: impl Into<String>,
        fixed_length: bool,
        min_bytes: u32,
        max_bytes: u32,
        alignment: u32,
        scripts: Vec<UnicodeScript>,
    ) -> Self {
        Self {
            name: name.into(),
            comment: comment.into(),
            fixed_length,
            min_bytes_per_char: min_bytes,
            max_bytes_per_char: max_bytes,
            alignment,
            scripts,
        }
    }

    /// Return the charset name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the charset description.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Whether this charset uses fixed-length characters.
    pub fn has_fixed_length_chars(&self) -> bool {
        self.fixed_length
    }

    /// Minimum bytes per character (0 = unknown).
    pub fn min_bytes_per_char(&self) -> u32 {
        self.min_bytes_per_char
    }

    /// Maximum bytes per character (0 = unknown).
    pub fn max_bytes_per_char(&self) -> u32 {
        self.max_bytes_per_char
    }

    /// Byte alignment.
    pub fn alignment(&self) -> u32 {
        self.alignment
    }

    /// Unicode scripts this charset can represent.
    pub fn scripts(&self) -> &[UnicodeScript] {
        &self.scripts
    }

    /// Return the min/max bytes display string (e.g. "1 / 6").
    pub fn min_max_display(&self) -> String {
        let min = if self.min_bytes_per_char > 0 {
            self.min_bytes_per_char.to_string()
        } else {
            "unknown".to_string()
        };
        let max = if self.max_bytes_per_char > 0 {
            self.max_bytes_per_char.to_string()
        } else {
            "unknown".to_string()
        };
        format!("{} / {}", min, max)
    }

    /// Return a comma-separated string of script names.
    pub fn scripts_string(&self) -> String {
        self.scripts
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_basic() {
        let info = CharsetDisplayInfo::new("UTF-8", "Unicode 8-bit", false, 1, 6, 1);
        assert_eq!(info.name(), "UTF-8");
        assert_eq!(info.comment(), "Unicode 8-bit");
        assert!(!info.has_fixed_length_chars());
        assert_eq!(info.min_bytes_per_char(), 1);
        assert_eq!(info.max_bytes_per_char(), 6);
        assert_eq!(info.alignment(), 1);
        assert!(info.scripts().is_empty());
    }

    #[test]
    fn test_with_scripts() {
        let info = CharsetDisplayInfo::with_scripts(
            "ISO-8859-1",
            "Latin-1",
            true,
            1,
            1,
            1,
            vec![UnicodeScript::Latin],
        );
        assert_eq!(info.scripts().len(), 1);
        assert_eq!(info.scripts()[0], UnicodeScript::Latin);
    }

    #[test]
    fn test_min_max_display() {
        let info = CharsetDisplayInfo::new("UTF-8", "", false, 1, 6, 1);
        assert_eq!(info.min_max_display(), "1 / 6");

        let info_unknown = CharsetDisplayInfo::new("X", "", false, 0, 0, 1);
        assert_eq!(info_unknown.min_max_display(), "unknown / unknown");
    }

    #[test]
    fn test_scripts_string() {
        let info = CharsetDisplayInfo::with_scripts(
            "UTF-8",
            "",
            false,
            1,
            6,
            1,
            vec![UnicodeScript::Latin, UnicodeScript::Han, UnicodeScript::Cyrillic],
        );
        assert_eq!(info.scripts_string(), "LATIN, HAN, CYRILLIC");
    }

    #[test]
    fn test_scripts_string_empty() {
        let info = CharsetDisplayInfo::new("X", "", false, 1, 1, 1);
        assert_eq!(info.scripts_string(), "");
    }

    #[test]
    fn test_clone() {
        let info = CharsetDisplayInfo::new("UTF-8", "desc", false, 1, 6, 1);
        let cloned = info.clone();
        assert_eq!(cloned.name(), "UTF-8");
    }
}
