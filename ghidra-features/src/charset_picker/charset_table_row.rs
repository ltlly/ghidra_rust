//! Charset table row.
//!
//! Ported from `CharsetTableRow.java` -- a record pairing a
//! [`CharsetDisplayInfo`] with a precomputed scripts display string.

use super::CharsetDisplayInfo;

/// A single row in the charset picker table.
///
/// Ported from the Java `record CharsetTableRow(CharsetInfo csi, String scripts)`.
/// Each row holds a reference to charset metadata plus a precomputed
/// comma-separated string of Unicode script names for display.
#[derive(Debug, Clone)]
pub struct CharsetTableRow {
    /// Charset display information.
    pub info: CharsetDisplayInfo,
    /// Comma-separated list of Unicode scripts this charset can represent.
    pub scripts: String,
}

impl CharsetTableRow {
    /// Create a new table row from charset display info.
    ///
    /// The `scripts` field is automatically computed from the info's scripts list.
    pub fn new(info: CharsetDisplayInfo) -> Self {
        let scripts = info.scripts_string();
        Self { info, scripts }
    }

    /// Create a new table row with an explicit scripts string.
    pub fn with_scripts(info: CharsetDisplayInfo, scripts: impl Into<String>) -> Self {
        Self {
            info,
            scripts: scripts.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::UnicodeScript;

    #[test]
    fn test_row_new() {
        let info = CharsetDisplayInfo::with_scripts(
            "UTF-8",
            "Unicode 8-bit",
            false,
            1,
            6,
            1,
            vec![UnicodeScript::Latin, UnicodeScript::Han],
        );
        let row = CharsetTableRow::new(info);
        assert_eq!(row.info.name(), "UTF-8");
        assert_eq!(row.scripts, "LATIN, HAN");
    }

    #[test]
    fn test_row_with_scripts() {
        let info = CharsetDisplayInfo::new("ASCII", "US ASCII", true, 1, 1, 1);
        let row = CharsetTableRow::with_scripts(info, "LATIN");
        assert_eq!(row.scripts, "LATIN");
    }

    #[test]
    fn test_row_empty_scripts() {
        let info = CharsetDisplayInfo::new("X", "desc", false, 1, 1, 1);
        let row = CharsetTableRow::new(info);
        assert_eq!(row.scripts, "");
    }

    #[test]
    fn test_row_clone() {
        let info = CharsetDisplayInfo::new("UTF-8", "desc", false, 1, 6, 1);
        let row = CharsetTableRow::new(info);
        let cloned = row.clone();
        assert_eq!(cloned.info.name(), "UTF-8");
    }
}
