//! Charset picker UI framework.
//!
//! Ported from `ghidra.util.charset.picker` -- lets users choose a charset
//! from a filterable table with detailed preview information.
//!
//! # Architecture
//!
//! - [`CharsetTableRow`]: A single row in the charset table.
//! - [`CharsetTableModel`]: Table model that enumerates all known charsets.
//! - [`CharsetPickerPanel`]: Panel displaying a filterable charset table with
//!   a details sub-panel.
//! - [`CharsetPickerDialog`]: Modal dialog wrapping the panel.
//! - [`CharsetInfoPanel`]: Detail panel showing charset properties and script
//!   examples.

use std::fmt;

// ---------------------------------------------------------------------------
// CharsetTableRow
// ---------------------------------------------------------------------------

/// A single row in the charset picker table.
///
/// Ported from `CharsetTableRow.java` -- a record pairing a [`CharsetDisplayInfo`]
/// with a precomputed scripts string.
#[derive(Debug, Clone)]
pub struct CharsetTableRow {
    /// Charset display information.
    pub info: CharsetDisplayInfo,
    /// Comma-separated list of Unicode scripts this charset can represent.
    pub scripts: String,
}

// ---------------------------------------------------------------------------
// CharsetDisplayInfo
// ---------------------------------------------------------------------------

/// Display information for a charset.
///
/// Ported from `ghidra.util.charset.CharsetInfo`.
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
}

// ---------------------------------------------------------------------------
// UnicodeScript
// ---------------------------------------------------------------------------

/// Unicode script identifiers.
///
/// Mirrors `java.lang.Character.UnicodeScript`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnicodeScript {
    /// Latin script.
    Latin,
    /// Greek script.
    Greek,
    /// Cyrillic script.
    Cyrillic,
    /// Armenian script.
    Armenian,
    /// Hebrew script.
    Hebrew,
    /// Arabic script.
    Arabic,
    /// Devanagari script.
    Devanagari,
    /// Bengali script.
    Bengali,
    /// Thai script.
    Thai,
    /// Han (CJK Unified Ideographs) script.
    Han,
    /// Hiragana script.
    Hiragana,
    /// Katakana script.
    Katakana,
    /// Hangul script.
    Hangul,
    /// CJK ideographs.
    CJK,
    /// Common script (shared across many writing systems).
    Common,
    /// Inherited script.
    Inherited,
    /// Unknown or unrecognized script.
    Unknown,
}

impl fmt::Display for UnicodeScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Latin => "LATIN",
            Self::Greek => "GREEK",
            Self::Cyrillic => "CYRILLIC",
            Self::Armenian => "ARMENIAN",
            Self::Hebrew => "HEBREW",
            Self::Arabic => "ARABIC",
            Self::Devanagari => "DEVANAGARI",
            Self::Bengali => "BENGALI",
            Self::Thai => "THAI",
            Self::Han => "HAN",
            Self::Hiragana => "HIRAGANA",
            Self::Katakana => "KATAKANA",
            Self::Hangul => "HANGUL",
            Self::CJK => "CJK",
            Self::Common => "COMMON",
            Self::Inherited => "INHERITED",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{}", name)
    }
}

// ---------------------------------------------------------------------------
// CharsetTableModel
// ---------------------------------------------------------------------------

/// Column indices for the charset table.
pub mod columns {
    /// Charset name.
    pub const NAME: usize = 0;
    /// Charset description.
    pub const COMMENT: usize = 1;
    /// Fixed-length flag.
    pub const FIXED_LEN: usize = 2;
    /// Minimum bytes per character.
    pub const MIN_BPC: usize = 3;
    /// Maximum bytes per character.
    pub const MAX_BPC: usize = 4;
    /// Unicode scripts.
    pub const SCRIPTS: usize = 5;

    /// Column names.
    pub const COL_NAMES: &[&str] = &[
        "Name",
        "Description",
        "Fixed Length",
        "Min BPC",
        "Max BPC",
        "Scripts",
    ];
}

/// Table model for the charset picker.
///
/// Ported from `CharsetTableModel.java`. Manages a list of
/// [`CharsetTableRow`] entries and supports sorting and filtering.
#[derive(Debug)]
pub struct CharsetTableModel {
    /// All charset rows.
    rows: Vec<CharsetTableRow>,
    /// Active text filter (empty = show all).
    filter: String,
}

impl CharsetTableModel {
    /// Create a new model populated from the given charset list.
    pub fn new(charsets: Vec<CharsetDisplayInfo>) -> Self {
        let rows = charsets
            .into_iter()
            .map(|info| {
                let scripts = Self::scripts_string(&info.scripts);
                CharsetTableRow { info, scripts }
            })
            .collect();
        Self {
            rows,
            filter: String::new(),
        }
    }

    /// Build a comma-separated scripts string.
    fn scripts_string(scripts: &[UnicodeScript]) -> String {
        scripts
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Find the index of a charset by name.
    pub fn find_charset(&self, name: &str) -> Option<usize> {
        self.rows.iter().position(|r| r.info.name == name)
    }

    /// Return the number of visible (filtered) rows.
    pub fn row_count(&self) -> usize {
        self.filtered_rows().count()
    }

    /// Return the number of columns.
    pub fn column_count(&self) -> usize {
        columns::COL_NAMES.len()
    }

    /// Return the column name for the given index.
    pub fn column_name(&self, col: usize) -> &str {
        columns::COL_NAMES.get(col).copied().unwrap_or("<<unknown>>")
    }

    /// Get the cell value as a display string.
    pub fn get_value(&self, row: usize, col: usize) -> Option<String> {
        let filtered: Vec<_> = self.filtered_rows().collect();
        let r = filtered.get(row)?;
        match col {
            columns::NAME => Some(r.info.name.clone()),
            columns::COMMENT => Some(r.info.comment.clone()),
            columns::FIXED_LEN => Some(if r.info.fixed_length {
                "true".to_string()
            } else {
                "false".to_string()
            }),
            columns::MIN_BPC => {
                Some(if r.info.min_bytes_per_char > 0 {
                    r.info.min_bytes_per_char.to_string()
                } else {
                    "unknown".to_string()
                })
            }
            columns::MAX_BPC => {
                Some(if r.info.max_bytes_per_char > 0 {
                    r.info.max_bytes_per_char.to_string()
                } else {
                    "unknown".to_string()
                })
            }
            columns::SCRIPTS => Some(r.scripts.clone()),
            _ => None,
        }
    }

    /// Set the filter text (case-insensitive substring match on name and comment).
    pub fn set_filter(&mut self, filter: &str) {
        self.filter = filter.to_lowercase();
    }

    /// Return the current filter.
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// Return an iterator over the filtered rows.
    fn filtered_rows(&self) -> impl Iterator<Item = &CharsetTableRow> {
        let filter = self.filter.clone();
        self.rows.iter().filter(move |row| {
            if filter.is_empty() {
                return true;
            }
            row.info.name.to_lowercase().contains(&filter)
                || row.info.comment.to_lowercase().contains(&filter)
                || row.scripts.to_lowercase().contains(&filter)
        })
    }

    /// Return all rows (unfiltered).
    pub fn all_rows(&self) -> &[CharsetTableRow] {
        &self.rows
    }

    /// Sort by a column.
    pub fn sort_by_column(&mut self, col: usize, ascending: bool) {
        self.rows.sort_by(|a, b| {
            let cmp = match col {
                columns::NAME => a.info.name.cmp(&b.info.name),
                columns::COMMENT => a.info.comment.cmp(&b.info.comment),
                columns::FIXED_LEN => a.info.fixed_length.cmp(&b.info.fixed_length),
                columns::MIN_BPC => {
                    a.info.min_bytes_per_char.cmp(&b.info.min_bytes_per_char)
                }
                columns::MAX_BPC => {
                    a.info.max_bytes_per_char.cmp(&b.info.max_bytes_per_char)
                }
                columns::SCRIPTS => a.scripts.cmp(&b.scripts),
                _ => std::cmp::Ordering::Equal,
            };
            if ascending {
                cmp
            } else {
                cmp.reverse()
            }
        });
    }
}

// ---------------------------------------------------------------------------
// CharsetPickerState
// ---------------------------------------------------------------------------

/// Model for the charset picker panel / dialog.
///
/// Ported from `CharsetPickerPanel.java` and `CharsetPickerDialog.java`.
/// This is the headless (no-GUI) Rust representation.
#[derive(Debug)]
pub struct CharsetPickerState {
    /// The table model.
    pub model: CharsetTableModel,
    /// Currently selected charset name (if any).
    selected: Option<String>,
}

impl CharsetPickerState {
    /// Create a new picker state with the given charsets.
    pub fn new(charsets: Vec<CharsetDisplayInfo>) -> Self {
        Self {
            model: CharsetTableModel::new(charsets),
            selected: None,
        }
    }

    /// Select a charset by name.
    pub fn set_selected(&mut self, name: &str) {
        if self.model.find_charset(name).is_some() {
            self.selected = Some(name.to_string());
        }
    }

    /// Get the selected charset name.
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Get the full display info for the selected charset.
    pub fn selected_info(&self) -> Option<&CharsetDisplayInfo> {
        let name = self.selected.as_ref()?;
        self.model
            .all_rows()
            .iter()
            .find(|r| r.info.name == *name)
            .map(|r| &r.info)
    }

    /// Get the min/max bytes string for a charset (for detail display).
    pub fn min_max_display(&self, info: &CharsetDisplayInfo) -> String {
        let min = if info.min_bytes_per_char > 0 {
            info.min_bytes_per_char.to_string()
        } else {
            "unknown".to_string()
        };
        let max = if info.max_bytes_per_char > 0 {
            info.max_bytes_per_char.to_string()
        } else {
            "unknown".to_string()
        };
        format!("{} / {}", min, max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_charsets() -> Vec<CharsetDisplayInfo> {
        vec![
            CharsetDisplayInfo::new("UTF-8", "Unicode Transformation Format 8-bit", false, 1, 6, 1),
            CharsetDisplayInfo::new(
                "ISO-8859-1",
                "Latin Alphabet No. 1",
                true,
                1,
                1,
                1,
            ),
            CharsetDisplayInfo::new(
                "UTF-16",
                "Unicode Transformation Format 16-bit",
                false,
                2,
                4,
                2,
            ),
            CharsetDisplayInfo::new(
                "US-ASCII",
                "American Standard Code",
                true,
                1,
                1,
                1,
            ),
        ]
    }

    #[test]
    fn test_table_model_creation() {
        let model = CharsetTableModel::new(sample_charsets());
        assert_eq!(model.row_count(), 4);
        assert_eq!(model.column_count(), 6);
    }

    #[test]
    fn test_column_names() {
        let model = CharsetTableModel::new(sample_charsets());
        assert_eq!(model.column_name(0), "Name");
        assert_eq!(model.column_name(1), "Description");
        assert_eq!(model.column_name(2), "Fixed Length");
        assert_eq!(model.column_name(3), "Min BPC");
        assert_eq!(model.column_name(4), "Max BPC");
        assert_eq!(model.column_name(5), "Scripts");
    }

    #[test]
    fn test_get_value() {
        let model = CharsetTableModel::new(sample_charsets());
        assert_eq!(model.get_value(0, 0), Some("UTF-8".to_string()));
        assert_eq!(
            model.get_value(0, 1),
            Some("Unicode Transformation Format 8-bit".to_string())
        );
        assert_eq!(model.get_value(0, 2), Some("false".to_string()));
        assert_eq!(model.get_value(0, 3), Some("1".to_string()));
        assert_eq!(model.get_value(0, 4), Some("6".to_string()));
    }

    #[test]
    fn test_find_charset() {
        let model = CharsetTableModel::new(sample_charsets());
        assert_eq!(model.find_charset("UTF-8"), Some(0));
        assert_eq!(model.find_charset("ISO-8859-1"), Some(1));
        assert_eq!(model.find_charset("NONEXISTENT"), None);
    }

    #[test]
    fn test_filter() {
        let mut model = CharsetTableModel::new(sample_charsets());
        assert_eq!(model.row_count(), 4);

        model.set_filter("utf");
        assert_eq!(model.row_count(), 2); // UTF-8, UTF-16

        model.set_filter("ascii");
        assert_eq!(model.row_count(), 1); // US-ASCII

        model.set_filter("");
        assert_eq!(model.row_count(), 4);
    }

    #[test]
    fn test_sort_by_column() {
        let mut model = CharsetTableModel::new(sample_charsets());

        // Sort by name ascending.
        model.sort_by_column(columns::NAME, true);
        assert_eq!(model.get_value(0, 0), Some("ISO-8859-1".to_string()));
        assert_eq!(model.get_value(3, 0), Some("UTF-8".to_string()));

        // Sort by name descending.
        model.sort_by_column(columns::NAME, false);
        assert_eq!(model.get_value(0, 0), Some("UTF-8".to_string()));

        // Sort by max BPC ascending.
        model.sort_by_column(columns::MAX_BPC, true);
        assert_eq!(model.get_value(0, 4), Some("1".to_string()));
    }

    #[test]
    fn test_picker_state_selection() {
        let mut picker = CharsetPickerState::new(sample_charsets());
        assert!(picker.selected().is_none());

        picker.set_selected("UTF-8");
        assert_eq!(picker.selected(), Some("UTF-8"));

        let info = picker.selected_info().unwrap();
        assert_eq!(info.name, "UTF-8");
        assert!(!info.fixed_length);
    }

    #[test]
    fn test_picker_state_invalid_selection() {
        let mut picker = CharsetPickerState::new(sample_charsets());
        picker.set_selected("NONEXISTENT");
        assert!(picker.selected().is_none());
    }

    #[test]
    fn test_min_max_display() {
        let mut picker = CharsetPickerState::new(sample_charsets());
        picker.set_selected("UTF-8");
        let info = picker.selected_info().unwrap();
        assert_eq!(picker.min_max_display(info), "1 / 6");
    }

    #[test]
    fn test_unicode_script_display() {
        assert_eq!(UnicodeScript::Latin.to_string(), "LATIN");
        assert_eq!(UnicodeScript::Han.to_string(), "HAN");
        assert_eq!(UnicodeScript::Unknown.to_string(), "UNKNOWN");
    }

    #[test]
    fn test_display_info_accessors() {
        let info = CharsetDisplayInfo::new("UTF-8", "desc", false, 1, 6, 1);
        assert_eq!(info.name(), "UTF-8");
        assert_eq!(info.comment(), "desc");
        assert!(!info.has_fixed_length_chars());
        assert_eq!(info.min_bytes_per_char(), 1);
        assert_eq!(info.max_bytes_per_char(), 6);
        assert_eq!(info.alignment(), 1);
        assert!(info.scripts().is_empty());
    }
}
