//! Decompiler action types.
//!
//! Ports Ghidra's decompiler action classes:
//! `DecompilerActionContext`, `ActionCategory`, `ActionMetadata`,
//! `DecompilerCursorPosition`, `DecompilerSearchLocation`, `DecompilerSearchResults`,
//! `DecompilerSearcher`, `ConstantFormat`, `EquateEntry`,
//! `HighlightDefinedUse`, `SliceHighlightColorProvider`,
//! `PCodeCfgGraphType`, `PCodeDfgDisplayOptions`, `PCodeDfgGraphType`.

use serde::{Deserialize, Serialize};

/// Category of decompiler action.
///
/// Port of Ghidra's `ghidra.app.plugin.core.decompile.DecompilerActionContext` action categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionCategory {
    /// Edit actions (rename, retype, etc.).
    Edit,
    /// Navigation actions (go to, back, forward).
    Navigation,
    /// Selection actions (highlight, find references).
    Selection,
    /// Display actions (format, convert).
    Display,
    /// Analysis actions (slice, DFG, CFG).
    Analysis,
    /// Clipboard actions (copy, paste).
    Clipboard,
}

/// Metadata for a decompiler action.
///
/// Port of Ghidra's decompiler action metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionMetadata {
    /// The action name.
    pub name: String,
    /// The action description.
    pub description: String,
    /// The action category.
    pub category: ActionCategory,
    /// Keyboard shortcut (if any).
    pub shortcut: Option<String>,
    /// Whether the action is enabled by default.
    pub enabled_by_default: bool,
}

impl ActionMetadata {
    /// Create new action metadata.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        category: ActionCategory,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            category,
            shortcut: None,
            enabled_by_default: true,
        }
    }

    /// Set the keyboard shortcut.
    pub fn with_shortcut(mut self, shortcut: impl Into<String>) -> Self {
        self.shortcut = Some(shortcut.into());
        self
    }
}

/// Position of the cursor in the decompiler panel.
///
/// Port of Ghidra's `ghidra.app.plugin.core.decompile.DecompilerCursorPosition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerCursorPosition {
    /// Line number in the decompiled output.
    pub line: usize,
    /// Token index within the line.
    pub token_index: usize,
    /// Character offset within the token text.
    pub char_offset: usize,
    /// The token ID (arena-based).
    pub token_id: u32,
}

impl DecompilerCursorPosition {
    /// Create a new cursor position.
    pub fn new(line: usize, token_index: usize, char_offset: usize, token_id: u32) -> Self {
        Self {
            line,
            token_index,
            char_offset,
            token_id,
        }
    }

    /// Create a position at the start of the document.
    pub fn start() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

impl Default for DecompilerCursorPosition {
    fn default() -> Self {
        Self::start()
    }
}

/// Location for a decompiler search result.
///
/// Port of Ghidra's `ghidra.app.plugin.core.decompile.DecompilerSearchLocation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerSearchLocation {
    /// Line number.
    pub line: usize,
    /// Start character offset.
    pub start_offset: usize,
    /// End character offset.
    pub end_offset: usize,
    /// The matching text.
    pub text: String,
}

impl DecompilerSearchLocation {
    /// Create a new search location.
    pub fn new(line: usize, start_offset: usize, end_offset: usize, text: impl Into<String>) -> Self {
        Self {
            line,
            start_offset,
            end_offset,
            text: text.into(),
        }
    }
}

/// Results from a decompiler search operation.
///
/// Port of Ghidra's `ghidra.app.plugin.core.decompile.DecompilerSearchResults`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecompilerSearchResults {
    /// Found locations.
    pub locations: Vec<DecompilerSearchLocation>,
    /// The search query.
    pub query: String,
}

impl DecompilerSearchResults {
    /// Create empty search results for a query.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            locations: Vec::new(),
            query: query.into(),
        }
    }

    /// Add a result location.
    pub fn add_location(&mut self, location: DecompilerSearchLocation) {
        self.locations.push(location);
    }

    /// Number of results.
    pub fn count(&self) -> usize {
        self.locations.len()
    }

    /// Whether results are empty.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }
}

/// Searcher for the decompiler text.
///
/// Port of Ghidra's `ghidra.app.plugin.core.decompile.DecompilerSearcher`.
#[derive(Debug, Clone)]
pub struct DecompilerSearcher {
    /// The search pattern.
    pub pattern: String,
    /// Whether the search is case-sensitive.
    pub case_sensitive: bool,
    /// Whether the pattern is a regex.
    pub is_regex: bool,
}

impl DecompilerSearcher {
    /// Create a new searcher.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            case_sensitive: false,
            is_regex: false,
        }
    }

    /// Set case sensitivity.
    pub fn case_sensitive(mut self, case_sensitive: bool) -> Self {
        self.case_sensitive = case_sensitive;
        self
    }

    /// Set regex mode.
    pub fn regex(mut self, is_regex: bool) -> Self {
        self.is_regex = is_regex;
        self
    }

    /// Search a line of text for matches.
    pub fn search_line(&self, line: &str) -> Vec<(usize, usize)> {
        let mut results = Vec::new();
        let (haystack, needle) = if self.case_sensitive {
            (line.to_string(), self.pattern.clone())
        } else {
            (line.to_lowercase(), self.pattern.to_lowercase())
        };

        let mut start = 0;
        while let Some(pos) = haystack[start..].find(&needle) {
            let actual_pos = start + pos;
            results.push((actual_pos, actual_pos + self.pattern.len()));
            start = actual_pos + 1;
        }
        results
    }
}

/// Format for displaying integer constants.
///
/// Port of Ghidra's `ConstantFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstantFormat {
    /// Decimal format.
    Decimal,
    /// Hexadecimal format (0x prefix).
    Hex,
    /// Octal format (0 prefix).
    Octal,
    /// Binary format (0b prefix).
    Binary,
    /// Character format ('x').
    Char,
    /// Floating point format.
    Float,
    /// Double precision.
    Double,
}

impl ConstantFormat {
    /// Format a value according to this format.
    pub fn format(&self, value: i64) -> String {
        match self {
            ConstantFormat::Decimal => format!("{}", value),
            ConstantFormat::Hex => format!("0x{:x}", value),
            ConstantFormat::Octal => format!("0{:o}", value),
            ConstantFormat::Binary => {
                format!("0b{:b}", value)
            }
            ConstantFormat::Char => {
                if (0x20..=0x7e).contains(&value) {
                    format!("'{}'", value as u8 as char)
                } else {
                    format!("'\\x{:02x}'", value & 0xff)
                }
            }
            ConstantFormat::Float => format!("{}", value as f32),
            ConstantFormat::Double => format!("{}", value as f64),
        }
    }
}

/// An equate entry for constant replacement.
///
/// Port of Ghidra's `EquateEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquateEntry {
    /// The equate name.
    pub name: String,
    /// The constant value it represents.
    pub value: i64,
}

impl EquateEntry {
    /// Create a new equate entry.
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Highlight defined-use action context.
///
/// Port of Ghidra's `HighlightDefinedUse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighlightDefinedUse {
    /// The token ID of the definition.
    pub definition_token_id: u32,
    /// The token IDs of all uses.
    pub use_token_ids: Vec<u32>,
}

impl HighlightDefinedUse {
    /// Create a new highlight defined-use.
    pub fn new(definition_token_id: u32) -> Self {
        Self {
            definition_token_id,
            use_token_ids: Vec::new(),
        }
    }

    /// Add a use token.
    pub fn add_use(&mut self, token_id: u32) {
        self.use_token_ids.push(token_id);
    }
}

/// Color provider for slice highlighting.
///
/// Port of Ghidra's `SliceHighlightColorProvider`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceHighlightColorProvider {
    /// Primary color (RGB).
    pub primary_color: [u8; 3],
    /// Secondary color (RGB).
    pub secondary_color: [u8; 3],
    /// Opacity (0.0..=1.0).
    pub opacity: f32,
}

impl SliceHighlightColorProvider {
    /// Create a new color provider.
    pub fn new(primary: [u8; 3], secondary: [u8; 3]) -> Self {
        Self {
            primary_color: primary,
            secondary_color: secondary,
            opacity: 0.3,
        }
    }
}

impl Default for SliceHighlightColorProvider {
    fn default() -> Self {
        Self::new([0, 120, 255], [255, 120, 0])
    }
}

/// Graph type for P-Code control flow graphs.
///
/// Port of Ghidra's `PCodeCfgGraphType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PCodeCfgGraphType {
    /// Basic block CFG.
    BasicBlock,
    /// Instruction-level CFG.
    Instruction,
}

/// Display options for P-Code data flow graphs.
///
/// Port of Ghidra's `PCodeDfgDisplayOptions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PCodeDfgDisplayOptions {
    /// Whether to show variable nodes.
    pub show_variables: bool,
    /// Whether to show operation nodes.
    pub show_operations: bool,
    /// Whether to show constant nodes.
    pub show_constants: bool,
    /// Whether to collapse trivial operations.
    pub collapse_trivial: bool,
}

impl PCodeDfgDisplayOptions {
    /// Create default display options.
    pub fn new() -> Self {
        Self {
            show_variables: true,
            show_operations: true,
            show_constants: true,
            collapse_trivial: false,
        }
    }
}

impl Default for PCodeDfgDisplayOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Graph type for P-Code data flow graphs.
///
/// Port of Ghidra's `PCodeDfgGraphType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PCodeDfgGraphType {
    /// Full DFG.
    Full,
    /// Varnode DFG (variables only).
    Varnode,
    /// Combined CFG + DFG.
    Combined,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_metadata_creation() {
        let meta = ActionMetadata::new("Rename", "Rename a variable", ActionCategory::Edit)
            .with_shortcut("Ctrl+R");
        assert_eq!(meta.name, "Rename");
        assert_eq!(meta.category, ActionCategory::Edit);
        assert_eq!(meta.shortcut.as_deref(), Some("Ctrl+R"));
    }

    #[test]
    fn cursor_position() {
        let pos = DecompilerCursorPosition::new(10, 5, 3, 42);
        assert_eq!(pos.line, 10);
        assert_eq!(pos.token_id, 42);

        let start = DecompilerCursorPosition::start();
        assert_eq!(start.line, 0);
    }

    #[test]
    fn search_results() {
        let mut results = DecompilerSearchResults::new("main");
        results.add_location(DecompilerSearchLocation::new(5, 10, 14, "main"));
        results.add_location(DecompilerSearchLocation::new(12, 0, 4, "main"));
        assert_eq!(results.count(), 2);
        assert!(!results.is_empty());
    }

    #[test]
    fn searcher_basic() {
        let searcher = DecompilerSearcher::new("func");
        let results = searcher.search_line("the func() calls func again");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], (4, 8));
    }

    #[test]
    fn searcher_case_insensitive() {
        let searcher = DecompilerSearcher::new("FUNC");
        let results = searcher.search_line("func is not FUNC");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn constant_format_variants() {
        assert_eq!(ConstantFormat::Decimal.format(42), "42");
        assert_eq!(ConstantFormat::Hex.format(255), "0xff");
        assert_eq!(ConstantFormat::Octal.format(8), "010");
        assert_eq!(ConstantFormat::Char.format(65), "'A'");
    }

    #[test]
    fn equate_entry() {
        let entry = EquateEntry::new("NULL", 0);
        assert_eq!(entry.name, "NULL");
        assert_eq!(entry.value, 0);
    }

    #[test]
    fn highlight_defined_use() {
        let mut hdu = HighlightDefinedUse::new(1);
        hdu.add_use(5);
        hdu.add_use(10);
        assert_eq!(hdu.use_token_ids, vec![5, 10]);
    }

    #[test]
    fn slice_highlight_color_provider() {
        let provider = SliceHighlightColorProvider::default();
        assert_eq!(provider.primary_color, [0, 120, 255]);
        assert_eq!(provider.opacity, 0.3);
    }

    #[test]
    fn pcode_display_options() {
        let opts = PCodeDfgDisplayOptions::new();
        assert!(opts.show_variables);
        assert!(opts.show_operations);
        assert!(!opts.collapse_trivial);
    }

    #[test]
    fn action_category_variants() {
        assert_ne!(ActionCategory::Edit, ActionCategory::Navigation);
        assert_ne!(ActionCategory::Analysis, ActionCategory::Clipboard);
    }
}
