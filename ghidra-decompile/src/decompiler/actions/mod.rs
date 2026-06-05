//! Decompiler action types (UI actions, no Swing dependency).
//!
//! Port of Ghidra's `ghidra.app.plugin.core.decompile.actions` package.
//!
//! These are data structures that represent actions a user can perform in the
//! decompiler view. In the Rust port, we provide the action definitions and
//! metadata only (no Swing/AWT integration).

pub mod action_types;
pub mod convert_actions;
pub mod edit_actions;
pub mod extra_actions;

// New modules ported from Ghidra's decompiler actions package
pub mod decompiler_actions;
pub mod decompiler_actions_ext;

use ghidra_core::addr::Address;

use super::clang_node::{ClangNodeId, SyntaxType};
use super::component::TokenKey;

// ============================================================================
// Action categories
// ============================================================================

/// Categories for decompiler actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionCategory {
    /// Navigation actions (go to address, brace matching).
    Navigation,
    /// Editing actions (rename, retype, edit).
    Editing,
    /// Analysis actions (slice, find references).
    Analysis,
    /// Display actions (highlight, select, format).
    Display,
    /// Clipboard actions (copy, export).
    Clipboard,
    /// P-code actions (CFG, DFG).
    Pcode,
    /// Structure actions (create struct, commit).
    Structure,
}

// ============================================================================
// DecompilerCursorPosition
// ============================================================================

/// Represents a cursor position in the decompiler view.
#[derive(Debug, Clone, Default)]
pub struct DecompilerCursorPosition {
    /// The ClangNodeId at the cursor.
    pub node_id: Option<ClangNodeId>,
    /// The address at the cursor.
    pub address: Option<Address>,
    /// The line number.
    pub line: usize,
    /// The column number.
    pub column: usize,
    /// The token text.
    pub token_text: Option<String>,
    /// The syntax type of the token.
    pub syntax_type: Option<SyntaxType>,
}

impl DecompilerCursorPosition {
    /// Create a new cursor position.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the cursor is on a token.
    pub fn is_on_token(&self) -> bool {
        self.node_id.is_some()
    }
}

// ============================================================================
// DecompilerSearcher
// ============================================================================

/// Search capabilities within the decompiler output.
#[derive(Debug, Clone)]
pub struct DecompilerSearcher {
    /// The search query string.
    pub query: String,
    /// Whether to search case-sensitively.
    pub case_sensitive: bool,
    /// Whether to use regex.
    pub use_regex: bool,
    /// The current search position (line, column).
    pub position: (usize, usize),
    /// Search results.
    pub results: Vec<DecompilerSearchLocation>,
}

impl DecompilerSearcher {
    /// Create a new searcher.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            case_sensitive: true,
            use_regex: false,
            position: (0, 0),
            results: Vec::new(),
        }
    }

    /// Set case sensitivity.
    pub fn case_sensitive(mut self, case_sensitive: bool) -> Self {
        self.case_sensitive = case_sensitive;
        self
    }

    /// Set regex mode.
    pub fn regex(mut self, use_regex: bool) -> Self {
        self.use_regex = use_regex;
        self
    }
}

/// A search result location in the decompiler.
#[derive(Debug, Clone)]
pub struct DecompilerSearchLocation {
    /// The line number.
    pub line: usize,
    /// The column number.
    pub column: usize,
    /// The length of the match.
    pub length: usize,
    /// The matched text.
    pub text: String,
    /// The ClangNodeId of the matched token (if any).
    pub node_id: Option<ClangNodeId>,
}

impl DecompilerSearchLocation {
    /// Create a new search location.
    pub fn new(line: usize, column: usize, length: usize, text: String) -> Self {
        Self {
            line,
            column,
            length,
            text,
            node_id: None,
        }
    }
}

// ============================================================================
// DecompilerSearchResults
// ============================================================================

/// Collection of search results from a decompiler search.
#[derive(Debug, Clone, Default)]
pub struct DecompilerSearchResults {
    /// The locations of search results.
    pub locations: Vec<DecompilerSearchLocation>,
    /// The current result index (for navigation).
    pub current_index: usize,
}

impl DecompilerSearchResults {
    /// Create empty search results.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a search result.
    pub fn add(&mut self, location: DecompilerSearchLocation) {
        self.locations.push(location);
    }

    /// Get the total number of results.
    pub fn count(&self) -> usize {
        self.locations.len()
    }

    /// Move to the next result. Returns the location, or None.
    pub fn next(&mut self) -> Option<&DecompilerSearchLocation> {
        if self.locations.is_empty() {
            return None;
        }
        if self.current_index < self.locations.len() - 1 {
            self.current_index += 1;
        }
        self.locations.get(self.current_index)
    }

    /// Move to the previous result. Returns the location, or None.
    pub fn previous(&mut self) -> Option<&DecompilerSearchLocation> {
        if self.locations.is_empty() {
            return None;
        }
        if self.current_index > 0 {
            self.current_index -= 1;
        }
        self.locations.get(self.current_index)
    }

    /// Get the current result.
    pub fn current(&self) -> Option<&DecompilerSearchLocation> {
        self.locations.get(self.current_index)
    }
}

// ============================================================================
// SliceHighlightColorProvider
// ============================================================================

/// Provides colors for slice highlighting (backwards/forward slicing).
#[derive(Debug, Clone)]
pub struct SliceHighlightColorProvider {
    /// Color for backwards slice.
    pub backward_color: String,
    /// Color for forward slice.
    pub forward_color: String,
    /// Color for combined slice.
    pub combined_color: String,
}

impl Default for SliceHighlightColorProvider {
    fn default() -> Self {
        Self {
            backward_color: "#0000ff".to_string(),
            forward_color: "#008000".to_string(),
            combined_color: "#800080".to_string(),
        }
    }
}

impl SliceHighlightColorProvider {
    /// Create a new slice highlight color provider.
    pub fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// ConvertConstant actions
// ============================================================================

/// Format for displaying numeric constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConstantFormat {
    /// Hexadecimal (0x1234).
    Hex,
    /// Decimal (4660).
    Decimal,
    /// Octal (011064).
    Octal,
    /// Binary (0b0001001000110100).
    Binary,
    /// Character ('B').
    Char,
    /// Float (IEEE 754).
    Float,
    /// Double (IEEE 754 double).
    Double,
}

impl ConstantFormat {
    /// Display a value in this format.
    pub fn format_value(&self, value: u64, size: usize) -> String {
        match self {
            ConstantFormat::Hex => {
                if size <= 4 {
                    format!("0x{:08x}", value)
                } else {
                    format!("0x{:016x}", value)
                }
            }
            ConstantFormat::Decimal => format!("{}", value as i64),
            ConstantFormat::Octal => format!("0o{:o}", value),
            ConstantFormat::Binary => format!("0b{:b}", value),
            ConstantFormat::Char => {
                if value < 128 {
                    let c = value as u8 as char;
                    if c.is_ascii_graphic() || c == ' ' {
                        format!("'{}'", c)
                    } else {
                        format!("0x{:02x}", value)
                    }
                } else {
                    format!("0x{:02x}", value)
                }
            }
            ConstantFormat::Float => {
                let bits = value as u32;
                let f = f32::from_bits(bits);
                format!("{}", f)
            }
            ConstantFormat::Double => {
                let f = f64::from_bits(value);
                format!("{}", f)
            }
        }
    }
}

// ============================================================================
// EquateAction
// ============================================================================

/// Represents an equate (symbolic name for a constant) in the decompiler.
#[derive(Debug, Clone)]
pub struct EquateEntry {
    /// The numeric value.
    pub value: u64,
    /// The symbolic name.
    pub name: String,
    /// The ClangNodeId where the equate is applied.
    pub node_id: ClangNodeId,
}

impl EquateEntry {
    /// Create a new equate entry.
    pub fn new(value: u64, name: impl Into<String>, node_id: ClangNodeId) -> Self {
        Self {
            value,
            name: name.into(),
            node_id,
        }
    }
}

// ============================================================================
// HighlightUse
// ============================================================================

/// Action to highlight all uses of a variable or symbol.
#[derive(Debug, Clone)]
pub struct HighlightDefinedUse {
    /// The name to highlight.
    pub name: String,
    /// The highlight color.
    pub color: String,
    /// Highlighted node IDs.
    pub highlighted_nodes: Vec<ClangNodeId>,
}

impl HighlightDefinedUse {
    /// Create a new highlight-defined-use action.
    pub fn new(name: impl Into<String>, color: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            color: color.into(),
            highlighted_nodes: Vec::new(),
        }
    }
}

// ============================================================================
// PCodeCfgDisplay / PCodeDfgDisplay
// ============================================================================

/// Type of P-code control-flow graph to display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PCodeCfgGraphType {
    /// Basic block CFG.
    BasicBlock,
    /// Instruction-level CFG.
    Instruction,
    /// Call graph.
    CallGraph,
}

/// Type of P-code data-flow graph to display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PCodeDfgGraphType {
    /// Full data-flow graph.
    Full,
    /// Selected operations only.
    Selected,
    /// Combined CFG+DFG.
    Combined,
}

/// Display options for P-code DFG.
#[derive(Debug, Clone, Default)]
pub struct PCodeDfgDisplayOptions {
    /// Whether to show constant propagation.
    pub show_constants: bool,
    /// Whether to show register dependencies.
    pub show_register_deps: bool,
    /// Whether to show memory dependencies.
    pub show_memory_deps: bool,
    /// Maximum depth to display.
    pub max_depth: Option<usize>,
}

impl PCodeDfgDisplayOptions {
    /// Create default display options.
    pub fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// Action context
// ============================================================================

/// Context for a decompiler action, providing access to the current state.
#[derive(Debug, Clone)]
pub struct DecompilerActionContext {
    /// The cursor position.
    pub cursor: DecompilerCursorPosition,
    /// The function entry point.
    pub function_entry: Address,
    /// The function name.
    pub function_name: Option<String>,
    /// The current token highlights.
    pub highlights: super::component::TokenHighlights,
    /// The markup root ClangNodeId.
    pub markup_root: Option<ClangNodeId>,
}

impl DecompilerActionContext {
    /// Create a new action context.
    pub fn new(function_entry: Address) -> Self {
        Self {
            cursor: DecompilerCursorPosition::default(),
            function_entry,
            function_name: None,
            highlights: super::component::TokenHighlights::new(),
            markup_root: None,
        }
    }

    /// Get the token at the cursor (if any).
    pub fn cursor_token(&self) -> Option<ClangNodeId> {
        self.cursor.node_id
    }

    /// Get the address at the cursor (if any).
    pub fn cursor_address(&self) -> Option<Address> {
        self.cursor.address
    }
}

// ============================================================================
// Action metadata
// ============================================================================

/// Metadata about a decompiler action.
#[derive(Debug, Clone)]
pub struct ActionMetadata {
    /// The action name (unique identifier).
    pub name: String,
    /// The display name for the action.
    pub display_name: String,
    /// The action category.
    pub category: ActionCategory,
    /// Keyboard shortcut (if any).
    pub shortcut: Option<String>,
    /// Menu path (e.g., "Edit/Rename").
    pub menu_path: Option<String>,
    /// Tooltip text.
    pub tooltip: Option<String>,
    /// Whether the action requires a function to be decompiled.
    pub requires_function: bool,
}

impl ActionMetadata {
    /// Create a new action metadata.
    pub fn new(name: impl Into<String>, display_name: impl Into<String>, category: ActionCategory) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            category,
            shortcut: None,
            menu_path: None,
            tooltip: None,
            requires_function: true,
        }
    }

    /// Set the keyboard shortcut.
    pub fn with_shortcut(mut self, shortcut: impl Into<String>) -> Self {
        self.shortcut = Some(shortcut.into());
        self
    }

    /// Set the menu path.
    pub fn with_menu_path(mut self, path: impl Into<String>) -> Self {
        self.menu_path = Some(path.into());
        self
    }

    /// Set the tooltip.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    /// Whether the action has a keyboard shortcut.
    pub fn has_shortcut(&self) -> bool {
        self.shortcut.is_some()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_position_default() {
        let pos = DecompilerCursorPosition::new();
        assert!(pos.node_id.is_none());
        assert!(!pos.is_on_token());
    }

    #[test]
    fn cursor_position_on_token() {
        let mut pos = DecompilerCursorPosition::new();
        pos.node_id = Some(42);
        assert!(pos.is_on_token());
    }

    #[test]
    fn searcher_creation() {
        let searcher = DecompilerSearcher::new("main")
            .case_sensitive(false)
            .regex(true);
        assert_eq!(searcher.query, "main");
        assert!(!searcher.case_sensitive);
        assert!(searcher.use_regex);
    }

    #[test]
    fn search_results_navigation() {
        let mut results = DecompilerSearchResults::new();
        results.add(DecompilerSearchLocation::new(1, 0, 4, "main".to_string()));
        results.add(DecompilerSearchLocation::new(5, 3, 4, "main".to_string()));
        results.add(DecompilerSearchLocation::new(10, 7, 4, "main".to_string()));

        assert_eq!(results.count(), 3);

        let curr = results.current().unwrap();
        assert_eq!(curr.line, 1);

        let next = results.next().unwrap();
        assert_eq!(next.line, 5);

        let next = results.next().unwrap();
        assert_eq!(next.line, 10);

        // At last result, next() stays at last.
        let next = results.next().unwrap();
        assert_eq!(next.line, 10);

        let prev = results.previous().unwrap();
        assert_eq!(prev.line, 5);
    }

    #[test]
    fn search_results_empty() {
        let mut results = DecompilerSearchResults::new();
        assert_eq!(results.count(), 0);
        assert!(results.next().is_none());
        assert!(results.previous().is_none());
        assert!(results.current().is_none());
    }

    #[test]
    fn constant_format_hex() {
        assert_eq!(ConstantFormat::Hex.format_value(255, 4), "0x000000ff");
        assert_eq!(ConstantFormat::Hex.format_value(255, 8), "0x00000000000000ff");
    }

    #[test]
    fn constant_format_decimal() {
        assert_eq!(ConstantFormat::Decimal.format_value(42, 4), "42");
    }

    #[test]
    fn constant_format_char() {
        assert_eq!(ConstantFormat::Char.format_value(65, 1), "'A'");
        assert_eq!(ConstantFormat::Char.format_value(0, 1), "0x00");
    }

    #[test]
    fn constant_format_float() {
        let val = 1.0f32.to_bits() as u64;
        let formatted = ConstantFormat::Float.format_value(val, 4);
        assert_eq!(formatted, "1");
    }

    #[test]
    fn slice_highlight_colors_default() {
        let provider = SliceHighlightColorProvider::new();
        assert_eq!(provider.backward_color, "#0000ff");
        assert_eq!(provider.forward_color, "#008000");
    }

    #[test]
    fn equate_entry() {
        let entry = EquateEntry::new(42, "ANSWER", 0);
        assert_eq!(entry.value, 42);
        assert_eq!(entry.name, "ANSWER");
    }

    #[test]
    fn highlight_defined_use() {
        let hdu = HighlightDefinedUse::new("x", "#ff0000");
        assert_eq!(hdu.name, "x");
        assert!(hdu.highlighted_nodes.is_empty());
    }

    #[test]
    fn action_metadata() {
        let meta = ActionMetadata::new("rename", "Rename Variable", ActionCategory::Editing)
            .with_shortcut("F2")
            .with_menu_path("Edit/Rename");
        assert!(meta.has_shortcut());
        assert_eq!(meta.shortcut.as_deref(), Some("F2"));
        assert_eq!(meta.category, ActionCategory::Editing);
    }

    #[test]
    fn pcode_cfg_graph_types() {
        assert_ne!(PCodeCfgGraphType::BasicBlock, PCodeCfgGraphType::Instruction);
    }

    #[test]
    fn pcode_dfg_display_options() {
        let opts = PCodeDfgDisplayOptions::new();
        assert!(!opts.show_constants);
    }

    #[test]
    fn decompiler_action_context() {
        let ctx = DecompilerActionContext::new(Address::new(0x1000));
        assert_eq!(ctx.function_entry, Address::new(0x1000));
        assert!(ctx.cursor_token().is_none());
    }

    #[test]
    fn action_category_variants() {
        assert_ne!(ActionCategory::Navigation, ActionCategory::Editing);
        assert_eq!(ActionCategory::Pcode, ActionCategory::Pcode);
    }
}
