//! Decompiler component types (UI-adjacent, but data structures only).
//!
//! Port of Ghidra's `ghidra.app.decompiler.component` package.
//!
//! These are data structures and interfaces used by the decompiler UI
//! component.  In the Rust port, we provide the data types and trait
//! definitions only (no Swing/AWT).

use super::clang_node::{ClangNodeId, SyntaxType};
use super::decompile_results::DecompileResults;

/// Data associated with a single decompile operation for the component.
#[derive(Debug, Clone)]
pub struct DecompileData {
    /// The function entry point.
    pub function_entry: u64,
    /// The function name.
    pub function_name: Option<String>,
    /// The decompile results (if available).
    pub results: Option<DecompileResults>,
    /// The address factory XML (for decode).
    pub address_factory_xml: Option<String>,
}

impl DecompileData {
    /// Create new empty DecompileData for the given function.
    pub fn new(function_entry: u64) -> Self {
        Self {
            function_entry,
            function_name: None,
            results: None,
            address_factory_xml: None,
        }
    }
}

/// An empty DecompileData (no function selected).
#[derive(Debug, Clone, Default)]
pub struct EmptyDecompileData;

impl EmptyDecompileData {
    /// Create a new EmptyDecompileData.
    pub fn new() -> DecompileData {
        DecompileData::new(0)
    }
}

/// A field element in the decompiler display (struct field with name and offset).
#[derive(Debug, Clone)]
pub struct ClangFieldElement {
    /// The field name.
    pub name: String,
    /// The data type name.
    pub datatype_name: Option<String>,
    /// The byte offset within the structure.
    pub offset: i32,
    /// The ClangNodeId in the AST.
    pub node_id: ClangNodeId,
}

impl ClangFieldElement {
    /// Create a new ClangFieldElement.
    pub fn new(name: String, node_id: ClangNodeId) -> Self {
        Self {
            name,
            datatype_name: None,
            offset: 0,
            node_id,
        }
    }
}

/// A token matcher for highlighting.
#[derive(Debug, Clone)]
pub struct NameTokenMatcher {
    /// The name to match.
    pub name: String,
    /// Whether to match case-sensitively.
    pub case_sensitive: bool,
    /// The syntax type to restrict matching to (None = all types).
    pub restrict_type: Option<SyntaxType>,
}

impl NameTokenMatcher {
    /// Create a new NameTokenMatcher.
    pub fn new(name: &str, case_sensitive: bool) -> Self {
        Self {
            name: name.to_string(),
            case_sensitive,
            restrict_type: None,
        }
    }

    /// Check if a token text matches.
    pub fn matches(&self, text: &str, syntax_type: Option<SyntaxType>) -> bool {
        if let Some(restrict) = self.restrict_type {
            if Some(restrict) != syntax_type {
                return false;
            }
        }
        if self.case_sensitive {
            text == self.name
        } else {
            text.eq_ignore_ascii_case(&self.name)
        }
    }
}

/// Key identifying a token for highlight tracking.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenKey {
    /// Token text.
    pub text: String,
    /// Token syntax type.
    pub syntax_type: i32,
}

impl TokenKey {
    /// Create a new TokenKey.
    pub fn new(text: String, syntax_type: i32) -> Self {
        Self { text, syntax_type }
    }
}

/// Listener for decompile results changes.
pub trait DecompileResultsListener: std::fmt::Debug {
    /// Called when decompile results are available.
    fn decompile_results_available(&self, results: &DecompileResults);

    /// Called when decompile results are cleared.
    fn decompile_results_cleared(&self);
}

/// Highlight token information.
#[derive(Debug, Clone)]
pub struct HighlightToken {
    /// The ClangNodeId of the token.
    pub node_id: ClangNodeId,
    /// The highlight color.
    pub color: String,
    /// Whether this is a primary or secondary highlight.
    pub is_primary: bool,
}

impl HighlightToken {
    /// Create a new HighlightToken.
    pub fn new(node_id: ClangNodeId, color: String, is_primary: bool) -> Self {
        Self {
            node_id,
            color,
            is_primary,
        }
    }
}

/// Token highlights container.
#[derive(Debug, Clone, Default)]
pub struct TokenHighlights {
    /// Primary highlights (current selection).
    pub primary: Vec<HighlightToken>,
    /// Secondary highlights (additional markers).
    pub secondary: Vec<HighlightToken>,
}

impl TokenHighlights {
    /// Create a new empty TokenHighlights.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a primary highlight.
    pub fn add_primary(&mut self, token: HighlightToken) {
        self.primary.push(token);
    }

    /// Add a secondary highlight.
    pub fn add_secondary(&mut self, token: HighlightToken) {
        self.secondary.push(token);
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.primary.clear();
        self.secondary.clear();
    }

    /// Whether there are any highlights.
    pub fn is_empty(&self) -> bool {
        self.primary.is_empty() && self.secondary.is_empty()
    }
}

/// User-defined highlights.
#[derive(Debug, Clone, Default)]
pub struct UserHighlights {
    /// Per-text highlight colors.
    pub highlights: std::collections::HashMap<String, String>,
}

impl UserHighlights {
    /// Create a new empty UserHighlights.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a highlight color for the given text.
    pub fn set_highlight(&mut self, text: String, color: String) {
        self.highlights.insert(text, color);
    }

    /// Get the highlight color for the given text.
    pub fn get_highlight(&self, text: &str) -> Option<&str> {
        self.highlights.get(text).map(|s| s.as_str())
    }

    /// Remove a highlight.
    pub fn remove_highlight(&mut self, text: &str) {
        self.highlights.remove(text);
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.highlights.clear();
    }
}

/// Color provider interface.
pub trait ColorProvider: std::fmt::Debug {
    /// Get the background color.
    fn background_color(&self) -> &str;

    /// Get the color for the given syntax type.
    fn color_for_type(&self, syntax_type: SyntaxType) -> &str;
}

/// Default color provider.
#[derive(Debug, Clone)]
pub struct DefaultColorProvider;

impl ColorProvider for DefaultColorProvider {
    fn background_color(&self) -> &str {
        "#ffffff"
    }

    fn color_for_type(&self, syntax_type: SyntaxType) -> &str {
        match syntax_type {
            SyntaxType::Keyword => "#0000ff",
            SyntaxType::Comment => "#808080",
            SyntaxType::Type => "#800080",
            SyntaxType::Function => "#0000ff",
            SyntaxType::Variable => "#000000",
            SyntaxType::Const => "#008000",
            SyntaxType::Parameter => "#804000",
            SyntaxType::Global => "#008080",
            SyntaxType::Default => "#000000",
            SyntaxType::Error => "#ff0000",
            SyntaxType::Special => "#8000ff",
            SyntaxType::Field => "#008080",
        }
    }
}

// ============================================================================
// ClangHighlightController
// ============================================================================

/// Controls highlighting of tokens in the decompiler display.
///
/// Manages primary highlights (selected token and its uses), secondary
/// highlights (additional user markers), and slice highlights.
#[derive(Debug, Clone, Default)]
pub struct ClangHighlightController {
    /// Primary highlight (selected token).
    pub primary_highlight: Option<ClangNodeId>,
    /// Secondary highlights (additional user markers).
    pub secondary_highlights: Vec<ClangNodeId>,
    /// Slice highlights.
    pub slice_highlights: Vec<ClangNodeId>,
    /// All tokens with the same text as the primary highlight.
    pub matching_tokens: Vec<ClangNodeId>,
    /// Whether to highlight matching tokens.
    pub highlight_matching: bool,
}

impl ClangHighlightController {
    /// Create a new highlight controller.
    pub fn new() -> Self {
        Self {
            highlight_matching: true,
            ..Default::default()
        }
    }

    /// Set the primary highlight.
    pub fn set_primary(&mut self, node_id: ClangNodeId) {
        self.primary_highlight = Some(node_id);
    }

    /// Clear the primary highlight.
    pub fn clear_primary(&mut self) {
        self.primary_highlight = None;
        self.matching_tokens.clear();
    }

    /// Add a secondary highlight.
    pub fn add_secondary(&mut self, node_id: ClangNodeId) {
        if !self.secondary_highlights.contains(&node_id) {
            self.secondary_highlights.push(node_id);
        }
    }

    /// Remove a secondary highlight.
    pub fn remove_secondary(&mut self, node_id: ClangNodeId) {
        self.secondary_highlights.retain(|&id| id != node_id);
    }

    /// Clear all secondary highlights.
    pub fn clear_secondary(&mut self) {
        self.secondary_highlights.clear();
    }

    /// Set matching tokens (same text as primary).
    pub fn set_matching_tokens(&mut self, tokens: Vec<ClangNodeId>) {
        self.matching_tokens = tokens;
    }

    /// Whether any highlights are active.
    pub fn has_highlights(&self) -> bool {
        self.primary_highlight.is_some()
            || !self.secondary_highlights.is_empty()
            || !self.slice_highlights.is_empty()
    }

    /// Remove all highlights.
    pub fn clear_all(&mut self) {
        self.primary_highlight = None;
        self.secondary_highlights.clear();
        self.slice_highlights.clear();
        self.matching_tokens.clear();
    }
}

/// Trait for highlight change listeners.
pub trait ClangHighlightListener: std::fmt::Debug {
    /// Called when the primary highlight changes.
    fn primary_highlight_changed(&self, old: Option<ClangNodeId>, new: Option<ClangNodeId>);

    /// Called when secondary highlights change.
    fn secondary_highlights_changed(&self);

    /// Called when slice highlights change.
    fn slice_highlights_changed(&self);
}

/// A null highlight listener that does nothing.
#[derive(Debug, Clone, Default)]
pub struct NullClangHighlightListener;

impl ClangHighlightListener for NullClangHighlightListener {
    fn primary_highlight_changed(&self, _old: Option<ClangNodeId>, _new: Option<ClangNodeId>) {}
    fn secondary_highlights_changed(&self) {}
    fn slice_highlights_changed(&self) {}
}

// ============================================================================
// ClangLayoutController
// ============================================================================

/// Controls the layout of Clang AST nodes for display.
///
/// Manages line breaks, indentation, and the mapping from display
/// coordinates to ClangNodeIds.
#[derive(Debug, Clone, Default)]
pub struct ClangLayoutController {
    /// The number of display lines.
    pub line_count: usize,
    /// The maximum column width.
    pub max_column: usize,
    /// Map from (line, column) to ClangNodeId.
    pub position_map: std::collections::HashMap<(usize, usize), ClangNodeId>,
    /// Map from ClangNodeId to (line, column).
    pub node_positions: std::collections::HashMap<ClangNodeId, (usize, usize)>,
    /// Whether layout needs recalculation.
    pub dirty: bool,
}

impl ClangLayoutController {
    /// Create a new layout controller.
    pub fn new() -> Self {
        Self {
            dirty: true,
            ..Default::default()
        }
    }

    /// Get the ClangNodeId at the given position.
    pub fn node_at_position(&self, line: usize, column: usize) -> Option<ClangNodeId> {
        self.position_map.get(&(line, column)).copied()
    }

    /// Get the position of a ClangNodeId.
    pub fn position_of_node(&self, node_id: ClangNodeId) -> Option<(usize, usize)> {
        self.node_positions.get(&node_id).copied()
    }

    /// Set the position of a ClangNodeId.
    pub fn set_node_position(&mut self, node_id: ClangNodeId, line: usize, column: usize) {
        self.node_positions.insert(node_id, (line, column));
        self.position_map.insert((line, column), node_id);
    }

    /// Mark layout as dirty (needs recalculation).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Mark layout as clean.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }
}

// ============================================================================
// DecompilerController
// ============================================================================

/// Controller for a decompiler view.
///
/// Manages the lifecycle of decompilation for a function, from request
/// to display. Coordinates between the DecompInterface (actual
/// decompilation) and the display component.
#[derive(Debug, Clone)]
pub struct DecompilerController {
    /// The current decompile data.
    pub data: Option<DecompileData>,
    /// The highlight controller.
    pub highlights: ClangHighlightController,
    /// The layout controller.
    pub layout: ClangLayoutController,
    /// Whether the controller is disposed.
    pub disposed: bool,
    /// Pending decompile requests (function addresses).
    pub pending_requests: Vec<u64>,
}

impl DecompilerController {
    /// Create a new decompiler controller.
    pub fn new() -> Self {
        Self {
            data: None,
            highlights: ClangHighlightController::new(),
            layout: ClangLayoutController::new(),
            disposed: false,
            pending_requests: Vec::new(),
        }
    }

    /// Request decompilation of a function.
    pub fn request_decompile(&mut self, function_entry: u64) {
        self.pending_requests.push(function_entry);
    }

    /// Set the decompile data (called when results arrive).
    pub fn set_data(&mut self, data: DecompileData) {
        self.data = Some(data);
        self.layout.mark_dirty();
    }

    /// Get the current function entry (if any).
    pub fn current_function(&self) -> Option<u64> {
        self.data.as_ref().map(|d| d.function_entry)
    }

    /// Clear the current decompile data.
    pub fn clear(&mut self) {
        self.data = None;
        self.highlights.clear_all();
        self.layout.mark_dirty();
    }

    /// Dispose of the controller.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.data = None;
        self.highlights.clear_all();
        self.pending_requests.clear();
    }

    /// Whether the controller has a decompiled function.
    pub fn has_function(&self) -> bool {
        self.data.is_some()
    }
}

impl Default for DecompilerController {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DecompilerPanel data
// ============================================================================

/// Data for the decompiler panel (display area).
///
/// Contains the layout of lines and their associated tokens.
#[derive(Debug, Clone, Default)]
pub struct DecompilerPanelData {
    /// The display lines.
    pub lines: Vec<PanelLine>,
    /// The current scroll position.
    pub scroll_position: (usize, usize),
    /// The viewport size (width, height).
    pub viewport_size: (usize, usize),
    /// Whether word-wrap is enabled.
    pub word_wrap: bool,
}

/// A single display line in the decompiler panel.
#[derive(Debug, Clone, Default)]
pub struct PanelLine {
    /// The line number.
    pub line_number: usize,
    /// The ClangNodeId of the line.
    pub node_id: ClangNodeId,
    /// The tokens in this line.
    pub tokens: Vec<PanelToken>,
    /// The y-position of this line (in pixels).
    pub y_position: usize,
    /// The height of this line (in pixels).
    pub height: usize,
}

/// A single token in the decompiler panel display.
#[derive(Debug, Clone)]
pub struct PanelToken {
    /// The ClangNodeId of the token.
    pub node_id: ClangNodeId,
    /// The text content.
    pub text: String,
    /// The syntax type for coloring.
    pub syntax_type: SyntaxType,
    /// The x-position of the token (in pixels).
    pub x_position: usize,
    /// The width of the token (in pixels).
    pub width: usize,
}

impl PanelToken {
    /// Create a new panel token.
    pub fn new(node_id: ClangNodeId, text: String, syntax_type: SyntaxType) -> Self {
        Self {
            node_id,
            text,
            syntax_type,
            x_position: 0,
            width: 0,
        }
    }
}

impl DecompilerPanelData {
    /// Create a new empty panel data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of display lines.
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Get a line by number.
    pub fn get_line(&self, line_number: usize) -> Option<&PanelLine> {
        self.lines.get(line_number)
    }

    /// Set word-wrap mode.
    pub fn set_word_wrap(&mut self, word_wrap: bool) {
        self.word_wrap = word_wrap;
    }
}

// ============================================================================
// ClangTextField
// ============================================================================

/// A text field for Clang token editing (rename, retype).
#[derive(Debug, Clone)]
pub struct ClangTextField {
    /// The current text value.
    pub text: String,
    /// The ClangNodeId being edited.
    pub node_id: ClangNodeId,
    /// Whether the field is active (visible).
    pub active: bool,
    /// The cursor position within the text field.
    pub cursor_position: usize,
}

impl ClangTextField {
    /// Create a new text field.
    pub fn new(node_id: ClangNodeId, initial_text: String) -> Self {
        let len = initial_text.len();
        Self {
            text: initial_text,
            node_id,
            active: false,
            cursor_position: len,
        }
    }

    /// Activate the text field.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate the text field.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Get the current text.
    pub fn get_text(&self) -> &str {
        &self.text
    }

    /// Set the text.
    pub fn set_text(&mut self, text: String) {
        self.cursor_position = text.len();
        self.text = text;
    }
}

// ============================================================================
// TokenHighlightColors
// ============================================================================

/// Pre-defined highlight colors for the decompiler.
#[derive(Debug, Clone)]
pub struct TokenHighlightColors {
    /// Primary highlight color.
    pub primary: String,
    /// Secondary highlight colors (cycle through these).
    pub secondary: Vec<String>,
    /// Slice highlight color.
    pub slice: String,
}

impl Default for TokenHighlightColors {
    fn default() -> Self {
        Self {
            primary: "#ffff00".to_string(),
            secondary: vec![
                "#00ffff".to_string(),
                "#ff80ff".to_string(),
                "#80ff80".to_string(),
                "#ff8080".to_string(),
                "#8080ff".to_string(),
            ],
            slice: "#c0c0ff".to_string(),
        }
    }
}

impl TokenHighlightColors {
    /// Create default highlight colors.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a secondary highlight color by index (cycling).
    pub fn secondary_color(&self, index: usize) -> &str {
        if self.secondary.is_empty() {
            &self.primary
        } else {
            &self.secondary[index % self.secondary.len()]
        }
    }
}

// ============================================================================
// EmptyDecompileData
// ============================================================================

// EmptyDecompileData is already defined above.

// ============================================================================
// DecompileResultsListener (already defined above)
// ============================================================================

// ============================================================================
// tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompile_data() {
        let data = DecompileData::new(0x1000);
        assert_eq!(data.function_entry, 0x1000);
        assert!(data.results.is_none());
    }

    #[test]
    fn test_empty_decompile_data() {
        let data = EmptyDecompileData::new();
        assert_eq!(data.function_entry, 0);
    }

    #[test]
    fn test_clang_field_element() {
        let elem = ClangFieldElement::new("x".to_string(), 0);
        assert_eq!(elem.name, "x");
        assert_eq!(elem.node_id, 0);
    }

    #[test]
    fn test_name_token_matcher() {
        let matcher = NameTokenMatcher::new("main", true);
        assert!(matcher.matches("main", None));
        assert!(!matcher.matches("Main", None));
    }

    #[test]
    fn test_token_key() {
        let key = TokenKey::new("int".to_string(), 0);
        assert_eq!(key.text, "int");
        assert_eq!(key.syntax_type, 0);
    }

    #[test]
    fn test_token_highlights() {
        let mut th = TokenHighlights::new();
        assert!(th.is_empty());
        th.add_primary(HighlightToken::new(0, "#ff0000".to_string(), true));
        assert!(!th.is_empty());
        th.clear();
        assert!(th.is_empty());
    }

    #[test]
    fn test_user_highlights() {
        let mut uh = UserHighlights::new();
        uh.set_highlight("main".to_string(), "#ff0000".to_string());
        assert_eq!(uh.get_highlight("main"), Some("#ff0000"));
        assert!(uh.get_highlight("other").is_none());
        uh.remove_highlight("main");
        assert!(uh.get_highlight("main").is_none());
    }

    #[test]
    fn test_default_color_provider() {
        let provider = DefaultColorProvider;
        assert_eq!(provider.background_color(), "#ffffff");
        assert_eq!(provider.color_for_type(SyntaxType::Keyword), "#0000ff");
        assert_eq!(provider.color_for_type(SyntaxType::Error), "#ff0000");
    }
}
