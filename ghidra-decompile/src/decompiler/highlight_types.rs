//! Advanced highlight and token management types.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangHighlightController`,
//! `ClangLayoutController`, `ClangTextField`, `ColorProvider`, `DecompileData`,
//! `DecompilerController`, `HighlightToken`, `TokenHighlights`, `TokenKey`,
//! `UserHighlights` and related types from the `ghidra.app.decompiler.panel` and
//! `ghidra.app.decompiler.panel2` packages.

use std::collections::HashMap;

use ghidra_core::addr::Address;

use super::clang_node::{ClangNodeId, ClangNodeArena, ClangNodeKind, ClangTokenGroupData, SyntaxType};

// ============================================================================
// HighlightToken
// ============================================================================

/// A token that has been marked for highlight display.
///
/// In Ghidra, `HighlightToken` wraps a `ClangToken` and carries the
/// highlight color plus matching context.
#[derive(Debug, Clone)]
pub struct HighlightToken {
    /// The node id of the highlighted token in the Clang AST.
    pub token_id: ClangNodeId,
    /// The highlight color (CSS color string).
    pub color: String,
    /// Whether this highlight is the "primary" highlight (as opposed to
    /// secondary or reference highlights).
    pub primary: bool,
    /// An optional label shown alongside the highlight.
    pub label: Option<String>,
}

impl HighlightToken {
    /// Create a new highlight token.
    pub fn new(token_id: ClangNodeId, color: impl Into<String>, primary: bool) -> Self {
        Self {
            token_id,
            color: color.into(),
            primary,
            label: None,
        }
    }
}

// ============================================================================
// TokenKey
// ============================================================================

/// A key that uniquely identifies a token within a decompiled function.
///
/// Used as a map key for highlight lookups.  The key is the (address, syntax-type)
/// pair, which uniquely identifies a token within its function context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenKey {
    /// The address of the P-code op that produced this token.
    pub address: u64,
    /// The syntax type of the token.
    pub syntax_type: SyntaxType,
}

impl TokenKey {
    /// Create a new token key.
    pub fn new(address: u64, syntax_type: SyntaxType) -> Self {
        Self {
            address,
            syntax_type,
        }
    }
}

// ============================================================================
// TokenHighlights
// ============================================================================

/// A collection of highlighted tokens indexed by `TokenKey`.
///
/// Manages the set of tokens that have user or system highlights applied.
#[derive(Debug, Clone, Default)]
pub struct TokenHighlights {
    /// Map from token key to highlight info.
    highlights: HashMap<TokenKey, HighlightToken>,
}

impl TokenHighlights {
    /// Create a new empty token highlights set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a highlight for the given key.
    pub fn set_highlight(&mut self, key: TokenKey, highlight: HighlightToken) {
        self.highlights.insert(key, highlight);
    }

    /// Remove the highlight for the given key.
    pub fn remove_highlight(&mut self, key: &TokenKey) -> Option<HighlightToken> {
        self.highlights.remove(key)
    }

    /// Get the highlight for the given key.
    pub fn get_highlight(&self, key: &TokenKey) -> Option<&HighlightToken> {
        self.highlights.get(key)
    }

    /// Check whether the given key has a highlight.
    pub fn has_highlight(&self, key: &TokenKey) -> bool {
        self.highlights.contains_key(key)
    }

    /// The number of highlights.
    pub fn len(&self) -> usize {
        self.highlights.len()
    }

    /// Whether there are no highlights.
    pub fn is_empty(&self) -> bool {
        self.highlights.is_empty()
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.highlights.clear();
    }

    /// Iterate over all highlight entries.
    pub fn iter(&self) -> impl Iterator<Item = (&TokenKey, &HighlightToken)> {
        self.highlights.iter()
    }
}

// ============================================================================
// UserHighlights
// ============================================================================

/// User-defined highlight selections.
///
/// In Ghidra, users can select tokens and assign highlight colors.
/// This structure stores those selections across the session.
#[derive(Debug, Clone, Default)]
pub struct UserHighlights {
    /// The current user highlight selections.
    selections: Vec<UserHighlightSelection>,
}

/// A single user highlight selection.
#[derive(Debug, Clone)]
pub struct UserHighlightSelection {
    /// The address range highlighted.
    pub address: u64,
    /// The highlight color.
    pub color: String,
    /// Whether this is an equate highlight.
    pub is_equate: bool,
    /// The equate name if this is an equate highlight.
    pub equate_name: Option<String>,
}

impl UserHighlights {
    /// Create a new empty user highlights set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a user highlight selection.
    pub fn add_selection(&mut self, sel: UserHighlightSelection) {
        self.selections.push(sel);
    }

    /// Remove all selections.
    pub fn clear(&mut self) {
        self.selections.clear();
    }

    /// The number of selections.
    pub fn len(&self) -> usize {
        self.selections.len()
    }

    /// Whether there are no selections.
    pub fn is_empty(&self) -> bool {
        self.selections.is_empty()
    }

    /// Iterate over selections.
    pub fn selections(&self) -> &[UserHighlightSelection] {
        &self.selections
    }
}

// ============================================================================
// NameTokenMatcher
// ============================================================================

/// Matches tokens by name for highlight lookups.
///
/// Used to highlight all occurrences of a variable or function name.
#[derive(Debug, Clone)]
pub struct NameTokenMatcher {
    /// The token text to match.
    pub pattern: String,
    /// Whether the match is case-sensitive.
    pub case_sensitive: bool,
    /// The syntax types to restrict matching to (empty = all).
    pub syntax_filter: Vec<SyntaxType>,
}

impl NameTokenMatcher {
    /// Create a new name token matcher.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            case_sensitive: true,
            syntax_filter: Vec::new(),
        }
    }

    /// Check if a token's text matches this matcher.
    pub fn matches(&self, text: &str, syntax_type: SyntaxType) -> bool {
        if !self.syntax_filter.is_empty() && !self.syntax_filter.contains(&syntax_type) {
            return false;
        }
        if self.case_sensitive {
            text == self.pattern
        } else {
            text.eq_ignore_ascii_case(&self.pattern)
        }
    }
}

// ============================================================================
// ClangHighlightListener
// ============================================================================

/// Trait for receiving highlight change notifications.
pub trait ClangHighlightListener: Send + Sync + std::fmt::Debug {
    /// Called when highlights have changed.
    fn highlights_changed(&self);
    /// Called when the cursor position has changed.
    fn cursor_moved(&self, new_address: Option<Address>);
}

/// A no-op highlight listener.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullClangHighlightListener;

impl ClangHighlightListener for NullClangHighlightListener {
    fn highlights_changed(&self) {}
    fn cursor_moved(&self, _new_address: Option<Address>) {}
}

// ============================================================================
// ClangHighlightController
// ============================================================================

/// Controls highlight state for the decompiler panel.
///
/// Manages the interaction between token selection, highlight colors,
/// and the display of matched tokens in the decompiled output.
#[derive(Debug)]
pub struct ClangHighlightController {
    /// Current highlighted tokens.
    highlights: TokenHighlights,
    /// User-defined highlights.
    user_highlights: UserHighlights,
    /// Currently matched token (e.g., from "highlight defined use").
    matched_token: Option<ClangNodeId>,
    /// Current cursor token.
    cursor_token: Option<ClangNodeId>,
    /// Listeners for highlight change events.
    listeners: Vec<Box<dyn ClangHighlightListener>>,
}

impl ClangHighlightController {
    /// Create a new highlight controller.
    pub fn new() -> Self {
        Self {
            highlights: TokenHighlights::new(),
            user_highlights: UserHighlights::new(),
            matched_token: None,
            cursor_token: None,
            listeners: Vec::new(),
        }
    }

    /// Add a listener.
    pub fn add_listener(&mut self, listener: Box<dyn ClangHighlightListener>) {
        self.listeners.push(listener);
    }

    /// Set the matched token (for "highlight defined use").
    pub fn set_matched_token(&mut self, token_id: Option<ClangNodeId>) {
        self.matched_token = token_id;
        self.notify_highlights_changed();
    }

    /// Get the matched token.
    pub fn matched_token(&self) -> Option<ClangNodeId> {
        self.matched_token
    }

    /// Set the cursor token.
    pub fn set_cursor_token(&mut self, token_id: Option<ClangNodeId>) {
        self.cursor_token = token_id;
        self.notify_cursor_moved(None);
    }

    /// Get the cursor token.
    pub fn cursor_token(&self) -> Option<ClangNodeId> {
        self.cursor_token
    }

    /// Get the highlights.
    pub fn highlights(&self) -> &TokenHighlights {
        &self.highlights
    }

    /// Get the highlights mutably.
    pub fn highlights_mut(&mut self) -> &mut TokenHighlights {
        &mut self.highlights
    }

    /// Get the user highlights.
    pub fn user_highlights(&self) -> &UserHighlights {
        &self.user_highlights
    }

    /// Get the user highlights mutably.
    pub fn user_highlights_mut(&mut self) -> &mut UserHighlights {
        &mut self.user_highlights
    }

    /// Clear all highlights and notify listeners.
    pub fn clear_all(&mut self) {
        self.highlights.clear();
        self.user_highlights.clear();
        self.matched_token = None;
        self.notify_highlights_changed();
    }

    fn notify_highlights_changed(&self) {
        for listener in &self.listeners {
            listener.highlights_changed();
        }
    }

    fn notify_cursor_moved(&self, addr: Option<Address>) {
        for listener in &self.listeners {
            listener.cursor_moved(addr);
        }
    }
}

impl Default for ClangHighlightController {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ClangLayoutController
// ============================================================================

/// Controls the layout (line breaking, indentation) of the decompiler output.
///
/// Manages how the token tree is flattened into displayable lines, including
/// field widths, line wrapping, and indentation settings.
#[derive(Debug, Clone)]
pub struct ClangLayoutController {
    /// Current indent level.
    indent_level: usize,
    /// Indent string (e.g., "    " for 4 spaces).
    indent_string: String,
    /// Maximum line width before wrapping.
    max_line_width: usize,
    /// Whether to use block style braces.
    block_braces: bool,
    /// Current line number.
    line_number: usize,
}

impl ClangLayoutController {
    /// Create a new layout controller with default settings.
    pub fn new() -> Self {
        Self {
            indent_level: 0,
            indent_string: "    ".to_string(),
            max_line_width: 120,
            block_braces: true,
            line_number: 0,
        }
    }

    /// Get the current indent level.
    pub fn indent_level(&self) -> usize {
        self.indent_level
    }

    /// Set the indent level.
    pub fn set_indent_level(&mut self, level: usize) {
        self.indent_level = level;
    }

    /// Increment the indent level.
    pub fn indent(&mut self) {
        self.indent_level += 1;
    }

    /// Decrement the indent level.
    pub fn outdent(&mut self) {
        if self.indent_level > 0 {
            self.indent_level -= 1;
        }
    }

    /// Get the indent string for the current level.
    pub fn current_indent(&self) -> String {
        self.indent_string.repeat(self.indent_level)
    }

    /// Get the indent string pattern.
    pub fn indent_string(&self) -> &str {
        &self.indent_string
    }

    /// Set the indent string pattern.
    pub fn set_indent_string(&mut self, s: impl Into<String>) {
        self.indent_string = s.into();
    }

    /// Get the maximum line width.
    pub fn max_line_width(&self) -> usize {
        self.max_line_width
    }

    /// Whether block braces are enabled.
    pub fn block_braces(&self) -> bool {
        self.block_braces
    }

    /// Get the current line number.
    pub fn line_number(&self) -> usize {
        self.line_number
    }

    /// Advance the line number.
    pub fn next_line(&mut self) -> usize {
        let n = self.line_number;
        self.line_number += 1;
        n
    }
}

impl Default for ClangLayoutController {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ClangTextField
// ============================================================================

/// A text field that displays a portion of the decompiled C code.
///
/// Represents a single "field" within the decompiler panel's grid layout,
/// which may span a fixed number of columns.
#[derive(Debug, Clone)]
pub struct ClangTextField {
    /// The column index in the panel grid.
    pub column: usize,
    /// The number of columns this field spans.
    pub column_span: usize,
    /// The text content (plain text, no formatting).
    pub text: String,
    /// The width in pixels.
    pub width: usize,
    /// Whether this field is currently visible.
    pub visible: bool,
}

impl ClangTextField {
    /// Create a new text field.
    pub fn new(column: usize, column_span: usize, text: impl Into<String>) -> Self {
        Self {
            column,
            column_span,
            text: text.into(),
            width: 0,
            visible: true,
        }
    }

    /// Whether this field is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The character length of the text.
    pub fn char_count(&self) -> usize {
        self.text.chars().count()
    }
}

// ============================================================================
// ColorProvider
// ============================================================================

/// Trait for providing syntax highlighting colors.
///
/// Implementors map `SyntaxType` values to display colors.
pub trait ColorProvider: Send + Sync + std::fmt::Debug {
    /// Get the color for a given syntax type.
    fn get_color(&self, syntax_type: SyntaxType) -> String;
    /// Get the background color for a given syntax type.
    fn get_background_color(&self, syntax_type: SyntaxType) -> Option<String>;
}

/// Default color provider with standard Ghidra decompiler colors.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultColorProvider;

impl ColorProvider for DefaultColorProvider {
    fn get_color(&self, syntax_type: SyntaxType) -> String {
        match syntax_type {
            SyntaxType::Keyword => "#0000FF".into(),
            SyntaxType::Comment => "#808080".into(),
            SyntaxType::Type => "#000080".into(),
            SyntaxType::Function => "#0000FF".into(),
            SyntaxType::Variable => "#800000".into(),
            SyntaxType::Const => "#008000".into(),
            SyntaxType::Parameter => "#800080".into(),
            SyntaxType::Global => "#808000".into(),
            SyntaxType::Default => "#000000".into(),
            SyntaxType::Error => "#FF0000".into(),
            SyntaxType::Special => "#FF8000".into(),
            SyntaxType::Field => "#008080".into(),
        }
    }

    fn get_background_color(&self, _syntax_type: SyntaxType) -> Option<String> {
        None
    }
}

// ============================================================================
// DecompileData
// ============================================================================

/// The data model for the decompiler panel.
///
/// Holds the decompiled function's AST and associated metadata.
/// In Ghidra this is shared between the panel and the controller.
#[derive(Debug, Clone)]
pub struct DecompileData {
    /// The function entry point address.
    pub function_entry: u64,
    /// The Clang AST arena.
    pub arena: Option<ClangNodeArena>,
    /// The root node id in the arena.
    pub root_id: Option<ClangNodeId>,
    /// The function name.
    pub function_name: Option<String>,
    /// Whether decompilation was successful.
    pub decompile_success: bool,
    /// Error message if decompilation failed.
    pub error_message: Option<String>,
    /// The highlight controller for this function.
    pub highlights: TokenHighlights,
}

impl DecompileData {
    /// Create new decompile data for the given function.
    pub fn new(function_entry: u64) -> Self {
        Self {
            function_entry,
            arena: None,
            root_id: None,
            function_name: None,
            decompile_success: false,
            error_message: None,
            highlights: TokenHighlights::new(),
        }
    }

    /// Set the decompile results.
    pub fn set_results(
        &mut self,
        arena: ClangNodeArena,
        root_id: ClangNodeId,
        function_name: Option<String>,
    ) {
        self.arena = Some(arena);
        self.root_id = Some(root_id);
        self.function_name = function_name;
        self.decompile_success = true;
        self.error_message = None;
    }

    /// Set an error.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.decompile_success = false;
        self.error_message = Some(message.into());
    }

    /// Whether this data has valid decompile results.
    pub fn has_results(&self) -> bool {
        self.decompile_success && self.arena.is_some() && self.root_id.is_some()
    }

    /// Get the AST arena, if present.
    pub fn arena(&self) -> Option<&ClangNodeArena> {
        self.arena.as_ref()
    }

    /// Get the root node id, if present.
    pub fn root_id(&self) -> Option<ClangNodeId> {
        self.root_id
    }
}

// ============================================================================
// DecompilerController
// ============================================================================

/// Controller for the decompiler panel.
///
/// Coordinates between the decompiler process, the panel display,
/// and the highlight state.
#[derive(Debug)]
pub struct DecompilerController {
    /// Current decompile data.
    data: Option<DecompileData>,
    /// The highlight controller.
    highlight_controller: ClangHighlightController,
    /// The layout controller.
    layout_controller: ClangLayoutController,
    /// The color provider.
    color_provider: Box<dyn ColorProvider>,
    /// Whether the panel is in "editable" mode (allows renaming, retyping).
    editable: bool,
}

impl DecompilerController {
    /// Create a new controller with default settings.
    pub fn new() -> Self {
        Self {
            data: None,
            highlight_controller: ClangHighlightController::new(),
            layout_controller: ClangLayoutController::new(),
            color_provider: Box::new(DefaultColorProvider),
            editable: true,
        }
    }

    /// Get the current decompile data.
    pub fn data(&self) -> Option<&DecompileData> {
        self.data.as_ref()
    }

    /// Set the decompile data.
    pub fn set_data(&mut self, data: DecompileData) {
        self.data = Some(data);
    }

    /// Get the highlight controller.
    pub fn highlight_controller(&self) -> &ClangHighlightController {
        &self.highlight_controller
    }

    /// Get the highlight controller mutably.
    pub fn highlight_controller_mut(&mut self) -> &mut ClangHighlightController {
        &mut self.highlight_controller
    }

    /// Get the layout controller.
    pub fn layout_controller(&self) -> &ClangLayoutController {
        &self.layout_controller
    }

    /// Get the layout controller mutably.
    pub fn layout_controller_mut(&mut self) -> &mut ClangLayoutController {
        &mut self.layout_controller
    }

    /// Whether the panel is editable.
    pub fn is_editable(&self) -> bool {
        self.editable
    }

    /// Set whether the panel is editable.
    pub fn set_editable(&mut self, editable: bool) {
        self.editable = editable;
    }
}

impl Default for DecompilerController {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DecompileResultsListener
// ============================================================================

/// Trait for receiving decompile results notifications.
pub trait DecompileResultsListener: Send + Sync {
    /// Called when new decompile results are available.
    fn results_available(&self, data: &DecompileData);
    /// Called when decompilation starts.
    fn decompile_started(&self, function_entry: u64);
    /// Called when decompilation fails.
    fn decompile_failed(&self, function_entry: u64, error: &str);
}

/// A no-op results listener.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullDecompileResultsListener;

impl DecompileResultsListener for NullDecompileResultsListener {
    fn results_available(&self, _data: &DecompileData) {}
    fn decompile_started(&self, _function_entry: u64) {}
    fn decompile_failed(&self, _function_entry: u64, _error: &str) {}
}

// ============================================================================
// ClangFieldElement
// ============================================================================

/// A field element in the decompiler panel's column layout.
///
/// Maps a field position in the display grid to a range of token ids
/// in the Clang AST.
#[derive(Debug, Clone)]
pub struct ClangFieldElement {
    /// Starting column in the panel grid.
    pub start_col: usize,
    /// Ending column in the panel grid (exclusive).
    pub end_col: usize,
    /// The line index in the display.
    pub line_index: usize,
    /// The token ids that make up this field.
    pub token_ids: Vec<ClangNodeId>,
}

impl ClangFieldElement {
    /// Create a new field element.
    pub fn new(start_col: usize, end_col: usize, line_index: usize) -> Self {
        Self {
            start_col,
            end_col,
            line_index,
            token_ids: Vec::new(),
        }
    }

    /// The number of columns this field spans.
    pub fn column_span(&self) -> usize {
        self.end_col - self.start_col
    }
}

// ============================================================================
// PanelLine / PanelToken
// ============================================================================

/// A line in the decompiler panel display.
#[derive(Debug, Clone)]
pub struct PanelLine {
    /// Line index.
    pub line_index: usize,
    /// Indent level.
    pub indent_level: usize,
    /// Field elements on this line.
    pub fields: Vec<ClangFieldElement>,
    /// Token ids on this line.
    pub token_ids: Vec<ClangNodeId>,
}

impl PanelLine {
    /// Create a new panel line.
    pub fn new(line_index: usize, indent_level: usize) -> Self {
        Self {
            line_index,
            indent_level,
            fields: Vec::new(),
            token_ids: Vec::new(),
        }
    }
}

/// A token in the decompiler panel display.
#[derive(Debug, Clone)]
pub struct PanelToken {
    /// The token id in the Clang AST.
    pub token_id: ClangNodeId,
    /// The display text.
    pub text: String,
    /// The syntax type.
    pub syntax_type: SyntaxType,
    /// The bounding rectangle in the panel (x, y, width, height).
    pub bounds: (f64, f64, f64, f64),
    /// The line index this token belongs to.
    pub line_index: usize,
}

impl PanelToken {
    /// Create a new panel token.
    pub fn new(token_id: ClangNodeId, text: impl Into<String>, syntax_type: SyntaxType) -> Self {
        Self {
            token_id,
            text: text.into(),
            syntax_type,
            bounds: (0.0, 0.0, 0.0, 0.0),
            line_index: 0,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlight_token_creation() {
        let ht = HighlightToken::new(0, "#FF0000", true);
        assert_eq!(ht.token_id, 0);
        assert_eq!(ht.color, "#FF0000");
        assert!(ht.primary);
        assert!(ht.label.is_none());
    }

    #[test]
    fn token_key_equality() {
        let k1 = TokenKey::new(0x1000, SyntaxType::Variable);
        let k2 = TokenKey::new(0x1000, SyntaxType::Variable);
        let k3 = TokenKey::new(0x1000, SyntaxType::Keyword);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn token_highlights_set_and_get() {
        let mut th = TokenHighlights::new();
        let key = TokenKey::new(0x1000, SyntaxType::Variable);
        assert!(!th.has_highlight(&key));

        let ht = HighlightToken::new(0, "#FF0000", true);
        th.set_highlight(key, ht);
        assert!(th.has_highlight(&key));
        assert_eq!(th.len(), 1);

        let removed = th.remove_highlight(&key);
        assert!(removed.is_some());
        assert!(th.is_empty());
    }

    #[test]
    fn user_highlights_selections() {
        let mut uh = UserHighlights::new();
        assert!(uh.is_empty());

        uh.add_selection(UserHighlightSelection {
            address: 0x1000,
            color: "#FF0000".into(),
            is_equate: false,
            equate_name: None,
        });
        assert_eq!(uh.len(), 1);
    }

    #[test]
    fn name_token_matcher_exact() {
        let matcher = NameTokenMatcher::new("main");
        assert!(matcher.matches("main", SyntaxType::Function));
        assert!(!matcher.matches("Main", SyntaxType::Function));
    }

    #[test]
    fn name_token_matcher_case_insensitive() {
        let mut matcher = NameTokenMatcher::new("main");
        matcher.case_sensitive = false;
        assert!(matcher.matches("Main", SyntaxType::Function));
        assert!(matcher.matches("MAIN", SyntaxType::Function));
    }

    #[test]
    fn name_token_matcher_syntax_filter() {
        let mut matcher = NameTokenMatcher::new("x");
        matcher.syntax_filter.push(SyntaxType::Variable);
        assert!(matcher.matches("x", SyntaxType::Variable));
        assert!(!matcher.matches("x", SyntaxType::Keyword));
    }

    #[test]
    fn highlight_controller_basics() {
        let mut hc = ClangHighlightController::new();
        assert!(hc.matched_token().is_none());
        assert!(hc.cursor_token().is_none());

        hc.set_matched_token(Some(5));
        assert_eq!(hc.matched_token(), Some(5));

        hc.set_cursor_token(Some(10));
        assert_eq!(hc.cursor_token(), Some(10));

        hc.clear_all();
        assert!(hc.matched_token().is_none());
    }

    #[test]
    fn layout_controller_indent() {
        let mut lc = ClangLayoutController::new();
        assert_eq!(lc.indent_level(), 0);
        assert_eq!(lc.current_indent(), "");

        lc.indent();
        assert_eq!(lc.indent_level(), 1);
        assert_eq!(lc.current_indent(), "    ");

        lc.indent();
        assert_eq!(lc.current_indent(), "        ");

        lc.outdent();
        assert_eq!(lc.indent_level(), 1);

        lc.outdent();
        lc.outdent(); // Should not go below 0
        assert_eq!(lc.indent_level(), 0);
    }

    #[test]
    fn layout_controller_line_numbers() {
        let mut lc = ClangLayoutController::new();
        assert_eq!(lc.line_number(), 0);
        assert_eq!(lc.next_line(), 0);
        assert_eq!(lc.line_number(), 1);
        assert_eq!(lc.next_line(), 1);
    }

    #[test]
    fn clang_text_field() {
        let tf = ClangTextField::new(0, 2, "int x");
        assert_eq!(tf.column, 0);
        assert_eq!(tf.column_span, 2);
        assert_eq!(tf.text, "int x");
        assert_eq!(tf.char_count(), 5);
        assert!(!tf.is_empty());
    }

    #[test]
    fn default_color_provider() {
        let cp = DefaultColorProvider;
        assert_eq!(cp.get_color(SyntaxType::Keyword), "#0000FF");
        assert_eq!(cp.get_color(SyntaxType::Comment), "#808080");
        assert_eq!(cp.get_color(SyntaxType::Error), "#FF0000");
        assert!(cp.get_background_color(SyntaxType::Default).is_none());
    }

    #[test]
    fn decompile_data_lifecycle() {
        let mut dd = DecompileData::new(0x1000);
        assert!(!dd.has_results());
        assert_eq!(dd.function_entry, 0x1000);

        let mut arena = ClangNodeArena::new();
        let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        dd.set_results(arena, root, Some("main".to_string()));
        assert!(dd.has_results());
        assert_eq!(dd.function_name.as_deref(), Some("main"));

        dd.set_error("timeout");
        assert!(!dd.has_results());
        assert!(dd.error_message.is_some());
    }

    #[test]
    fn decompiler_controller_default() {
        let ctrl = DecompilerController::new();
        assert!(ctrl.data().is_none());
        assert!(ctrl.is_editable());
    }

    #[test]
    fn clang_field_element() {
        let fe = ClangFieldElement::new(2, 5, 10);
        assert_eq!(fe.column_span(), 3);
        assert_eq!(fe.line_index, 10);
    }

    #[test]
    fn panel_line_creation() {
        let pl = PanelLine::new(42, 2);
        assert_eq!(pl.line_index, 42);
        assert_eq!(pl.indent_level, 2);
        assert!(pl.fields.is_empty());
    }

    #[test]
    fn panel_token_creation() {
        let pt = PanelToken::new(0, "int", SyntaxType::Keyword);
        assert_eq!(pt.token_id, 0);
        assert_eq!(pt.text, "int");
        assert_eq!(pt.syntax_type, SyntaxType::Keyword);
    }
}
