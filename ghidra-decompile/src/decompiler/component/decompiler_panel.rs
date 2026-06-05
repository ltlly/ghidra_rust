//! Decompiler panel data structures -- the main display area.
//!
//! Port of Ghidra's `ghidra.app.decompiler.component.DecompilerPanel`.
//!
//! The DecompilerPanel is the central display area that renders the
//! decompiled C code with syntax highlighting, cursor tracking,
//! and token selection. This module provides the data structures
//! for managing the panel's state without Swing/AWT dependencies.

use super::super::clang_node::{ClangNodeId, SyntaxType};
use super::clang_decompiler_highlighter::ClangDecompilerHighlighter;
use super::layout_pixel_index_map::{LayoutPixelIndexMap, VerticalLayoutPixelIndexMap};

/// Cursor position in the decompiler panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorPosition {
    /// Line number (0-indexed).
    pub line: usize,
    /// Column within the line (0-indexed, character position).
    pub column: usize,
    /// The ClangNodeId at the cursor (if any).
    pub node_id: Option<ClangNodeId>,
}

impl CursorPosition {
    /// Create a new cursor position.
    pub fn new(line: usize, column: usize) -> Self {
        Self {
            line,
            column,
            node_id: None,
        }
    }

    /// Create a cursor position with an associated node.
    pub fn with_node(line: usize, column: usize, node_id: ClangNodeId) -> Self {
        Self {
            line,
            column,
            node_id: Some(node_id),
        }
    }
}

impl Default for CursorPosition {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Selection range in the decompiler panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionRange {
    /// Start of the selection.
    pub start: CursorPosition,
    /// End of the selection.
    pub end: CursorPosition,
}

impl SelectionRange {
    /// Create a new selection range.
    pub fn new(start: CursorPosition, end: CursorPosition) -> Self {
        Self { start, end }
    }

    /// Whether the selection is empty (start == end).
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Get the normalized start (earlier position).
    pub fn normalized_start(&self) -> CursorPosition {
        if self.start.line < self.end.line
            || (self.start.line == self.end.line && self.start.column <= self.end.column)
        {
            self.start
        } else {
            self.end
        }
    }

    /// Get the normalized end (later position).
    pub fn normalized_end(&self) -> CursorPosition {
        if self.start.line < self.end.line
            || (self.start.line == self.end.line && self.start.column <= self.end.column)
        {
            self.end
        } else {
            self.start
        }
    }

    /// Whether the selection contains a given line.
    pub fn contains_line(&self, line: usize) -> bool {
        let ns = self.normalized_start();
        let ne = self.normalized_end();
        line >= ns.line && line <= ne.line
    }
}

/// A display token in the decompiler panel with its visual properties.
#[derive(Debug, Clone)]
pub struct DisplayToken {
    /// The text content of the token.
    pub text: String,
    /// The ClangNodeId of the token in the AST.
    pub node_id: ClangNodeId,
    /// The syntax type for coloring.
    pub syntax_type: SyntaxType,
    /// The line number.
    pub line: usize,
    /// The starting column (character offset within the line).
    pub column_start: usize,
    /// The ending column (exclusive).
    pub column_end: usize,
    /// Whether this token is highlighted.
    pub highlighted: bool,
    /// The highlight color (if highlighted).
    pub highlight_color: Option<String>,
}

impl DisplayToken {
    /// Create a new display token.
    pub fn new(
        text: String,
        node_id: ClangNodeId,
        syntax_type: SyntaxType,
        line: usize,
        column_start: usize,
    ) -> Self {
        let column_end = column_start + text.len();
        Self {
            text,
            node_id,
            syntax_type,
            line,
            column_start,
            column_end,
            highlighted: false,
            highlight_color: None,
        }
    }

    /// Get the length of this token in characters.
    pub fn char_len(&self) -> usize {
        self.column_end - self.column_start
    }

    /// Check if a column position falls within this token.
    pub fn contains_column(&self, col: usize) -> bool {
        col >= self.column_start && col < self.column_end
    }
}

/// The decompiler panel state.
///
/// Manages the display content, cursor, selection, and highlighting
/// for the decompiler panel.
#[derive(Debug, Clone)]
pub struct DecompilerPanelState {
    /// The display tokens organized by line.
    lines: Vec<Vec<DisplayToken>>,
    /// Current cursor position.
    cursor: CursorPosition,
    /// Current selection (if any).
    selection: Option<SelectionRange>,
    /// The highlighter for applying highlights.
    highlighter: ClangDecompilerHighlighter,
    /// Pixel index map for converting between pixels and lines.
    pixel_map: VerticalLayoutPixelIndexMap,
    /// Whether word wrap is enabled.
    word_wrap: bool,
    /// Font size in points.
    font_size: f32,
    /// Line height in pixels.
    line_height: i32,
}

impl DecompilerPanelState {
    /// Create a new panel state.
    pub fn new() -> Self {
        Self {
            lines: Vec::new(),
            cursor: CursorPosition::default(),
            selection: None,
            highlighter: ClangDecompilerHighlighter::new(),
            pixel_map: VerticalLayoutPixelIndexMap::new(2),
            word_wrap: true,
            font_size: 12.0,
            line_height: 16,
        }
    }

    /// Set the display content (organized by lines of tokens).
    pub fn set_content(&mut self, lines: Vec<Vec<DisplayToken>>) {
        self.lines = lines;
        self.rebuild_pixel_map();
    }

    /// Get the number of display lines.
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Get the tokens for a specific line.
    pub fn line_tokens(&self, line: usize) -> Option<&[DisplayToken]> {
        self.lines.get(line).map(|v| v.as_slice())
    }

    /// Get the current cursor position.
    pub fn cursor(&self) -> CursorPosition {
        self.cursor
    }

    /// Set the cursor position.
    pub fn set_cursor(&mut self, pos: CursorPosition) {
        self.cursor = pos;
    }

    /// Move the cursor to a specific line and column.
    pub fn move_cursor(&mut self, line: usize, column: usize) {
        self.cursor = CursorPosition::new(line, column);
        // Try to find the ClangNodeId at this position.
        if let Some(tokens) = self.lines.get(line) {
            for token in tokens {
                if token.contains_column(column) {
                    self.cursor.node_id = Some(token.node_id);
                    break;
                }
            }
        }
    }

    /// Get the current selection.
    pub fn selection(&self) -> Option<&SelectionRange> {
        self.selection.as_ref()
    }

    /// Set the selection.
    pub fn set_selection(&mut self, selection: Option<SelectionRange>) {
        self.selection = selection;
    }

    /// Select a range of text.
    pub fn select_range(&mut self, start: CursorPosition, end: CursorPosition) {
        self.selection = Some(SelectionRange::new(start, end));
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selection = None;
    }

    /// Get the highlighter.
    pub fn highlighter(&self) -> &ClangDecompilerHighlighter {
        &self.highlighter
    }

    /// Get a mutable reference to the highlighter.
    pub fn highlighter_mut(&mut self) -> &mut ClangDecompilerHighlighter {
        &mut self.highlighter
    }

    /// Get the pixel index map.
    pub fn pixel_map(&self) -> &VerticalLayoutPixelIndexMap {
        &self.pixel_map
    }

    /// Convert a pixel Y position to a line number.
    pub fn pixel_to_line(&self, y_pixel: i32) -> usize {
        self.pixel_map.pixel_to_index(y_pixel)
    }

    /// Convert a line number to a pixel Y position.
    pub fn line_to_pixel(&self, line: usize) -> i32 {
        self.pixel_map.index_to_pixel(line)
    }

    /// Whether word wrap is enabled.
    pub fn word_wrap(&self) -> bool {
        self.word_wrap
    }

    /// Set word wrap.
    pub fn set_word_wrap(&mut self, enabled: bool) {
        self.word_wrap = enabled;
    }

    /// Get the font size.
    pub fn font_size(&self) -> f32 {
        self.font_size
    }

    /// Set the font size.
    pub fn set_font_size(&mut self, size: f32) {
        self.font_size = size;
    }

    /// Get the line height.
    pub fn line_height(&self) -> i32 {
        self.line_height
    }

    /// Set the line height.
    pub fn set_line_height(&mut self, height: i32) {
        self.line_height = height;
        self.rebuild_pixel_map();
    }

    /// Get the token at the cursor position.
    pub fn token_at_cursor(&self) -> Option<&DisplayToken> {
        let line = self.cursor.line;
        let col = self.cursor.column;
        self.lines.get(line).and_then(|tokens| {
            tokens.iter().find(|t| t.contains_column(col))
        })
    }

    /// Get all tokens with a specific ClangNodeId.
    pub fn tokens_with_node_id(&self, node_id: ClangNodeId) -> Vec<&DisplayToken> {
        self.lines
            .iter()
            .flatten()
            .filter(|t| t.node_id == node_id)
            .collect()
    }

    /// Get the total number of tokens.
    pub fn total_token_count(&self) -> usize {
        self.lines.iter().map(|l| l.len()).sum()
    }

    /// Get the total text character count.
    pub fn total_char_count(&self) -> usize {
        self.lines
            .iter()
            .flatten()
            .map(|t| t.text.len())
            .sum()
    }

    fn rebuild_pixel_map(&mut self) {
        self.pixel_map = VerticalLayoutPixelIndexMap::new(2);
        for _ in 0..self.lines.len() {
            self.pixel_map.add_line(self.line_height);
        }
    }
}

impl Default for DecompilerPanelState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_token(text: &str, node_id: ClangNodeId, line: usize, col: usize) -> DisplayToken {
        DisplayToken::new(
            text.to_string(),
            node_id,
            SyntaxType::Default,
            line,
            col,
        )
    }

    #[test]
    fn test_panel_state_default() {
        let state = DecompilerPanelState::new();
        assert_eq!(state.line_count(), 0);
        assert_eq!(state.cursor(), CursorPosition::new(0, 0));
        assert!(state.selection().is_none());
        assert!(state.word_wrap());
    }

    #[test]
    fn test_panel_set_content() {
        let mut state = DecompilerPanelState::new();
        let lines = vec![
            vec![make_test_token("int", 1, 0, 0), make_test_token(" x", 2, 0, 3)],
            vec![make_test_token("return", 3, 1, 0)],
        ];
        state.set_content(lines);
        assert_eq!(state.line_count(), 2);
        assert_eq!(state.total_token_count(), 3);
    }

    #[test]
    fn test_panel_cursor() {
        let mut state = DecompilerPanelState::new();
        let lines = vec![
            vec![make_test_token("int", 1, 0, 0)],
        ];
        state.set_content(lines);
        state.move_cursor(0, 1);
        assert_eq!(state.cursor().line, 0);
        assert_eq!(state.cursor().column, 1);
        assert_eq!(state.cursor().node_id, Some(1)); // "int" token
    }

    #[test]
    fn test_panel_selection() {
        let mut state = DecompilerPanelState::new();
        state.select_range(
            CursorPosition::new(0, 0),
            CursorPosition::new(1, 5),
        );
        let sel = state.selection().unwrap();
        assert_eq!(sel.normalized_start(), CursorPosition::new(0, 0));
        assert_eq!(sel.normalized_end(), CursorPosition::new(1, 5));
        assert!(sel.contains_line(0));
        assert!(sel.contains_line(1));
        assert!(!sel.contains_line(2));
    }

    #[test]
    fn test_panel_token_at_cursor() {
        let mut state = DecompilerPanelState::new();
        let lines = vec![
            vec![make_test_token("int", 1, 0, 0), make_test_token(" x", 2, 0, 3)],
        ];
        state.set_content(lines);
        state.move_cursor(0, 1); // Inside "int"
        let token = state.token_at_cursor().unwrap();
        assert_eq!(token.text, "int");
        assert_eq!(token.node_id, 1);
    }

    #[test]
    fn test_panel_tokens_with_node_id() {
        let mut state = DecompilerPanelState::new();
        let lines = vec![
            vec![
                DisplayToken::new("x".to_string(), 1, SyntaxType::Variable, 0, 0),
                DisplayToken::new(" = ".to_string(), 2, SyntaxType::Default, 0, 1),
                DisplayToken::new("x".to_string(), 1, SyntaxType::Variable, 0, 4),
            ],
        ];
        state.set_content(lines);
        let tokens = state.tokens_with_node_id(1);
        assert_eq!(tokens.len(), 2); // Both "x" tokens have node_id 1
    }

    #[test]
    fn test_display_token() {
        let token = DisplayToken::new("hello".to_string(), 5, SyntaxType::Keyword, 2, 10);
        assert_eq!(token.char_len(), 5);
        assert!(token.contains_column(10));
        assert!(token.contains_column(14));
        assert!(!token.contains_column(15));
        assert!(!token.contains_column(9));
    }

    #[test]
    fn test_selection_range() {
        let sel = SelectionRange::new(
            CursorPosition::new(5, 10),
            CursorPosition::new(2, 3),
        );
        assert_eq!(sel.normalized_start(), CursorPosition::new(2, 3));
        assert_eq!(sel.normalized_end(), CursorPosition::new(5, 10));
    }

    #[test]
    fn test_selection_empty() {
        let pos = CursorPosition::new(3, 7);
        let sel = SelectionRange::new(pos, pos);
        assert!(sel.is_empty());
    }

    #[test]
    fn test_cursor_with_node() {
        let pos = CursorPosition::with_node(1, 5, 42);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.column, 5);
        assert_eq!(pos.node_id, Some(42));
    }

    #[test]
    fn test_panel_pixel_conversion() {
        let mut state = DecompilerPanelState::new();
        let lines = vec![
            vec![make_test_token("line0", 0, 0, 0)],
            vec![make_test_token("line1", 1, 1, 0)],
            vec![make_test_token("line2", 2, 2, 0)],
        ];
        state.set_content(lines);
        assert_eq!(state.pixel_to_line(0), 0);
        assert_eq!(state.pixel_to_line(20), 1);
        assert_eq!(state.line_to_pixel(0), 0);
        assert_eq!(state.line_to_pixel(2), 36); // 2 * (16 + 2)
    }

    #[test]
    fn test_panel_font_size() {
        let mut state = DecompilerPanelState::new();
        assert_eq!(state.font_size(), 12.0);
        state.set_font_size(14.0);
        assert_eq!(state.font_size(), 14.0);
    }

    #[test]
    fn test_panel_word_wrap() {
        let mut state = DecompilerPanelState::new();
        assert!(state.word_wrap());
        state.set_word_wrap(false);
        assert!(!state.word_wrap());
    }

    #[test]
    fn test_panel_total_counts() {
        let mut state = DecompilerPanelState::new();
        let lines = vec![
            vec![make_test_token("ab", 1, 0, 0), make_test_token("cd", 2, 0, 2)],
            vec![make_test_token("ef", 3, 1, 0)],
        ];
        state.set_content(lines);
        assert_eq!(state.total_token_count(), 3);
        assert_eq!(state.total_char_count(), 6);
    }
}
