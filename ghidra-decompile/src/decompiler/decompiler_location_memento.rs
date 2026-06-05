//! Memento for saving and restoring decompiler location state.
//!
//! Ports `ghidra.app.plugin.core.decompile.DecompilerLocationMemento`.

/// Saved state of the decompiler cursor position and view.
///
/// Allows the user to save and restore their position within
/// decompiled code (e.g., for undo/redo navigation).
#[derive(Debug, Clone)]
pub struct DecompilerLocationMemento {
    /// The function entry address.
    pub function_entry: u64,
    /// The cursor offset within the decompiled text.
    pub cursor_offset: usize,
    /// The scroll position (line number).
    pub scroll_line: usize,
    /// The selected token text, if any.
    pub selected_token: Option<String>,
    /// The token's line number.
    pub token_line: Option<usize>,
    /// The token's column within the line.
    pub token_column: Option<usize>,
}

impl DecompilerLocationMemento {
    /// Create a new memento.
    pub fn new(function_entry: u64) -> Self {
        Self {
            function_entry,
            cursor_offset: 0,
            scroll_line: 0,
            selected_token: None,
            token_line: None,
            token_column: None,
        }
    }

    /// Set cursor position.
    pub fn with_cursor(mut self, offset: usize) -> Self {
        self.cursor_offset = offset;
        self
    }

    /// Set scroll position.
    pub fn with_scroll(mut self, line: usize) -> Self {
        self.scroll_line = line;
        self
    }

    /// Set selected token.
    pub fn with_token(mut self, text: &str, line: usize, column: usize) -> Self {
        self.selected_token = Some(text.to_string());
        self.token_line = Some(line);
        self.token_column = Some(column);
        self
    }

    /// Whether a token is selected in this memento.
    pub fn has_token(&self) -> bool {
        self.selected_token.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memento_creation() {
        let m = DecompilerLocationMemento::new(0x1000);
        assert_eq!(m.function_entry, 0x1000);
        assert_eq!(m.cursor_offset, 0);
        assert!(!m.has_token());
    }

    #[test]
    fn test_memento_builder() {
        let m = DecompilerLocationMemento::new(0x400000)
            .with_cursor(100)
            .with_scroll(5)
            .with_token("main", 3, 10);
        assert_eq!(m.cursor_offset, 100);
        assert_eq!(m.scroll_line, 5);
        assert!(m.has_token());
        assert_eq!(m.selected_token.as_deref(), Some("main"));
        assert_eq!(m.token_line, Some(3));
        assert_eq!(m.token_column, Some(10));
    }

    #[test]
    fn test_memento_clone() {
        let m = DecompilerLocationMemento::new(0x1000).with_cursor(42);
        let m2 = m.clone();
        assert_eq!(m2.cursor_offset, 42);
    }
}
