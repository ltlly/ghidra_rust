//! Composite editor action contexts.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor` context classes.
//!
//! Provides context objects that carry information about the current
//! editor state to action handlers.

/// The type of composite editor context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextType {
    /// Context from a standalone editor dialog.
    StandAlone,
    /// Context from a program-embedded editor.
    Program,
}

/// Context information for composite editor actions.
///
/// Carries the current selection, cursor position, and editor state
/// that actions need to determine what to operate on.
#[derive(Debug, Clone)]
pub struct CompositeEditorContext {
    /// The type of context.
    pub context_type: ContextType,
    /// The selected row indices.
    pub selected_rows: Vec<usize>,
    /// The cursor row index.
    pub cursor_row: Option<usize>,
    /// The column index of the cursor.
    pub cursor_column: Option<usize>,
    /// Whether the editor is currently in edit mode.
    pub in_edit_mode: bool,
    /// The name of the composite being edited.
    pub composite_name: String,
    /// Whether the composite is locked (fixed size).
    pub is_locked: bool,
    /// Whether the selection spans multiple rows.
    pub has_multi_selection: bool,
}

impl CompositeEditorContext {
    /// Create a new context.
    pub fn new(context_type: ContextType, composite_name: impl Into<String>) -> Self {
        Self {
            context_type,
            selected_rows: Vec::new(),
            cursor_row: None,
            cursor_column: None,
            in_edit_mode: false,
            composite_name: composite_name.into(),
            is_locked: false,
            has_multi_selection: false,
        }
    }

    /// Create a stand-alone context.
    pub fn stand_alone(composite_name: impl Into<String>) -> Self {
        Self::new(ContextType::StandAlone, composite_name)
    }

    /// Create a program context.
    pub fn program(composite_name: impl Into<String>) -> Self {
        Self::new(ContextType::Program, composite_name)
    }

    /// Set the selected rows.
    pub fn set_selection(&mut self, rows: Vec<usize>) {
        self.has_multi_selection = rows.len() > 1;
        self.selected_rows = rows;
    }

    /// Set the cursor position.
    pub fn set_cursor(&mut self, row: Option<usize>, column: Option<usize>) {
        self.cursor_row = row;
        self.cursor_column = column;
    }

    /// Whether the context has a valid selection.
    pub fn has_selection(&self) -> bool {
        !self.selected_rows.is_empty()
    }

    /// Whether the context has a single row selected.
    pub fn has_single_selection(&self) -> bool {
        self.selected_rows.len() == 1
    }

    /// Whether the context has a valid cursor position.
    pub fn has_cursor(&self) -> bool {
        self.cursor_row.is_some()
    }

    /// Whether this is a standalone context.
    pub fn is_standalone(&self) -> bool {
        self.context_type == ContextType::StandAlone
    }

    /// Whether this is a program context.
    pub fn is_program(&self) -> bool {
        self.context_type == ContextType::Program
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_new() {
        let ctx = CompositeEditorContext::stand_alone("MyStruct");
        assert_eq!(ctx.composite_name, "MyStruct");
        assert!(ctx.is_standalone());
        assert!(!ctx.is_program());
    }

    #[test]
    fn test_context_selection() {
        let mut ctx = CompositeEditorContext::program("S");
        ctx.set_selection(vec![0, 1, 2]);
        assert!(ctx.has_selection());
        assert!(!ctx.has_single_selection());
        assert!(ctx.has_multi_selection);
    }

    #[test]
    fn test_context_single_selection() {
        let mut ctx = CompositeEditorContext::stand_alone("S");
        ctx.set_selection(vec![3]);
        assert!(ctx.has_selection());
        assert!(ctx.has_single_selection());
        assert!(!ctx.has_multi_selection);
    }

    #[test]
    fn test_context_cursor() {
        let mut ctx = CompositeEditorContext::stand_alone("S");
        assert!(!ctx.has_cursor());
        ctx.set_cursor(Some(5), Some(1));
        assert!(ctx.has_cursor());
        assert_eq!(ctx.cursor_row, Some(5));
        assert_eq!(ctx.cursor_column, Some(1));
    }

    #[test]
    fn test_context_type() {
        let ctx1 = CompositeEditorContext::stand_alone("S");
        assert_eq!(ctx1.context_type, ContextType::StandAlone);
        let ctx2 = CompositeEditorContext::program("S");
        assert_eq!(ctx2.context_type, ContextType::Program);
    }
}
