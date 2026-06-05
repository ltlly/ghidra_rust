//! Code browser listing display model.
//!
//! Ported from `ghidra.app.plugin.core.codebrowser.CodeBrowserModel`.
//!
//! Manages the display state of the code browser listing, including
//! the current program, cursor position, view range, field formatting,
//! and address-to-display mapping.

/// Display options for the code browser listing.
#[derive(Debug, Clone)]
pub struct ListingDisplayOptions {
    /// Whether to show bytes column.
    pub show_bytes: bool,
    /// Whether to show address column.
    pub show_address: bool,
    /// Whether to show EOL comments.
    pub show_eol_comments: bool,
    /// Whether to show plate comments.
    pub show_plate_comments: bool,
    /// Whether to show repeatable comments.
    pub show_repeatable_comments: bool,
    /// Whether to show pre-comments.
    pub show_pre_comments: bool,
    /// Whether to show post-comments.
    pub show_post_comments: bool,
    /// Highlight cursor line.
    pub highlight_cursor_line: bool,
    /// Selection color (ARGB).
    pub selection_color: u32,
    /// Highlight color (ARGB).
    pub highlight_color: u32,
    /// Cursor color (ARGB).
    pub cursor_color: u32,
}

impl Default for ListingDisplayOptions {
    fn default() -> Self {
        Self {
            show_bytes: true,
            show_address: true,
            show_eol_comments: true,
            show_plate_comments: true,
            show_repeatable_comments: true,
            show_pre_comments: true,
            show_post_comments: true,
            highlight_cursor_line: true,
            selection_color: 0xFF_33_66_99,
            highlight_color: 0xFF_FF_FF_00,
            cursor_color: 0xFF_00_00_FF,
        }
    }
}

/// State of the cursor in the listing.
#[derive(Debug, Clone, Default)]
pub struct CursorState {
    /// The current address.
    pub address: u64,
    /// The row within the field (0-based).
    pub row: usize,
    /// The col within the field (0-based).
    pub col: usize,
    /// Whether the cursor is on a valid code unit.
    pub on_code_unit: bool,
}

/// A memento that captures the listing view state for later restoration.
#[derive(Debug, Clone)]
pub struct ListingMemento {
    /// The cursor address.
    pub cursor_address: u64,
    /// The top-of-view address.
    pub top_address: u64,
    /// The program name.
    pub program_name: String,
}

impl ListingMemento {
    pub fn new(cursor_address: u64, top_address: u64, program_name: impl Into<String>) -> Self {
        Self {
            cursor_address,
            top_address,
            program_name: program_name.into(),
        }
    }
}

/// The code browser listing display model.
#[derive(Debug)]
pub struct ListingModel {
    /// Current display options.
    options: ListingDisplayOptions,
    /// Current cursor state.
    cursor: CursorState,
    /// View start address (top of visible area).
    view_start: u64,
    /// View end address (bottom of visible area).
    view_end: u64,
    /// Whether the model has a valid program loaded.
    has_program: bool,
    /// Saved mementos.
    memento_stack: Vec<ListingMemento>,
}

impl ListingModel {
    pub fn new() -> Self {
        Self {
            options: ListingDisplayOptions::default(),
            cursor: CursorState::default(),
            view_start: 0,
            view_end: 0,
            has_program: false,
            memento_stack: Vec::new(),
        }
    }

    pub fn options(&self) -> &ListingDisplayOptions {
        &self.options
    }

    pub fn options_mut(&mut self) -> &mut ListingDisplayOptions {
        &mut self.options
    }

    pub fn cursor(&self) -> &CursorState {
        &self.cursor
    }

    pub fn set_cursor(&mut self, address: u64, row: usize, col: usize) {
        self.cursor.address = address;
        self.cursor.row = row;
        self.cursor.col = col;
    }

    pub fn view_range(&self) -> (u64, u64) {
        (self.view_start, self.view_end)
    }

    pub fn set_view_range(&mut self, start: u64, end: u64) {
        self.view_start = start;
        self.view_end = end;
    }

    pub fn has_program(&self) -> bool {
        self.has_program
    }

    pub fn set_program_loaded(&mut self, loaded: bool) {
        self.has_program = loaded;
    }

    pub fn save_memento(&mut self, program_name: impl Into<String>) {
        let m = ListingMemento::new(self.cursor.address, self.view_start, program_name);
        self.memento_stack.push(m);
    }

    pub fn restore_memento(&mut self) -> Option<ListingMemento> {
        let m = self.memento_stack.pop();
        if let Some(ref memento) = m {
            self.cursor.address = memento.cursor_address;
            self.view_start = memento.top_address;
        }
        m
    }

    pub fn has_mementos(&self) -> bool {
        !self.memento_stack.is_empty()
    }
}

impl Default for ListingModel {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listing_model_new() {
        let model = ListingModel::new();
        assert!(!model.has_program());
        assert!(model.options().show_bytes);
        assert!(!model.has_mementos());
    }

    #[test]
    fn test_cursor_state() {
        let mut model = ListingModel::new();
        model.set_cursor(0x1000, 2, 5);
        assert_eq!(model.cursor().address, 0x1000);
        assert_eq!(model.cursor().row, 2);
        assert_eq!(model.cursor().col, 5);
    }

    #[test]
    fn test_view_range() {
        let mut model = ListingModel::new();
        model.set_view_range(0x1000, 0x2000);
        assert_eq!(model.view_range(), (0x1000, 0x2000));
    }

    #[test]
    fn test_memento() {
        let mut model = ListingModel::new();
        model.set_cursor(0x1000, 0, 0);
        model.set_view_range(0x1000, 0x2000);
        model.save_memento("test_program");
        assert!(model.has_mementos());
        model.set_cursor(0x5000, 0, 0);
        let m = model.restore_memento();
        assert!(m.is_some());
        assert_eq!(model.cursor().address, 0x1000);
    }

    #[test]
    fn test_display_options() {
        let mut model = ListingModel::new();
        model.options_mut().show_bytes = false;
        assert!(!model.options().show_bytes);
    }
}
