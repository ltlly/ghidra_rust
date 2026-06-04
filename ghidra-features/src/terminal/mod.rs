//! Terminal emulator plugin for VT100-compatible terminal display.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.terminal` package.
//!
//! Provides a VT100 terminal emulator embedded in Ghidra, used by
//! the debugger and other components that need to display terminal
//! output. Supports ANSI escape sequences, scrolling, and searching.
//!
//! # Key Types
//!
//! - [`TerminalPlugin`] -- Plugin providing terminal instances
//! - [`TerminalState`] -- The state of a terminal's display buffer
//! - [`TerminalCell`] -- A single cell in the terminal grid
//! - [`TerminalColor`] -- ANSI color representation
//! - [`TerminalFindOptions`] -- Options for text search in the terminal

use std::collections::VecDeque;

/// Default terminal width in columns.
pub const DEFAULT_WIDTH: usize = 80;

/// Default terminal height in rows.
pub const DEFAULT_HEIGHT: usize = 24;

/// Maximum scrollback buffer lines.
pub const MAX_SCROLLBACK: usize = 10_000;

// ---------------------------------------------------------------------------
// Terminal color
// ---------------------------------------------------------------------------

/// ANSI terminal colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalColor {
    /// Default foreground/background.
    Default,
    /// Standard black (0).
    Black,
    /// Standard red (1).
    Red,
    /// Standard green (2).
    Green,
    /// Standard yellow (3).
    Yellow,
    /// Standard blue (4).
    Blue,
    /// Standard magenta (5).
    Magenta,
    /// Standard cyan (6).
    Cyan,
    /// Standard white (7).
    White,
    /// Bright black (8) -- typically dark gray.
    BrightBlack,
    /// Bright red (9).
    BrightRed,
    /// Bright green (10).
    BrightGreen,
    /// Bright yellow (11).
    BrightYellow,
    /// Bright blue (12).
    BrightBlue,
    /// Bright magenta (13).
    BrightMagenta,
    /// Bright cyan (14).
    BrightCyan,
    /// Bright white (15).
    BrightWhite,
    /// 256-color palette index.
    Indexed(u8),
    /// 24-bit true color (R, G, B).
    Rgb(u8, u8, u8),
}

impl TerminalColor {
    /// Convert to an RGB hex value (0xRRGGBB), using standard ANSI colors.
    pub fn to_rgb(&self) -> u32 {
        match self {
            Self::Default => 0xD4D4D4,
            Self::Black => 0x000000,
            Self::Red => 0xCD3131,
            Self::Green => 0x0DBC79,
            Self::Yellow => 0xE5E510,
            Self::Blue => 0x2472C8,
            Self::Magenta => 0xBC3FBC,
            Self::Cyan => 0x11A8CD,
            Self::White => 0xE5E5E5,
            Self::BrightBlack => 0x666666,
            Self::BrightRed => 0xF14C4C,
            Self::BrightGreen => 0x23D18B,
            Self::BrightYellow => 0xF5F543,
            Self::BrightBlue => 0x3B8EEA,
            Self::BrightMagenta => 0xD670D6,
            Self::BrightCyan => 0x29B8DB,
            Self::BrightWhite => 0xFFFFFF,
            Self::Indexed(_) => 0xD4D4D4, // simplified
            Self::Rgb(r, g, b) => ((*r as u32) << 16) | ((*g as u32) << 8) | (*b as u32),
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal cell
// ---------------------------------------------------------------------------

/// A single character cell in the terminal grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalCell {
    /// The character to display.
    pub ch: char,
    /// Foreground color.
    pub foreground: TerminalColor,
    /// Background color.
    pub background: TerminalColor,
    /// Bold attribute.
    pub bold: bool,
    /// Italic attribute.
    pub italic: bool,
    /// Underline attribute.
    pub underline: bool,
    /// Strikethrough attribute.
    pub strikethrough: bool,
    /// Reverse video attribute.
    pub reverse: bool,
}

impl Default for TerminalCell {
    fn default() -> Self {
        Self {
            ch: ' ',
            foreground: TerminalColor::Default,
            background: TerminalColor::Default,
            bold: false,
            italic: false,
            underline: false,
            strikethrough: false,
            reverse: false,
        }
    }
}

impl TerminalCell {
    /// Create a plain cell with a character.
    pub fn new(ch: char) -> Self {
        Self {
            ch,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal find options
// ---------------------------------------------------------------------------

/// Options for text search in the terminal.
///
/// Ported from `TerminalPanel.FindOptions`.
#[derive(Debug, Clone)]
pub struct TerminalFindOptions {
    /// The search string.
    pub pattern: String,
    /// Whether the search is case-sensitive.
    pub case_sensitive: bool,
    /// Whether to match whole words only.
    pub whole_word: bool,
    /// Whether to use regular expressions.
    pub regex: bool,
    /// Whether to search backwards.
    pub backwards: bool,
}

impl Default for TerminalFindOptions {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            case_sensitive: false,
            whole_word: false,
            regex: false,
            backwards: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal state
// ---------------------------------------------------------------------------

/// The state of a terminal display buffer.
///
/// Ported from the `DefaultTerminal` class.
#[derive(Debug)]
pub struct TerminalState {
    /// The visible grid of cells (width x height).
    grid: Vec<Vec<TerminalCell>>,
    /// Scrollback buffer.
    scrollback: VecDeque<Vec<TerminalCell>>,
    /// Terminal width in columns.
    pub width: usize,
    /// Terminal height in rows.
    pub height: usize,
    /// Current cursor column.
    pub cursor_col: usize,
    /// Current cursor row.
    pub cursor_row: usize,
    /// Whether the cursor is visible.
    pub cursor_visible: bool,
}

impl TerminalState {
    /// Create a new terminal state with the given dimensions.
    pub fn new(width: usize, height: usize) -> Self {
        let grid = vec![vec![TerminalCell::default(); width]; height];
        Self {
            grid,
            scrollback: VecDeque::new(),
            width,
            height,
            cursor_col: 0,
            cursor_row: 0,
            cursor_visible: true,
        }
    }

    /// Get the cell at the given position.
    pub fn cell(&self, row: usize, col: usize) -> Option<&TerminalCell> {
        self.grid.get(row)?.get(col)
    }

    /// Set a cell at the given position.
    pub fn set_cell(&mut self, row: usize, col: usize, cell: TerminalCell) {
        if let Some(r) = self.grid.get_mut(row) {
            if let Some(c) = r.get_mut(col) {
                *c = cell;
            }
        }
    }

    /// Write a character at the current cursor position and advance.
    pub fn write_char(&mut self, ch: char) {
        if self.cursor_row < self.height && self.cursor_col < self.width {
            self.grid[self.cursor_row][self.cursor_col] = TerminalCell::new(ch);
            self.cursor_col += 1;
            if self.cursor_col >= self.width {
                self.cursor_col = 0;
                self.cursor_row += 1;
            }
        }
    }

    /// Write a string at the current cursor position.
    pub fn write_str(&mut self, s: &str) {
        for ch in s.chars() {
            if ch == '\n' {
                self.newline();
            } else if ch == '\r' {
                self.cursor_col = 0;
            } else {
                self.write_char(ch);
            }
        }
    }

    /// Move to a new line.
    pub fn newline(&mut self) {
        self.cursor_col = 0;
        if self.cursor_row + 1 >= self.height {
            // Scroll: move first line to scrollback
            let line = self.grid.remove(0);
            if self.scrollback.len() >= MAX_SCROLLBACK {
                self.scrollback.pop_front();
            }
            self.scrollback.push_back(line);
            self.grid.push(vec![TerminalCell::default(); self.width]);
        } else {
            self.cursor_row += 1;
        }
    }

    /// Clear the entire screen.
    pub fn clear(&mut self) {
        for row in &mut self.grid {
            for cell in row.iter_mut() {
                *cell = TerminalCell::default();
            }
        }
        self.cursor_col = 0;
        self.cursor_row = 0;
    }

    /// Clear from cursor to end of line.
    pub fn clear_to_end_of_line(&mut self) {
        for col in self.cursor_col..self.width {
            self.grid[self.cursor_row][col] = TerminalCell::default();
        }
    }

    /// Get the scrollback buffer.
    pub fn scrollback(&self) -> &VecDeque<Vec<TerminalCell>> {
        &self.scrollback
    }

    /// Search for text in the visible buffer.
    pub fn find(&self, options: &TerminalFindOptions) -> Vec<(usize, usize)> {
        let mut results = Vec::new();
        let pattern = if options.case_sensitive {
            options.pattern.clone()
        } else {
            options.pattern.to_lowercase()
        };

        for (row, line) in self.grid.iter().enumerate() {
            let line_str: String = line.iter().map(|c| c.ch).collect();
            let haystack = if options.case_sensitive {
                line_str.clone()
            } else {
                line_str.to_lowercase()
            };

            let mut start = 0;
            while let Some(pos) = haystack[start..].find(&pattern) {
                results.push((row, start + pos));
                start += pos + 1;
            }
        }

        results
    }
}

// ---------------------------------------------------------------------------
// Terminal plugin
// ---------------------------------------------------------------------------

/// Plugin providing terminal emulator instances.
///
/// Ported from `ghidra.app.plugin.core.terminal.TerminalPlugin`.
#[derive(Debug)]
pub struct TerminalPlugin {
    /// Terminal instances.
    terminals: Vec<TerminalState>,
    /// Default dimensions for new terminals.
    default_width: usize,
    default_height: usize,
}

impl TerminalPlugin {
    /// Create a new terminal plugin.
    pub fn new() -> Self {
        Self {
            terminals: Vec::new(),
            default_width: DEFAULT_WIDTH,
            default_height: DEFAULT_HEIGHT,
        }
    }

    /// Create a new terminal instance.
    pub fn create_terminal(&mut self) -> usize {
        let terminal = TerminalState::new(self.default_width, self.default_height);
        self.terminals.push(terminal);
        self.terminals.len() - 1
    }

    /// Get a terminal by index.
    pub fn terminal(&self, index: usize) -> Option<&TerminalState> {
        self.terminals.get(index)
    }

    /// Get a mutable reference to a terminal by index.
    pub fn terminal_mut(&mut self, index: usize) -> Option<&mut TerminalState> {
        self.terminals.get_mut(index)
    }

    /// Number of terminal instances.
    pub fn terminal_count(&self) -> usize {
        self.terminals.len()
    }

    /// Close a terminal instance.
    pub fn close_terminal(&mut self, index: usize) -> bool {
        if index < self.terminals.len() {
            self.terminals.remove(index);
            true
        } else {
            false
        }
    }
}

impl Default for TerminalPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_color_rgb() {
        assert_eq!(TerminalColor::Black.to_rgb(), 0x000000);
        assert_eq!(TerminalColor::Red.to_rgb(), 0xCD3131);
        assert_eq!(TerminalColor::BrightWhite.to_rgb(), 0xFFFFFF);
        assert_eq!(TerminalColor::Rgb(0x12, 0x34, 0x56).to_rgb(), 0x123456);
    }

    #[test]
    fn test_terminal_cell_default() {
        let cell = TerminalCell::default();
        assert_eq!(cell.ch, ' ');
        assert!(!cell.bold);
        assert_eq!(cell.foreground, TerminalColor::Default);
    }

    #[test]
    fn test_terminal_state_creation() {
        let state = TerminalState::new(80, 24);
        assert_eq!(state.width, 80);
        assert_eq!(state.height, 24);
        assert_eq!(state.cursor_col, 0);
        assert_eq!(state.cursor_row, 0);
    }

    #[test]
    fn test_terminal_state_cell_access() {
        let mut state = TerminalState::new(10, 5);
        state.set_cell(2, 3, TerminalCell::new('X'));
        assert_eq!(state.cell(2, 3).unwrap().ch, 'X');
        assert_eq!(state.cell(0, 0).unwrap().ch, ' ');
    }

    #[test]
    fn test_terminal_state_write_char() {
        let mut state = TerminalState::new(5, 3);
        state.write_char('H');
        state.write_char('i');
        assert_eq!(state.cell(0, 0).unwrap().ch, 'H');
        assert_eq!(state.cell(0, 1).unwrap().ch, 'i');
        assert_eq!(state.cursor_col, 2);
    }

    #[test]
    fn test_terminal_state_write_str() {
        let mut state = TerminalState::new(20, 5);
        state.write_str("Hello\nWorld");
        assert_eq!(state.cell(0, 0).unwrap().ch, 'H');
        assert_eq!(state.cell(1, 0).unwrap().ch, 'W');
        assert_eq!(state.cursor_row, 1);
    }

    #[test]
    fn test_terminal_state_newline_scroll() {
        let mut state = TerminalState::new(10, 2);
        state.write_str("Line1\nLine2\nLine3");
        // After 3 newlines on a 2-row terminal, Line1 should be in scrollback
        assert_eq!(state.scrollback().len(), 1);
        assert_eq!(state.cell(0, 0).unwrap().ch, 'L'); // Line2
        assert_eq!(state.cell(1, 0).unwrap().ch, 'L'); // Line3
    }

    #[test]
    fn test_terminal_state_clear() {
        let mut state = TerminalState::new(5, 3);
        state.write_str("Test");
        state.clear();
        assert_eq!(state.cursor_col, 0);
        assert_eq!(state.cursor_row, 0);
        assert_eq!(state.cell(0, 0).unwrap().ch, ' ');
    }

    #[test]
    fn test_terminal_state_find() {
        let mut state = TerminalState::new(20, 5);
        state.write_str("Hello World\nHello Again");

        let opts = TerminalFindOptions {
            pattern: "Hello".into(),
            case_sensitive: true,
            ..Default::default()
        };
        let results = state.find(&opts);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], (0, 0));
        assert_eq!(results[1], (1, 0));
    }

    #[test]
    fn test_terminal_find_case_insensitive() {
        let mut state = TerminalState::new(20, 5);
        state.write_str("hello WORLD");

        let opts = TerminalFindOptions {
            pattern: "Hello".into(),
            case_sensitive: false,
            ..Default::default()
        };
        assert_eq!(state.find(&opts).len(), 1);
    }

    #[test]
    fn test_terminal_plugin() {
        let mut plugin = TerminalPlugin::new();
        assert_eq!(plugin.terminal_count(), 0);

        let idx = plugin.create_terminal();
        assert_eq!(plugin.terminal_count(), 1);
        assert!(plugin.terminal(idx).is_some());

        plugin.close_terminal(idx);
        assert_eq!(plugin.terminal_count(), 0);
    }
}
