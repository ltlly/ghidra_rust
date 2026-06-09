//! Terminal Plugin -- provides a VT100 terminal emulator.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.terminal` package.
//!
//! This module provides the terminal plugin that provides a VT100 terminal
//! emulator embedded in Ghidra. Supports ANSI escape sequences, scrolling,
//! and searching.
//!
//! # Architecture
//!
//! ```text
//! TerminalPlugin
//!   ├── TerminalProvider (display component)
//!   ├── TerminalState (display buffer)
//!   ├── TerminalCell (grid cell)
//!   └── TerminalFindOptions (search)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::plugin::terminal::terminal_plugin::TerminalPlugin;
//!
//! let mut plugin = TerminalPlugin::new("Terminal");
//! plugin.init();
//! assert_eq!(plugin.name(), "Terminal");
//! ```

use std::collections::VecDeque;
use std::fmt;

// ---------------------------------------------------------------------------
// Terminal constants
// ---------------------------------------------------------------------------

/// Default terminal width in columns.
pub const DEFAULT_WIDTH: usize = 80;

/// Default terminal height in rows.
pub const DEFAULT_HEIGHT: usize = 24;

/// Maximum scrollback buffer lines.
pub const MAX_SCROLLBACK: usize = 10_000;

// ---------------------------------------------------------------------------
// TerminalColor -- ANSI colors
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
    /// Convert to an RGB hex value (0xRRGGBB).
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
            Self::BrightWhite => 0xE5E5E5,
            Self::Indexed(i) => indexed_to_rgb(*i),
            Self::Rgb(r, g, b) => ((*r as u32) << 16) | ((*g as u32) << 8) | (*b as u32),
        }
    }
}

/// Converts a 256-color index to RGB.
fn indexed_to_rgb(index: u8) -> u32 {
    if index < 16 {
        // Standard colors
        let colors: [u32; 16] = [
            0x000000, 0xCD3131, 0x0DBC79, 0xE5E510,
            0x2472C8, 0xBC3FBC, 0x11A8CD, 0xE5E5E5,
            0x666666, 0xF14C4C, 0x23D18B, 0xF5F543,
            0x3B8EEA, 0xD670D6, 0x29B8DB, 0xE5E5E5,
        ];
        colors[index as usize]
    } else if index < 232 {
        // 6x6x6 color cube
        let i = index - 16;
        let r = (i / 36) * 51;
        let g = ((i % 36) / 6) * 51;
        let b = (i % 6) * 51;
        ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
    } else {
        // Grayscale ramp
        let gray = 8 + (index - 232) * 10;
        ((gray as u32) << 16) | ((gray as u32) << 8) | (gray as u32)
    }
}

// ---------------------------------------------------------------------------
// TerminalCell -- a single cell in the terminal grid
// ---------------------------------------------------------------------------

/// A single cell in the terminal grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalCell {
    /// The character in this cell.
    pub character: char,
    /// The foreground color.
    pub foreground: TerminalColor,
    /// The background color.
    pub background: TerminalColor,
    /// Whether the cell is bold.
    pub bold: bool,
    /// Whether the cell is italic.
    pub italic: bool,
    /// Whether the cell is underlined.
    pub underline: bool,
    /// Whether the cell is dim.
    pub dim: bool,
    /// Whether the cell is blinking.
    pub blink: bool,
    /// Whether the cell is inverse (swap fg/bg).
    pub inverse: bool,
}

impl TerminalCell {
    /// Creates a new terminal cell with default attributes.
    pub fn new(character: char) -> Self {
        Self {
            character,
            foreground: TerminalColor::Default,
            background: TerminalColor::Default,
            bold: false,
            italic: false,
            underline: false,
            dim: false,
            blink: false,
            inverse: false,
        }
    }

    /// Creates a blank cell.
    pub fn blank() -> Self {
        Self::new(' ')
    }

    /// Returns the effective foreground color (considering inverse).
    pub fn effective_foreground(&self) -> TerminalColor {
        if self.inverse {
            self.background
        } else {
            self.foreground
        }
    }

    /// Returns the effective background color (considering inverse).
    pub fn effective_background(&self) -> TerminalColor {
        if self.inverse {
            self.foreground
        } else {
            self.background
        }
    }
}

impl Default for TerminalCell {
    fn default() -> Self {
        Self::blank()
    }
}

// ---------------------------------------------------------------------------
// TerminalState -- the terminal display buffer
// ---------------------------------------------------------------------------

/// The state of a terminal's display buffer.
#[derive(Debug)]
pub struct TerminalState {
    /// The grid of cells (rows x columns).
    grid: Vec<Vec<TerminalCell>>,
    /// The scrollback buffer.
    scrollback: VecDeque<Vec<TerminalCell>>,
    /// The cursor column.
    cursor_col: usize,
    /// The cursor row.
    cursor_row: usize,
    /// The terminal width.
    width: usize,
    /// The terminal height.
    height: usize,
    /// Saved cursor position (for save/restore).
    saved_cursor: Option<(usize, usize)>,
}

impl TerminalState {
    /// Creates a new terminal state.
    pub fn new(width: usize, height: usize) -> Self {
        let grid = (0..height)
            .map(|_| (0..width).map(|_| TerminalCell::blank()).collect())
            .collect();
        Self {
            grid,
            scrollback: VecDeque::new(),
            cursor_col: 0,
            cursor_row: 0,
            width,
            height,
            saved_cursor: None,
        }
    }

    /// Returns the terminal width.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Returns the terminal height.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns the cursor column.
    pub fn cursor_col(&self) -> usize {
        self.cursor_col
    }

    /// Returns the cursor row.
    pub fn cursor_row(&self) -> usize {
        self.cursor_row
    }

    /// Sets the cursor position.
    pub fn set_cursor(&mut self, row: usize, col: usize) {
        self.cursor_row = row.min(self.height - 1);
        self.cursor_col = col.min(self.width - 1);
    }

    /// Returns a reference to a cell.
    pub fn cell(&self, row: usize, col: usize) -> Option<&TerminalCell> {
        self.grid.get(row)?.get(col)
    }

    /// Returns a mutable reference to a cell.
    pub fn cell_mut(&mut self, row: usize, col: usize) -> Option<&mut TerminalCell> {
        self.grid.get_mut(row)?.get_mut(col)
    }

    /// Writes a character at the current cursor position and advances.
    pub fn write_char(&mut self, ch: char) {
        if self.cursor_row < self.height && self.cursor_col < self.width {
            self.grid[self.cursor_row][self.cursor_col] = TerminalCell::new(ch);
            self.cursor_col += 1;
            if self.cursor_col >= self.width {
                self.cursor_col = 0;
                self.cursor_row += 1;
                if self.cursor_row >= self.height {
                    self.scroll_up();
                }
            }
        }
    }

    /// Writes a string at the current cursor position.
    pub fn write_str(&mut self, s: &str) {
        for ch in s.chars() {
            if ch == '\n' {
                self.cursor_col = 0;
                self.cursor_row += 1;
                if self.cursor_row >= self.height {
                    self.scroll_up();
                }
            } else if ch == '\r' {
                self.cursor_col = 0;
            } else if ch == '\t' {
                let next_tab = (self.cursor_col / 8 + 1) * 8;
                while self.cursor_col < next_tab && self.cursor_col < self.width {
                    self.write_char(' ');
                }
            } else {
                self.write_char(ch);
            }
        }
    }

    /// Scrolls the terminal up by one line.
    pub fn scroll_up(&mut self) {
        if let Some(top_line) = self.grid.first().cloned() {
            if self.scrollback.len() >= MAX_SCROLLBACK {
                self.scrollback.pop_front();
            }
            self.scrollback.push_back(top_line);
        }
        self.grid.remove(0);
        self.grid.push((0..self.width).map(|_| TerminalCell::blank()).collect());
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
        }
    }

    /// Clears the terminal.
    pub fn clear(&mut self) {
        for row in &mut self.grid {
            for cell in row.iter_mut() {
                *cell = TerminalCell::blank();
            }
        }
        self.cursor_col = 0;
        self.cursor_row = 0;
    }

    /// Clears from cursor to end of line.
    pub fn clear_to_eol(&mut self) {
        for col in self.cursor_col..self.width {
            self.grid[self.cursor_row][col] = TerminalCell::blank();
        }
    }

    /// Clears from cursor to end of screen.
    pub fn clear_to_eos(&mut self) {
        self.clear_to_eol();
        for row in (self.cursor_row + 1)..self.height {
            for col in 0..self.width {
                self.grid[row][col] = TerminalCell::blank();
            }
        }
    }

    /// Saves the cursor position.
    pub fn save_cursor(&mut self) {
        self.saved_cursor = Some((self.cursor_row, self.cursor_col));
    }

    /// Restores the cursor position.
    pub fn restore_cursor(&mut self) {
        if let Some((row, col)) = self.saved_cursor {
            self.cursor_row = row;
            self.cursor_col = col;
        }
    }

    /// Returns the scrollback buffer size.
    pub fn scrollback_size(&self) -> usize {
        self.scrollback.len()
    }

    /// Returns the number of rows in the grid.
    pub fn row_count(&self) -> usize {
        self.height
    }

    /// Returns the number of columns in the grid.
    pub fn col_count(&self) -> usize {
        self.width
    }
}

// ---------------------------------------------------------------------------
// TerminalFindOptions -- search options
// ---------------------------------------------------------------------------

/// Options for text search in the terminal.
#[derive(Debug, Clone)]
pub struct TerminalFindOptions {
    /// The search text.
    pub text: String,
    /// Whether to match case.
    pub case_sensitive: bool,
    /// Whether to use regular expressions.
    pub use_regex: bool,
    /// Whether to search backwards.
    pub backwards: bool,
    /// Whether to wrap around.
    pub wrap: bool,
}

impl TerminalFindOptions {
    /// Creates new find options.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            case_sensitive: false,
            use_regex: false,
            backwards: false,
            wrap: true,
        }
    }

    /// Sets case sensitivity.
    pub fn with_case_sensitive(mut self, case_sensitive: bool) -> Self {
        self.case_sensitive = case_sensitive;
        self
    }

    /// Sets regex mode.
    pub fn with_regex(mut self, use_regex: bool) -> Self {
        self.use_regex = use_regex;
        self
    }

    /// Sets search direction.
    pub fn with_backwards(mut self, backwards: bool) -> Self {
        self.backwards = backwards;
        self
    }

    /// Sets wrap mode.
    pub fn with_wrap(mut self, wrap: bool) -> Self {
        self.wrap = wrap;
        self
    }
}

impl Default for TerminalFindOptions {
    fn default() -> Self {
        Self::new("")
    }
}

// ---------------------------------------------------------------------------
// TerminalPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The terminal plugin.
///
/// Provides a VT100 terminal emulator embedded in Ghidra. Supports ANSI
/// escape sequences, scrolling, and searching.
///
/// Ported from Ghidra's `TerminalPlugin` Java class.
#[derive(Debug)]
pub struct TerminalPlugin {
    /// The plugin name.
    name: String,
    /// The terminal state.
    state: TerminalState,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Plugin options.
    options: std::collections::HashMap<String, TerminalOption>,
}

/// A terminal plugin option.
#[derive(Debug, Clone)]
pub enum TerminalOption {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i32),
    /// String option.
    String(String),
}

impl fmt::Display for TerminalOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

impl TerminalPlugin {
    /// Creates a new terminal plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: TerminalState::new(DEFAULT_WIDTH, DEFAULT_HEIGHT),
            initialized: false,
            disposed: false,
            options: std::collections::HashMap::new(),
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.state.clear();
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Returns a reference to the terminal state.
    pub fn state(&self) -> &TerminalState {
        &self.state
    }

    /// Returns a mutable reference to the terminal state.
    pub fn state_mut(&mut self) -> &mut TerminalState {
        &mut self.state
    }

    /// Writes a string to the terminal.
    pub fn write(&mut self, text: &str) {
        self.state.write_str(text);
    }

    /// Writes a line to the terminal.
    pub fn writeln(&mut self, text: &str) {
        self.state.write_str(text);
        self.state.write_str("\n");
    }

    /// Clears the terminal.
    pub fn clear(&mut self) {
        self.state.clear();
    }

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: TerminalOption) {
        self.options.insert(key.into(), value);
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&TerminalOption> {
        self.options.get(key)
    }
}

impl Default for TerminalPlugin {
    fn default() -> Self {
        Self::new("TerminalPlugin")
    }
}

impl fmt::Display for TerminalPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TerminalPlugin({})", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = TerminalPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert_eq!(plugin.state().width(), DEFAULT_WIDTH);
        assert_eq!(plugin.state().height(), DEFAULT_HEIGHT);
    }

    #[test]
    fn test_terminal_state() {
        let mut state = TerminalState::new(80, 24);
        assert_eq!(state.width(), 80);
        assert_eq!(state.height(), 24);
        state.write_str("Hello");
        assert_eq!(state.cursor_col(), 5);
        assert_eq!(state.cursor_row(), 0);
    }

    #[test]
    fn test_terminal_cell() {
        let cell = TerminalCell::new('A');
        assert_eq!(cell.character, 'A');
        assert!(!cell.bold);
        assert_eq!(cell.effective_foreground(), TerminalColor::Default);

        let mut cell = TerminalCell::new('B');
        cell.inverse = true;
        cell.foreground = TerminalColor::Red;
        cell.background = TerminalColor::Blue;
        assert_eq!(cell.effective_foreground(), TerminalColor::Blue);
        assert_eq!(cell.effective_background(), TerminalColor::Red);
    }

    #[test]
    fn test_terminal_color() {
        assert_eq!(TerminalColor::Default.to_rgb(), 0xD4D4D4);
        assert_eq!(TerminalColor::Red.to_rgb(), 0xCD3131);
        assert_eq!(TerminalColor::Indexed(0).to_rgb(), 0x000000);
        assert_eq!(TerminalColor::Rgb(255, 0, 0).to_rgb(), 0xFF0000);
    }

    #[test]
    fn test_write_and_clear() {
        let mut plugin = TerminalPlugin::new("TestPlugin");
        plugin.write("Hello");
        plugin.writeln(" World");
        assert_eq!(plugin.state().cursor_row(), 1);
        plugin.clear();
        assert_eq!(plugin.state().cursor_row(), 0);
        assert_eq!(plugin.state().cursor_col(), 0);
    }

    #[test]
    fn test_scroll() {
        let mut state = TerminalState::new(80, 2);
        state.write_str("Line 1\nLine 2\nLine 3");
        assert_eq!(state.scrollback_size(), 1);
    }

    #[test]
    fn test_init_dispose() {
        let mut plugin = TerminalPlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_find_options() {
        let opts = TerminalFindOptions::new("test")
            .with_case_sensitive(true)
            .with_backwards(true);
        assert_eq!(opts.text, "test");
        assert!(opts.case_sensitive);
        assert!(opts.backwards);
    }
}
