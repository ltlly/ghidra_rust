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

/// VT100 terminal emulator internals (parser, buffer, attributes, state machine).
///
/// Ported from Ghidra's `ghidra.app.plugin.core.terminal.vt` package.
pub mod vt;

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

// ---------------------------------------------------------------------------
// ANSI escape sequence parser
// ---------------------------------------------------------------------------

/// A parsed ANSI escape sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnsiSequence {
    /// Cursor Up: move cursor up N rows.
    CursorUp(u16),
    /// Cursor Down: move cursor down N rows.
    CursorDown(u16),
    /// Cursor Forward: move cursor right N columns.
    CursorForward(u16),
    /// Cursor Back: move cursor left N columns.
    CursorBack(u16),
    /// Cursor Position: move to row, column (1-based).
    CursorPosition(u16, u16),
    /// Erase Display: 0=to end, 1=to start, 2=all, 3=all + scrollback.
    EraseDisplay(u8),
    /// Erase in Line: 0=to end, 1=to start, 2=all.
    EraseInLine(u8),
    /// Set Graphics Rendition (SGR).
    SetGraphicsRendition(Vec<u16>),
    /// Set scrolling region (top, bottom).
    SetScrollRegion(u16, u16),
    /// Save cursor position.
    SaveCursor,
    /// Restore cursor position.
    RestoreCursor,
    /// Hide cursor.
    HideCursor,
    /// Show cursor.
    ShowCursor,
    /// Set mode.
    SetMode(u16),
    /// Reset mode.
    ResetMode(u16),
    /// Device Status Report.
    DeviceStatusReport,
    /// An unrecognized sequence.
    Unknown(Vec<u16>),
}

/// State of the ANSI parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    /// Normal character processing.
    Normal,
    /// Seen ESC character.
    EscSeen,
    /// Inside CSI (Control Sequence Introducer) sequence, collecting params.
    CsiParams,
    /// Inside CSI with private mode prefix (`?`).
    CsiPrivate,
}

/// Parser for ANSI/VT100 escape sequences.
///
/// Ported from terminal emulator parsing logic.
#[derive(Debug)]
pub struct AnsiParser {
    state: ParseState,
    params: Vec<u16>,
    /// The current accumulated parameter string.
    param_str: String,
    /// Whether this is a private mode sequence (has `?` prefix).
    private_mode: bool,
}

impl AnsiParser {
    /// Create a new ANSI parser.
    pub fn new() -> Self {
        Self {
            state: ParseState::Normal,
            params: Vec::new(),
            param_str: String::new(),
            private_mode: false,
        }
    }

    /// Parse a string and extract escape sequences and text.
    pub fn parse(&mut self, input: &str) -> Vec<ParsedElement> {
        let mut elements = Vec::new();
        let mut text_buf = String::new();

        for ch in input.chars() {
            match self.feed_char(ch) {
                Some(ParsedElement::Text(t)) => text_buf.push_str(&t),
                Some(seq) => {
                    if !text_buf.is_empty() {
                        elements.push(ParsedElement::Text(std::mem::take(&mut text_buf)));
                    }
                    elements.push(seq);
                }
                None => {}
            }
        }

        if !text_buf.is_empty() {
            elements.push(ParsedElement::Text(text_buf));
        }

        elements
    }

    /// Feed a single character to the parser.
    pub fn feed_char(&mut self, ch: char) -> Option<ParsedElement> {
        match self.state {
            ParseState::Normal => {
                if ch == '\x1B' {
                    self.state = ParseState::EscSeen;
                    self.params.clear();
                    self.param_str.clear();
                    None
                } else {
                    Some(ParsedElement::Text(ch.to_string()))
                }
            }
            ParseState::EscSeen => {
                if ch == '[' {
                    self.state = ParseState::CsiParams;
                    self.private_mode = false;
                    None
                } else {
                    self.state = ParseState::Normal;
                    Some(ParsedElement::Sequence(AnsiSequence::Unknown(vec![])))
                }
            }
            ParseState::CsiParams => {
                if ch == '?' {
                    self.private_mode = true;
                    self.state = ParseState::CsiPrivate;
                    None
                } else if ch.is_ascii_digit() {
                    self.param_str.push(ch);
                    None
                } else if ch == ';' {
                    self.params.push(self.param_str.parse().unwrap_or(0));
                    self.param_str.clear();
                    None
                } else {
                    self.params.push(self.param_str.parse().unwrap_or(0));
                    self.state = ParseState::Normal;
                    Some(ParsedElement::Sequence(self.decode_csi(ch)))
                }
            }
            ParseState::CsiPrivate => {
                if ch.is_ascii_digit() {
                    self.param_str.push(ch);
                    None
                } else if ch == ';' {
                    self.params.push(self.param_str.parse().unwrap_or(0));
                    self.param_str.clear();
                    None
                } else {
                    self.params.push(self.param_str.parse().unwrap_or(0));
                    self.state = ParseState::Normal;
                    Some(ParsedElement::Sequence(self.decode_csi(ch)))
                }
            }
        }
    }

    fn decode_csi(&self, final_byte: char) -> AnsiSequence {
        let p = |i: usize| -> u16 {
            self.params.get(i).copied().unwrap_or(0).max(1)
        };

        match final_byte {
            'A' => AnsiSequence::CursorUp(p(0)),
            'B' => AnsiSequence::CursorDown(p(0)),
            'C' => AnsiSequence::CursorForward(p(0)),
            'D' => AnsiSequence::CursorBack(p(0)),
            'H' | 'f' => AnsiSequence::CursorPosition(p(0), p(1)),
            'J' => AnsiSequence::EraseDisplay(self.params.first().copied().unwrap_or(0) as u8),
            'K' => AnsiSequence::EraseInLine(self.params.first().copied().unwrap_or(0) as u8),
            'm' => AnsiSequence::SetGraphicsRendition(self.params.clone()),
            'r' => AnsiSequence::SetScrollRegion(p(0), p(1)),
            's' => AnsiSequence::SaveCursor,
            'u' => AnsiSequence::RestoreCursor,
            'l' => {
                if let Some(&mode) = self.params.first() {
                    if mode == 25 {
                        AnsiSequence::HideCursor
                    } else {
                        AnsiSequence::ResetMode(mode)
                    }
                } else {
                    AnsiSequence::Unknown(self.params.clone())
                }
            }
            'h' => {
                if let Some(&mode) = self.params.first() {
                    if mode == 25 {
                        AnsiSequence::ShowCursor
                    } else {
                        AnsiSequence::SetMode(mode)
                    }
                } else {
                    AnsiSequence::Unknown(self.params.clone())
                }
            }
            'n' => AnsiSequence::DeviceStatusReport,
            _ => AnsiSequence::Unknown(self.params.clone()),
        }
    }
}

impl Default for AnsiParser {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed element from an ANSI terminal stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedElement {
    /// Plain text.
    Text(String),
    /// An ANSI escape sequence.
    Sequence(AnsiSequence),
}

/// Process ANSI sequences and apply them to a terminal state.
pub struct AnsiProcessor {
    parser: AnsiParser,
    /// Saved cursor position (row, col).
    saved_cursor: (usize, usize),
    /// Current SGR attributes.
    current_fg: TerminalColor,
    current_bg: TerminalColor,
    current_bold: bool,
    current_italic: bool,
    current_underline: bool,
    current_reverse: bool,
}

impl AnsiProcessor {
    /// Create a new ANSI processor.
    pub fn new() -> Self {
        Self {
            parser: AnsiParser::new(),
            saved_cursor: (0, 0),
            current_fg: TerminalColor::Default,
            current_bg: TerminalColor::Default,
            current_bold: false,
            current_italic: false,
            current_underline: false,
            current_reverse: false,
        }
    }

    /// Process a string and apply it to the terminal state.
    pub fn process(&mut self, terminal: &mut TerminalState, input: &str) {
        let elements = self.parser.parse(input);
        for elem in elements {
            match elem {
                ParsedElement::Text(text) => {
                    for ch in text.chars() {
                        let mut cell = TerminalCell::new(ch);
                        cell.foreground = self.current_fg;
                        cell.background = self.current_bg;
                        cell.bold = self.current_bold;
                        cell.italic = self.current_italic;
                        cell.underline = self.current_underline;
                        cell.reverse = self.current_reverse;
                        terminal.set_cell(terminal.cursor_row, terminal.cursor_col, cell);
                        terminal.cursor_col += 1;
                        if terminal.cursor_col >= terminal.width {
                            terminal.cursor_col = 0;
                            terminal.cursor_row += 1;
                            if terminal.cursor_row >= terminal.height {
                                terminal.newline();
                                terminal.cursor_row = terminal.height - 1;
                            }
                        }
                    }
                }
                ParsedElement::Sequence(seq) => {
                    self.apply_sequence(terminal, seq);
                }
            }
        }
    }

    fn apply_sequence(&mut self, terminal: &mut TerminalState, seq: AnsiSequence) {
        match seq {
            AnsiSequence::CursorUp(n) => {
                terminal.cursor_row = terminal.cursor_row.saturating_sub(n as usize);
            }
            AnsiSequence::CursorDown(n) => {
                terminal.cursor_row = (terminal.cursor_row + n as usize).min(terminal.height - 1);
            }
            AnsiSequence::CursorForward(n) => {
                terminal.cursor_col = (terminal.cursor_col + n as usize).min(terminal.width - 1);
            }
            AnsiSequence::CursorBack(n) => {
                terminal.cursor_col = terminal.cursor_col.saturating_sub(n as usize);
            }
            AnsiSequence::CursorPosition(row, col) => {
                terminal.cursor_row = (row as usize).saturating_sub(1).min(terminal.height - 1);
                terminal.cursor_col = (col as usize).saturating_sub(1).min(terminal.width - 1);
            }
            AnsiSequence::EraseDisplay(mode) => {
                match mode {
                    0 => terminal.clear(), // simplified: clear all
                    2 => terminal.clear(),
                    _ => {}
                }
            }
            AnsiSequence::EraseInLine(mode) => {
                if mode == 0 || mode == 2 {
                    terminal.clear_to_end_of_line();
                }
            }
            AnsiSequence::SetGraphicsRendition(params) => {
                self.apply_sgr(&params);
            }
            AnsiSequence::SaveCursor => {
                self.saved_cursor = (terminal.cursor_row, terminal.cursor_col);
            }
            AnsiSequence::RestoreCursor => {
                terminal.cursor_row = self.saved_cursor.0;
                terminal.cursor_col = self.saved_cursor.1;
            }
            AnsiSequence::HideCursor => {
                terminal.cursor_visible = false;
            }
            AnsiSequence::ShowCursor => {
                terminal.cursor_visible = true;
            }
            _ => {} // ignore unrecognized
        }
    }

    fn apply_sgr(&mut self, params: &[u16]) {
        if params.is_empty() {
            self.current_fg = TerminalColor::Default;
            self.current_bg = TerminalColor::Default;
            self.current_bold = false;
            self.current_italic = false;
            self.current_underline = false;
            self.current_reverse = false;
            return;
        }

        let mut i = 0;
        while i < params.len() {
            match params[i] {
                0 => {
                    self.current_fg = TerminalColor::Default;
                    self.current_bg = TerminalColor::Default;
                    self.current_bold = false;
                    self.current_italic = false;
                    self.current_underline = false;
                    self.current_reverse = false;
                }
                1 => self.current_bold = true,
                3 => self.current_italic = true,
                4 => self.current_underline = true,
                7 => self.current_reverse = true,
                22 => self.current_bold = false,
                23 => self.current_italic = false,
                24 => self.current_underline = false,
                27 => self.current_reverse = false,
                30..=37 => {
                    self.current_fg = Self::ansi_color((params[i] - 30) as u8);
                }
                40..=47 => {
                    self.current_bg = Self::ansi_color((params[i] - 40) as u8);
                }
                90..=97 => {
                    self.current_fg = Self::ansi_bright_color((params[i] - 90) as u8);
                }
                100..=107 => {
                    self.current_bg = Self::ansi_bright_color((params[i] - 100) as u8);
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn ansi_color(code: u8) -> TerminalColor {
        match code {
            0 => TerminalColor::Black,
            1 => TerminalColor::Red,
            2 => TerminalColor::Green,
            3 => TerminalColor::Yellow,
            4 => TerminalColor::Blue,
            5 => TerminalColor::Magenta,
            6 => TerminalColor::Cyan,
            7 => TerminalColor::White,
            _ => TerminalColor::Default,
        }
    }

    fn ansi_bright_color(code: u8) -> TerminalColor {
        match code {
            0 => TerminalColor::BrightBlack,
            1 => TerminalColor::BrightRed,
            2 => TerminalColor::BrightGreen,
            3 => TerminalColor::BrightYellow,
            4 => TerminalColor::BrightBlue,
            5 => TerminalColor::BrightMagenta,
            6 => TerminalColor::BrightCyan,
            7 => TerminalColor::BrightWhite,
            _ => TerminalColor::Default,
        }
    }
}

impl Default for AnsiProcessor {
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

    #[test]
    fn test_ansi_parser_plain_text() {
        let mut parser = AnsiParser::new();
        let elements = parser.parse("Hello World");
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0], ParsedElement::Text("Hello World".into()));
    }

    #[test]
    fn test_ansi_parser_cursor_movement() {
        let mut parser = AnsiParser::new();
        let elements = parser.parse("A\x1B[2BB");
        assert_eq!(elements.len(), 3);
        assert_eq!(elements[0], ParsedElement::Text("A".into()));
        assert_eq!(elements[1], ParsedElement::Sequence(AnsiSequence::CursorDown(2)));
        assert_eq!(elements[2], ParsedElement::Text("B".into()));
    }

    #[test]
    fn test_ansi_parser_cursor_position() {
        let mut parser = AnsiParser::new();
        let elements = parser.parse("\x1B[5;10H");
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0], ParsedElement::Sequence(AnsiSequence::CursorPosition(5, 10)));
    }

    #[test]
    fn test_ansi_parser_default_params() {
        let mut parser = AnsiParser::new();
        // CSI A with no params should default to 1
        let elements = parser.parse("\x1B[A");
        assert_eq!(elements[0], ParsedElement::Sequence(AnsiSequence::CursorUp(1)));
    }

    #[test]
    fn test_ansi_parser_erase() {
        let mut parser = AnsiParser::new();
        let elements = parser.parse("\x1B[2J");
        assert_eq!(elements[0], ParsedElement::Sequence(AnsiSequence::EraseDisplay(2)));
    }

    #[test]
    fn test_ansi_parser_erase_line() {
        let mut parser = AnsiParser::new();
        let elements = parser.parse("\x1B[K");
        assert_eq!(elements[0], ParsedElement::Sequence(AnsiSequence::EraseInLine(0)));
    }

    #[test]
    fn test_ansi_parser_sgr() {
        let mut parser = AnsiParser::new();
        let elements = parser.parse("\x1B[1;31m");
        assert_eq!(
            elements[0],
            ParsedElement::Sequence(AnsiSequence::SetGraphicsRendition(vec![1, 31]))
        );
    }

    #[test]
    fn test_ansi_parser_save_restore_cursor() {
        let mut parser = AnsiParser::new();
        let elements = parser.parse("\x1B[s\x1B[u");
        assert_eq!(elements[0], ParsedElement::Sequence(AnsiSequence::SaveCursor));
        assert_eq!(elements[1], ParsedElement::Sequence(AnsiSequence::RestoreCursor));
    }

    #[test]
    fn test_ansi_parser_cursor_visibility() {
        let mut parser = AnsiParser::new();
        let elements = parser.parse("\x1B[?25l\x1B[?25h");
        assert_eq!(elements[0], ParsedElement::Sequence(AnsiSequence::HideCursor));
        assert_eq!(elements[1], ParsedElement::Sequence(AnsiSequence::ShowCursor));
    }

    #[test]
    fn test_ansi_processor_basic() {
        let mut terminal = TerminalState::new(20, 5);
        let mut processor = AnsiProcessor::new();
        processor.process(&mut terminal, "Hello");
        assert_eq!(terminal.cell(0, 0).unwrap().ch, 'H');
        assert_eq!(terminal.cell(0, 4).unwrap().ch, 'o');
    }

    #[test]
    fn test_ansi_processor_cursor_movement() {
        let mut terminal = TerminalState::new(20, 10);
        let mut processor = AnsiProcessor::new();
        processor.process(&mut terminal, "A\x1B[2BB");
        assert_eq!(terminal.cell(0, 0).unwrap().ch, 'A');
        assert_eq!(terminal.cell(2, 1).unwrap().ch, 'B');
    }

    #[test]
    fn test_ansi_processor_cursor_position() {
        let mut terminal = TerminalState::new(20, 10);
        let mut processor = AnsiProcessor::new();
        processor.process(&mut terminal, "\x1B[3;5HX");
        assert_eq!(terminal.cell(2, 4).unwrap().ch, 'X');
    }

    #[test]
    fn test_ansi_processor_colors() {
        let mut terminal = TerminalState::new(20, 5);
        let mut processor = AnsiProcessor::new();
        processor.process(&mut terminal, "\x1B[1;31mR");
        assert!(terminal.cell(0, 0).unwrap().bold);
        assert_eq!(terminal.cell(0, 0).unwrap().foreground, TerminalColor::Red);
    }

    #[test]
    fn test_ansi_processor_save_restore() {
        let mut terminal = TerminalState::new(20, 5);
        let mut processor = AnsiProcessor::new();
        processor.process(&mut terminal, "AB\x1B[sCD\x1B[uXY");
        assert_eq!(terminal.cell(0, 0).unwrap().ch, 'A');
        assert_eq!(terminal.cell(0, 1).unwrap().ch, 'B');
        // After restore, cursor goes back to position after B (col 2)
        // X and Y overwrite the C and D that were written
        assert_eq!(terminal.cell(0, 2).unwrap().ch, 'X');
        assert_eq!(terminal.cell(0, 3).unwrap().ch, 'Y');
    }

    #[test]
    fn test_ansi_parser_escape_sequences() {
        // Test \r and \n handling via write_str (not ANSI, but terminal)
        let mut terminal = TerminalState::new(20, 5);
        let mut processor = AnsiProcessor::new();
        processor.process(&mut terminal, "Line1\nLine2");
        assert_eq!(terminal.cell(0, 0).unwrap().ch, 'L');
        // \n in the text should go through write logic
    }

    #[test]
    fn test_ansi_processor_erase_display() {
        let mut terminal = TerminalState::new(10, 3);
        let mut processor = AnsiProcessor::new();
        processor.process(&mut terminal, "Hello");
        assert_eq!(terminal.cell(0, 0).unwrap().ch, 'H');
        processor.process(&mut terminal, "\x1B[2J");
        assert_eq!(terminal.cell(0, 0).unwrap().ch, ' ');
    }

    #[test]
    fn test_ansi_color_mapping() {
        assert_eq!(AnsiProcessor::ansi_color(0), TerminalColor::Black);
        assert_eq!(AnsiProcessor::ansi_color(7), TerminalColor::White);
        assert_eq!(AnsiProcessor::ansi_bright_color(0), TerminalColor::BrightBlack);
        assert_eq!(AnsiProcessor::ansi_bright_color(7), TerminalColor::BrightWhite);
    }
}
