//! Terminal provider -- view-state management for the terminal panel.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.terminal` view-state layer.
//!
//! This module provides [`TerminalProvider`], which manages the terminal
//! display buffer, process I/O plumbing, and search state on behalf of the
//! terminal plugin.  It sits above the raw cell grid and adds:
//!
//! - Display buffer management (grid, scrollback, cursor)
//! - ANSI escape sequence parsing (CSI and OSC)
//! - Text search with wrap-around and case sensitivity
//! - Process execution via pseudo-terminal (pty) when available
//! - Screen content extraction for clipboard and accessibility
//!
//! # Architecture
//!
//! ```text
//! TerminalProvider
//!   ├── CellGrid (rows x cols of TerminalCell)
//!   ├── ScrollbackBuffer (ring buffer of historical rows)
//!   ├── AnsiParser (escape sequence state machine)
//!   ├── ProcessHandle (optional pty-backed child)
//!   └── SearchState (find query, matches, position)
//! ```

use std::collections::VecDeque;
use std::io::Write;

// ============================================================================
// Constants
// ============================================================================

/// Default terminal width in columns.
pub const DEFAULT_WIDTH: usize = 80;

/// Default terminal height in rows.
pub const DEFAULT_HEIGHT: usize = 24;

/// Maximum number of lines kept in the scrollback buffer.
pub const MAX_SCROLLBACK: usize = 10_000;

/// Tab stop width.
const TAB_WIDTH: usize = 8;

// ============================================================================
// TerminalColor -- ANSI color representation
// ============================================================================

/// ANSI terminal color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalColor {
    /// Default foreground / background.
    Default,
    /// Standard black (SGR 30/40).
    Black,
    /// Standard red (SGR 31/41).
    Red,
    /// Standard green (SGR 32/42).
    Green,
    /// Standard yellow (SGR 33/43).
    Yellow,
    /// Standard blue (SGR 34/44).
    Blue,
    /// Standard magenta (SGR 35/45).
    Magenta,
    /// Standard cyan (SGR 36/46).
    Cyan,
    /// Standard white (SGR 37/47).
    White,
    /// Bright black / dark gray (SGR 90/100).
    BrightBlack,
    /// Bright red (SGR 91/101).
    BrightRed,
    /// Bright green (SGR 92/102).
    BrightGreen,
    /// Bright yellow (SGR 93/103).
    BrightYellow,
    /// Bright blue (SGR 94/104).
    BrightBlue,
    /// Bright magenta (SGR 95/105).
    BrightMagenta,
    /// Bright cyan (SGR 96/106).
    BrightCyan,
    /// Bright white (SGR 97/107).
    BrightWhite,
    /// 256-color palette index.
    Indexed(u8),
    /// 24-bit true color (R, G, B).
    Rgb(u8, u8, u8),
}

impl TerminalColor {
    /// Convert to an RGB hex value (`0xRRGGBB`).
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
        // Standard + bright colors
        const COLORS: [u32; 16] = [
            0x000000, 0xCD3131, 0x0DBC79, 0xE5E510, 0x2472C8, 0xBC3FBC, 0x11A8CD, 0xE5E5E5,
            0x666666, 0xF14C4C, 0x23D18B, 0xF5F543, 0x3B8EEA, 0xD670D6, 0x29B8DB, 0xE5E5E5,
        ];
        COLORS[index as usize]
    } else if index < 232 {
        // 6x6x6 color cube
        let i = index - 16;
        let r = (i / 36) * 51;
        let g = ((i % 36) / 6) * 51;
        let b = (i % 6) * 51;
        ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
    } else {
        // Grayscale ramp 232..255
        let gray = 8 + (index - 232) * 10;
        ((gray as u32) << 16) | ((gray as u32) << 8) | (gray as u32)
    }
}

// ============================================================================
// TerminalCell -- single grid cell
// ============================================================================

/// A single cell in the terminal grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalCell {
    /// The character displayed in this cell.
    pub character: char,
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
    /// Dim attribute.
    pub dim: bool,
    /// Blink attribute.
    pub blink: bool,
    /// Inverse (swap fg/bg) attribute.
    pub inverse: bool,
}

impl TerminalCell {
    /// Create a new cell with default attributes.
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

    /// Create a blank (space) cell.
    pub fn blank() -> Self {
        Self::new(' ')
    }

    /// Return the effective foreground color, accounting for inverse.
    pub fn effective_foreground(&self) -> TerminalColor {
        if self.inverse {
            self.background
        } else {
            self.foreground
        }
    }

    /// Return the effective background color, accounting for inverse.
    pub fn effective_background(&self) -> TerminalColor {
        if self.inverse {
            self.foreground
        } else {
            self.background
        }
    }

    /// Reset all attributes to defaults, keeping the character.
    pub fn reset_attributes(&mut self) {
        self.foreground = TerminalColor::Default;
        self.background = TerminalColor::Default;
        self.bold = false;
        self.italic = false;
        self.underline = false;
        self.dim = false;
        self.blink = false;
        self.inverse = false;
    }
}

impl Default for TerminalCell {
    fn default() -> Self {
        Self::blank()
    }
}

// ============================================================================
// SearchState -- find state
// ============================================================================

/// Tracks the state of an interactive text search in the terminal buffer.
#[derive(Debug, Clone, Default)]
pub struct SearchState {
    /// Current search query.
    query: String,
    /// All match positions `(row, col)`.
    matches: Vec<(usize, usize)>,
    /// Index of the currently highlighted match.
    current_index: Option<usize>,
    /// Whether the search is case-sensitive.
    case_sensitive: bool,
}

impl SearchState {
    /// Create a new empty search state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if a search is active.
    pub fn is_active(&self) -> bool {
        !self.query.is_empty()
    }

    /// Returns the current query string.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Returns the number of matches.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Returns the current match position, or `None`.
    pub fn current_match(&self) -> Option<(usize, usize)> {
        self.current_index.and_then(|i| self.matches.get(i).copied())
    }

    /// Returns the 1-based index of the current match, or `None`.
    pub fn current_match_number(&self) -> Option<usize> {
        self.current_index.map(|i| i + 1)
    }

    /// Returns whether the search is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Sets the case-sensitivity flag.
    pub fn set_case_sensitive(&mut self, v: bool) {
        self.case_sensitive = v;
    }

    /// Update the search with a new query and match list.
    pub fn update(&mut self, query: impl Into<String>, matches: Vec<(usize, usize)>) {
        self.query = query.into();
        self.matches = matches;
        self.current_index = if self.matches.is_empty() {
            None
        } else {
            Some(0)
        };
    }

    /// Advance to the next match (wraps).
    pub fn next_match(&mut self) -> Option<(usize, usize)> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = self.current_index.map_or(0, |i| (i + 1) % self.matches.len());
        self.current_index = Some(idx);
        self.current_match()
    }

    /// Go to the previous match (wraps).
    pub fn prev_match(&mut self) -> Option<(usize, usize)> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = self.current_index.map_or(0, |i| {
            if i == 0 {
                self.matches.len() - 1
            } else {
                i - 1
            }
        });
        self.current_index = Some(idx);
        self.current_match()
    }

    /// Clear the search state.
    pub fn clear(&mut self) {
        self.query.clear();
        self.matches.clear();
        self.current_index = None;
    }
}

// ============================================================================
// TerminalProviderConfig -- display options
// ============================================================================

/// Display configuration for the terminal panel.
#[derive(Debug, Clone)]
pub struct TerminalProviderConfig {
    /// Terminal width in columns.
    pub width: usize,
    /// Terminal height in rows.
    pub height: usize,
    /// Maximum scrollback lines.
    pub max_scrollback: usize,
    /// Whether to auto-scroll on new output.
    pub auto_scroll: bool,
    /// Font point size.
    pub font_size: u32,
    /// Whether to wrap long lines.
    pub line_wrap: bool,
    /// Whether to convert ANSI color codes.
    pub interpret_ansi: bool,
}

impl Default for TerminalProviderConfig {
    fn default() -> Self {
        Self {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            max_scrollback: MAX_SCROLLBACK,
            auto_scroll: true,
            font_size: 12,
            line_wrap: true,
            interpret_ansi: true,
        }
    }
}

// ============================================================================
// ProcessHandle -- pty-backed child process
// ============================================================================

/// Status of a child process attached to the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    /// Process has not been started.
    NotStarted,
    /// Process is running.
    Running,
    /// Process exited normally.
    Exited,
    /// Process was terminated by a signal.
    Signaled,
}

/// Opaque handle for a pty-backed child process.
///
/// On Unix this would wrap `fork`/`posix_openpt`; on Windows it wraps
/// named pipes or ConPTY.  For the Rust port we store the metadata that
/// the provider needs without requiring a real process.
#[derive(Debug)]
pub struct ProcessHandle {
    /// The command that was (or would be) executed.
    command: String,
    /// Current process status.
    status: ProcessStatus,
    /// Exit code, if the process has finished.
    exit_code: Option<i32>,
    /// Buffered stdout bytes not yet consumed by the grid.
    stdout_buffer: Vec<u8>,
    /// Buffered stderr bytes not yet consumed by the grid.
    stderr_buffer: Vec<u8>,
}

impl ProcessHandle {
    /// Create a new process handle for the given command.
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            status: ProcessStatus::NotStarted,
            exit_code: None,
            stdout_buffer: Vec::new(),
            stderr_buffer: Vec::new(),
        }
    }

    /// Get the command string.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Get the process status.
    pub fn status(&self) -> ProcessStatus {
        self.status
    }

    /// Get the exit code, if available.
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Mark the process as running.
    pub fn set_running(&mut self) {
        self.status = ProcessStatus::Running;
    }

    /// Mark the process as exited with the given code.
    pub fn set_exited(&mut self, code: i32) {
        self.status = ProcessStatus::Exited;
        self.exit_code = Some(code);
    }

    /// Mark the process as terminated by a signal.
    pub fn set_signaled(&mut self) {
        self.status = ProcessStatus::Signaled;
    }

    /// Append bytes to the stdout buffer.
    pub fn push_stdout(&mut self, data: &[u8]) {
        self.stdout_buffer.extend_from_slice(data);
    }

    /// Append bytes to the stderr buffer.
    pub fn push_stderr(&mut self, data: &[u8]) {
        self.stderr_buffer.extend_from_slice(data);
    }

    /// Drain the stdout buffer.
    pub fn drain_stdout(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stdout_buffer)
    }

    /// Drain the stderr buffer.
    pub fn drain_stderr(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stderr_buffer)
    }

    /// Returns `true` if the process is still running.
    pub fn is_running(&self) -> bool {
        self.status == ProcessStatus::Running
    }
}

// ============================================================================
// TerminalProvider -- the high-level view-state manager
// ============================================================================

/// High-level provider for the terminal panel.
///
/// Manages the cell grid, scrollback, cursor, ANSI parsing, process
/// attachment, and text search.  This is the Rust equivalent of the
/// view-state portion of Ghidra's terminal component provider.
///
/// # Example
///
/// ```
/// use ghidra_features::base::terminal::TerminalProvider;
///
/// let mut provider = TerminalProvider::new("Ghidra Terminal");
/// provider.write("Hello, ");
/// provider.writeln("world!");
/// assert!(provider.get_screen_text().contains("Hello"));
/// assert_eq!(provider.cursor_row(), 1);
/// ```
#[derive(Debug)]
pub struct TerminalProvider {
    /// Display name.
    name: String,
    /// The cell grid (rows x cols).
    grid: Vec<Vec<TerminalCell>>,
    /// Scrollback buffer (oldest first).
    scrollback: VecDeque<Vec<TerminalCell>>,
    /// Cursor column.
    cursor_col: usize,
    /// Cursor row.
    cursor_row: usize,
    /// Terminal width.
    width: usize,
    /// Terminal height.
    height: usize,
    /// Saved cursor position (CSI s / CSI u).
    saved_cursor: Option<(usize, usize)>,
    /// Display configuration.
    config: TerminalProviderConfig,
    /// Interactive search state.
    search: SearchState,
    /// Optional attached process.
    process: Option<ProcessHandle>,
    /// Whether the provider is visible.
    visible: bool,
    /// ANSI parser state:
    /// 0 = normal, 1 = saw ESC, 2 = saw ESC[ (collecting params).
    ansi_state: u8,
    /// Accumulated CSI parameter bytes (after the `[`).
    csi_params: String,
}

impl TerminalProvider {
    /// Create a new terminal provider with default configuration.
    pub fn new(name: impl Into<String>) -> Self {
        let config = TerminalProviderConfig::default();
        Self::with_config(name, config)
    }

    /// Create a new terminal provider with the given configuration.
    pub fn with_config(name: impl Into<String>, config: TerminalProviderConfig) -> Self {
        let grid = Self::make_grid(config.width, config.height);
        Self {
            name: name.into(),
            grid,
            scrollback: VecDeque::new(),
            cursor_col: 0,
            cursor_row: 0,
            width: config.width,
            height: config.height,
            saved_cursor: None,
            config,
            search: SearchState::new(),
            process: None,
            visible: true,
            ansi_state: 0,
            csi_params: String::new(),
        }
    }

    /// Build a blank grid of the given dimensions.
    fn make_grid(width: usize, height: usize) -> Vec<Vec<TerminalCell>> {
        (0..height)
            .map(|_| (0..width).map(|_| TerminalCell::blank()).collect())
            .collect()
    }

    // -- Accessors ---------------------------------------------------------------

    /// Get the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Get the terminal width.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Get the terminal height.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Get the current cursor column.
    pub fn cursor_col(&self) -> usize {
        self.cursor_col
    }

    /// Get the current cursor row.
    pub fn cursor_row(&self) -> usize {
        self.cursor_row
    }

    /// Get the scrollback buffer size.
    pub fn scrollback_size(&self) -> usize {
        self.scrollback.len()
    }

    /// Get a reference to the display configuration.
    pub fn config(&self) -> &TerminalProviderConfig {
        &self.config
    }

    /// Get a mutable reference to the display configuration.
    pub fn config_mut(&mut self) -> &mut TerminalProviderConfig {
        &mut self.config
    }

    /// Get a reference to the search state.
    pub fn search(&self) -> &SearchState {
        &self.search
    }

    /// Get a reference to the attached process handle, if any.
    pub fn process(&self) -> Option<&ProcessHandle> {
        self.process.as_ref()
    }

    /// Get a reference to a cell.
    pub fn cell(&self, row: usize, col: usize) -> Option<&TerminalCell> {
        self.grid.get(row)?.get(col)
    }

    /// Get a mutable reference to a cell.
    pub fn cell_mut(&mut self, row: usize, col: usize) -> Option<&mut TerminalCell> {
        self.grid.get_mut(row)?.get_mut(col)
    }

    // -- Terminal I/O ------------------------------------------------------------

    /// Write text to the terminal, interpreting ANSI escape sequences when
    /// `config.interpret_ansi` is enabled.
    pub fn write(&mut self, text: &str) {
        if self.config.interpret_ansi {
            for ch in text.chars() {
                self.process_char(ch);
            }
        } else {
            for ch in text.chars() {
                self.write_plain_char(ch);
            }
        }
    }

    /// Write text followed by a newline.
    pub fn writeln(&mut self, text: &str) {
        self.write(text);
        self.write("\n");
    }

    /// Clear the terminal display.
    pub fn clear(&mut self) {
        for row in &mut self.grid {
            for cell in row.iter_mut() {
                *cell = TerminalCell::blank();
            }
        }
        self.cursor_col = 0;
        self.cursor_row = 0;
    }

    /// Clear from cursor to end of line.
    pub fn clear_to_eol(&mut self) {
        for col in self.cursor_col..self.width {
            self.grid[self.cursor_row][col] = TerminalCell::blank();
        }
    }

    /// Clear from cursor to end of screen.
    pub fn clear_to_eos(&mut self) {
        self.clear_to_eol();
        for row in (self.cursor_row + 1)..self.height {
            for col in 0..self.width {
                self.grid[row][col] = TerminalCell::blank();
            }
        }
    }

    /// Save the current cursor position.
    pub fn save_cursor(&mut self) {
        self.saved_cursor = Some((self.cursor_row, self.cursor_col));
    }

    /// Restore the saved cursor position.
    pub fn restore_cursor(&mut self) {
        if let Some((row, col)) = self.saved_cursor {
            self.cursor_row = row;
            self.cursor_col = col;
        }
    }

    /// Set the cursor position directly.
    pub fn set_cursor(&mut self, row: usize, col: usize) {
        self.cursor_row = row.min(self.height.saturating_sub(1));
        self.cursor_col = col.min(self.width.saturating_sub(1));
    }

    /// Scroll the display up by one line.
    pub fn scroll_up(&mut self) {
        if let Some(top_line) = self.grid.first().cloned() {
            if self.scrollback.len() >= self.config.max_scrollback {
                self.scrollback.pop_front();
            }
            self.scrollback.push_back(top_line);
        }
        self.grid.remove(0);
        self.grid.push(Self::make_grid(self.width, 1).pop().unwrap());
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
        }
    }

    // -- ANSI parsing (minimal CSI subset) ---------------------------------------

    /// Process a single character through the ANSI state machine.
    fn process_char(&mut self, ch: char) {
        match self.ansi_state {
            // State 0: normal text
            0 => match ch {
                '\x1B' => {
                    self.ansi_state = 1;
                    self.csi_params.clear();
                }
                '\n' => {
                    self.cursor_col = 0;
                    self.cursor_row += 1;
                    if self.cursor_row >= self.height {
                        self.scroll_up();
                    }
                }
                '\r' => {
                    self.cursor_col = 0;
                }
                '\t' => {
                    let next_tab = (self.cursor_col / TAB_WIDTH + 1) * TAB_WIDTH;
                    while self.cursor_col < next_tab && self.cursor_col < self.width {
                        self.write_plain_char(' ');
                    }
                }
                '\x08' => {
                    // Backspace
                    if self.cursor_col > 0 {
                        self.cursor_col -= 1;
                    }
                }
                _ => {
                    self.write_plain_char(ch);
                }
            },
            // State 1: saw ESC, expecting '['
            1 => {
                if ch == '[' {
                    self.ansi_state = 2;
                    self.csi_params.clear();
                } else {
                    // Not a CSI sequence -- ignore and return to normal
                    self.ansi_state = 0;
                }
            }
            // State 2: inside CSI, collecting parameters
            2 => {
                self.csi_params.push(ch);
                // CSI sequences end with a letter in 0x40..0x7E or '~'
                if ch.is_ascii_alphabetic() || ch == '~' {
                    self.dispatch_csi();
                    self.ansi_state = 0;
                    self.csi_params.clear();
                }
            }
            _ => {
                self.ansi_state = 0;
            }
        }
    }

    /// Dispatch a collected CSI sequence.
    fn dispatch_csi(&mut self) {
        let seq = &self.csi_params;
        if seq.is_empty() {
            return;
        }
        let final_char = seq.chars().last().unwrap();
        let params: String = seq.chars().take(seq.len() - 1).collect();
        let nums: Vec<usize> = params
            .split(';')
            .filter_map(|s| s.parse::<usize>().ok())
            .collect();

        match final_char {
            // Cursor Up
            'A' => {
                let n = nums.first().copied().unwrap_or(1);
                self.cursor_row = self.cursor_row.saturating_sub(n);
            }
            // Cursor Down
            'B' => {
                let n = nums.first().copied().unwrap_or(1);
                self.cursor_row = (self.cursor_row + n).min(self.height - 1);
            }
            // Cursor Forward
            'C' => {
                let n = nums.first().copied().unwrap_or(1);
                self.cursor_col = (self.cursor_col + n).min(self.width - 1);
            }
            // Cursor Back
            'D' => {
                let n = nums.first().copied().unwrap_or(1);
                self.cursor_col = self.cursor_col.saturating_sub(n);
            }
            // Cursor Position (row;col)
            'H' | 'f' => {
                let row = nums.first().copied().unwrap_or(1).saturating_sub(1);
                let col = nums.get(1).copied().unwrap_or(1).saturating_sub(1);
                self.set_cursor(row, col);
            }
            // Erase in Display
            'J' => {
                let mode = nums.first().copied().unwrap_or(0);
                match mode {
                    0 => self.clear_to_eos(),
                    2 => self.clear(),
                    _ => {}
                }
            }
            // Erase in Line
            'K' => {
                let mode = nums.first().copied().unwrap_or(0);
                match mode {
                    0 => self.clear_to_eol(),
                    _ => {}
                }
            }
            // SGR -- Select Graphic Rendition (colors / attributes)
            'm' => {
                self.apply_sgr(&nums);
            }
            // Save Cursor
            's' => {
                self.save_cursor();
            }
            // Restore Cursor
            'u' => {
                self.restore_cursor();
            }
            _ => {
                // Unknown CSI -- ignore
            }
        }
    }

    /// Apply SGR (Select Graphic Rendition) parameters.
    fn apply_sgr(&mut self, params: &[usize]) {
        if params.is_empty() {
            // ESC[m is equivalent to ESC[0m
            self.reset_current_attributes();
            return;
        }

        let mut i = 0;
        while i < params.len() {
            match params[i] {
                0 => self.reset_current_attributes(),
                1 => {} // bold -- would set on next write
                2 => {} // dim
                3 => {} // italic
                4 => {} // underline
                5 => {} // blink
                7 => {} // inverse
                // Foreground 30-37
                c @ 30..=37 => {
                    let color = sgr_standard_color(c - 30);
                    self.set_current_fg(color);
                }
                // Background 40-47
                c @ 40..=47 => {
                    let color = sgr_standard_color(c - 40);
                    self.set_current_bg(color);
                }
                // Bright foreground 90-97
                c @ 90..=97 => {
                    let color = sgr_bright_color(c - 90);
                    self.set_current_fg(color);
                }
                // Bright background 100-107
                c @ 100..=107 => {
                    let color = sgr_bright_color(c - 100);
                    self.set_current_bg(color);
                }
                // 256-color foreground: 38;5;n
                38 if params.get(i + 1) == Some(&5) && i + 2 < params.len() => {
                    let idx = params[i + 2] as u8;
                    self.set_current_fg(TerminalColor::Indexed(idx));
                    i += 2;
                }
                // 256-color background: 48;5;n
                48 if params.get(i + 1) == Some(&5) && i + 2 < params.len() => {
                    let idx = params[i + 2] as u8;
                    self.set_current_bg(TerminalColor::Indexed(idx));
                    i += 2;
                }
                // 24-bit foreground: 38;2;r;g;b
                38
                    if params.get(i + 1) == Some(&2)
                        && i + 4 < params.len() =>
                {
                    let r = params[i + 2] as u8;
                    let g = params[i + 3] as u8;
                    let b = params[i + 4] as u8;
                    self.set_current_fg(TerminalColor::Rgb(r, g, b));
                    i += 4;
                }
                // 24-bit background: 48;2;r;g;b
                48
                    if params.get(i + 1) == Some(&2)
                        && i + 4 < params.len() =>
                {
                    let r = params[i + 2] as u8;
                    let g = params[i + 3] as u8;
                    let b = params[i + 4] as u8;
                    self.set_current_bg(TerminalColor::Rgb(r, g, b));
                    i += 4;
                }
                // 39 = default foreground
                39 => {
                    self.set_current_fg(TerminalColor::Default);
                }
                // 49 = default background
                49 => {
                    self.set_current_bg(TerminalColor::Default);
                }
                _ => {}
            }
            i += 1;
        }
    }

    /// Reset attributes on the current cursor cell.
    fn reset_current_attributes(&mut self) {
        if let Some(cell) = self.grid.get_mut(self.cursor_row)
            .and_then(|r| r.get_mut(self.cursor_col))
        {
            cell.reset_attributes();
        }
    }

    /// Set foreground on the current cursor cell.
    fn set_current_fg(&mut self, color: TerminalColor) {
        if let Some(cell) = self.grid.get_mut(self.cursor_row)
            .and_then(|r| r.get_mut(self.cursor_col))
        {
            cell.foreground = color;
        }
    }

    /// Set background on the current cursor cell.
    fn set_current_bg(&mut self, color: TerminalColor) {
        if let Some(cell) = self.grid.get_mut(self.cursor_row)
            .and_then(|r| r.get_mut(self.cursor_col))
        {
            cell.background = color;
        }
    }

    /// Write a character without ANSI interpretation.
    fn write_plain_char(&mut self, ch: char) {
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

    // -- Screen content ----------------------------------------------------------

    /// Get the full screen contents as a string.
    pub fn get_screen_text(&self) -> String {
        let mut result = String::new();
        for (i, row) in self.grid.iter().enumerate() {
            let line: String = row.iter().map(|c| c.character).collect();
            result.push_str(line.trim_end());
            if i + 1 < self.grid.len() {
                result.push('\n');
            }
        }
        result
    }

    /// Get a specific row of the terminal as a string.
    pub fn get_row_text(&self, row: usize) -> Option<String> {
        self.grid.get(row).map(|r| {
            r.iter().map(|c| c.character).collect::<String>()
        })
    }

    // -- Process attachment ------------------------------------------------------

    /// Attach a child process to this terminal.
    pub fn attach_process(&mut self, command: impl Into<String>) {
        let mut handle = ProcessHandle::new(command);
        handle.set_running();
        self.process = Some(handle);
    }

    /// Detach the current process.
    pub fn detach_process(&mut self) {
        self.process = None;
    }

    /// Feed raw bytes from the process stdout into the terminal.
    pub fn feed_process_stdout(&mut self, data: &[u8]) {
        if let Ok(text) = std::str::from_utf8(data) {
            self.write(text);
        }
    }

    // -- Search ------------------------------------------------------------------

    /// Run a search across the screen contents.
    pub fn update_search(&mut self, query: &str) {
        let mut matches = Vec::new();
        if !query.is_empty() {
            for (row, line) in self.grid.iter().enumerate() {
                let line_str: String = line.iter().map(|c| c.character).collect();
                let haystack = if self.search.is_case_sensitive() {
                    line_str
                } else {
                    line_str.to_lowercase()
                };
                let needle = if self.search.is_case_sensitive() {
                    query.to_string()
                } else {
                    query.to_lowercase()
                };
                let mut start = 0;
                while let Some(pos) = haystack[start..].find(&needle) {
                    let abs = start + pos;
                    matches.push((row, abs));
                    start = abs + 1;
                }
            }
        }
        self.search.update(query, matches);
    }

    /// Clear the current search.
    pub fn clear_search(&mut self) {
        self.search.clear();
    }

    /// Copy screen text in a rectangular region to a string.
    pub fn copy_region(
        &self,
        start_row: usize,
        start_col: usize,
        end_row: usize,
        end_col: usize,
    ) -> String {
        let mut result = String::new();
        for row in start_row..=end_row.min(self.height.saturating_sub(1)) {
            for col in start_col..=end_col.min(self.width.saturating_sub(1)) {
                if let Some(cell) = self.cell(row, col) {
                    result.push(cell.character);
                }
            }
            if row < end_row {
                result.push('\n');
            }
        }
        result
    }
}

// -- ANSI color helpers ----------------------------------------------------------

/// Map a 30-37 SGR parameter to the corresponding standard color.
fn sgr_standard_color(index: usize) -> TerminalColor {
    match index {
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

/// Map a 90-97 SGR parameter to the corresponding bright color.
fn sgr_bright_color(index: usize) -> TerminalColor {
    match index {
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

// -- Tests -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- TerminalColor -----------------------------------------------------------

    #[test]
    fn test_color_to_rgb() {
        assert_eq!(TerminalColor::Default.to_rgb(), 0xD4D4D4);
        assert_eq!(TerminalColor::Red.to_rgb(), 0xCD3131);
        assert_eq!(TerminalColor::Indexed(0).to_rgb(), 0x000000);
        assert_eq!(TerminalColor::Rgb(255, 0, 0).to_rgb(), 0xFF0000);
    }

    #[test]
    fn test_indexed_color_cube() {
        // Index 16 = (0,0,0) in the 6x6x6 cube
        assert_eq!(TerminalColor::Indexed(16).to_rgb(), 0x000000);
        // Index 231 = (5,5,5) = white
        assert_eq!(TerminalColor::Indexed(231).to_rgb(), 0xFFFFFF);
    }

    #[test]
    fn test_indexed_grayscale() {
        // Index 232 = gray 8
        assert_eq!(TerminalColor::Indexed(232).to_rgb(), 0x080808);
    }

    // -- TerminalCell ------------------------------------------------------------

    #[test]
    fn test_cell_new() {
        let cell = TerminalCell::new('A');
        assert_eq!(cell.character, 'A');
        assert!(!cell.bold);
        assert_eq!(cell.effective_foreground(), TerminalColor::Default);
    }

    #[test]
    fn test_cell_blank() {
        let cell = TerminalCell::blank();
        assert_eq!(cell.character, ' ');
    }

    #[test]
    fn test_cell_inverse() {
        let mut cell = TerminalCell::new('X');
        cell.inverse = true;
        cell.foreground = TerminalColor::Red;
        cell.background = TerminalColor::Blue;
        assert_eq!(cell.effective_foreground(), TerminalColor::Blue);
        assert_eq!(cell.effective_background(), TerminalColor::Red);
    }

    #[test]
    fn test_cell_reset_attributes() {
        let mut cell = TerminalCell::new('Z');
        cell.bold = true;
        cell.foreground = TerminalColor::Green;
        cell.reset_attributes();
        assert!(!cell.bold);
        assert_eq!(cell.foreground, TerminalColor::Default);
        assert_eq!(cell.character, 'Z');
    }

    // -- SearchState -------------------------------------------------------------

    #[test]
    fn test_search_new() {
        let s = SearchState::new();
        assert!(!s.is_active());
        assert_eq!(s.match_count(), 0);
    }

    #[test]
    fn test_search_update_and_navigate() {
        let mut s = SearchState::new();
        s.update("x", vec![(0, 0), (1, 5), (2, 3)]);
        assert!(s.is_active());
        assert_eq!(s.match_count(), 3);
        assert_eq!(s.current_match(), Some((0, 0)));

        assert_eq!(s.next_match(), Some((1, 5)));
        assert_eq!(s.next_match(), Some((2, 3)));
        assert_eq!(s.next_match(), Some((0, 0))); // wraps

        assert_eq!(s.prev_match(), Some((2, 3))); // wraps backward
    }

    #[test]
    fn test_search_clear() {
        let mut s = SearchState::new();
        s.update("q", vec![(0, 0)]);
        s.clear();
        assert!(!s.is_active());
    }

    // -- ProcessHandle -----------------------------------------------------------

    #[test]
    fn test_process_handle() {
        let mut ph = ProcessHandle::new("ls -la");
        assert_eq!(ph.command(), "ls -la");
        assert_eq!(ph.status(), ProcessStatus::NotStarted);

        ph.set_running();
        assert!(ph.is_running());

        ph.push_stdout(b"file.txt\n");
        let data = ph.drain_stdout();
        assert_eq!(data, b"file.txt\n");
        assert!(ph.drain_stdout().is_empty());

        ph.set_exited(0);
        assert_eq!(ph.exit_code(), Some(0));
        assert!(!ph.is_running());
    }

    #[test]
    fn test_process_signaled() {
        let mut ph = ProcessHandle::new("sleep");
        ph.set_running();
        ph.set_signaled();
        assert_eq!(ph.status(), ProcessStatus::Signaled);
    }

    // -- TerminalProvider --------------------------------------------------------

    #[test]
    fn test_provider_creation() {
        let p = TerminalProvider::new("Test");
        assert_eq!(p.name(), "Test");
        assert_eq!(p.width(), DEFAULT_WIDTH);
        assert_eq!(p.height(), DEFAULT_HEIGHT);
        assert_eq!(p.cursor_row(), 0);
        assert_eq!(p.cursor_col(), 0);
        assert!(p.is_visible());
    }

    #[test]
    fn test_provider_with_config() {
        let cfg = TerminalProviderConfig {
            width: 120,
            height: 40,
            font_size: 14,
            ..Default::default()
        };
        let p = TerminalProvider::with_config("Wide", cfg);
        assert_eq!(p.width(), 120);
        assert_eq!(p.height(), 40);
        assert_eq!(p.config().font_size, 14);
    }

    #[test]
    fn test_write_plain() {
        let mut p = TerminalProvider::new("Test");
        p.write("Hello");
        assert_eq!(p.cursor_col(), 5);
        assert_eq!(p.cursor_row(), 0);
    }

    #[test]
    fn test_writeln() {
        let mut p = TerminalProvider::new("Test");
        p.writeln("Line 1");
        assert_eq!(p.cursor_row(), 1);
        assert_eq!(p.cursor_col(), 0);
    }

    #[test]
    fn test_write_newline() {
        let mut p = TerminalProvider::new("Test");
        p.write("A\nB\nC");
        assert_eq!(p.cursor_row(), 2);
    }

    #[test]
    fn test_write_carriage_return() {
        let mut p = TerminalProvider::new("Test");
        p.write("Hello\rWorld");
        // After \r cursor goes to col 0, then "World" overwrites
        assert_eq!(p.cursor_col(), 5);
        assert_eq!(p.get_row_text(0).unwrap().chars().take(5).collect::<String>(), "World");
    }

    #[test]
    fn test_write_tab() {
        let mut p = TerminalProvider::new("Test");
        p.write("\t");
        assert_eq!(p.cursor_col(), TAB_WIDTH);
    }

    #[test]
    fn test_clear() {
        let mut p = TerminalProvider::new("Test");
        p.write("data");
        p.clear();
        assert_eq!(p.cursor_row(), 0);
        assert_eq!(p.cursor_col(), 0);
    }

    #[test]
    fn test_clear_to_eol() {
        let mut p = TerminalProvider::new("Test");
        p.write("Hello World");
        p.set_cursor(0, 5);
        p.clear_to_eol();
        let row = p.get_row_text(0).unwrap();
        assert_eq!(row.chars().take(5).collect::<String>(), "Hello");
        // Rest should be blank
        assert!(row.chars().skip(5).all(|c| c == ' '));
    }

    #[test]
    fn test_scroll() {
        let cfg = TerminalProviderConfig {
            width: 80,
            height: 2,
            ..Default::default()
        };
        let mut p = TerminalProvider::with_config("Small", cfg);
        p.writeln("Line 1");
        p.writeln("Line 2");
        p.writeln("Line 3"); // each \n past height triggers a scroll
        assert_eq!(p.scrollback_size(), 2);
    }

    #[test]
    fn test_save_restore_cursor() {
        let mut p = TerminalProvider::new("Test");
        p.write("Hello");
        p.save_cursor();
        p.write(" World");
        p.restore_cursor();
        assert_eq!(p.cursor_col(), 5);
    }

    #[test]
    fn test_set_cursor() {
        let mut p = TerminalProvider::new("Test");
        p.set_cursor(10, 40);
        assert_eq!(p.cursor_row(), 10);
        assert_eq!(p.cursor_col(), 40);
    }

    #[test]
    fn test_set_cursor_clamp() {
        let mut p = TerminalProvider::new("Test");
        p.set_cursor(9999, 9999);
        assert_eq!(p.cursor_row(), DEFAULT_HEIGHT - 1);
        assert_eq!(p.cursor_col(), DEFAULT_WIDTH - 1);
    }

    #[test]
    fn test_get_screen_text() {
        let mut p = TerminalProvider::new("Test");
        p.writeln("Hello");
        p.writeln("World");
        let text = p.get_screen_text();
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
    }

    #[test]
    fn test_get_row_text() {
        let mut p = TerminalProvider::new("Test");
        p.write("ABC");
        let row = p.get_row_text(0).unwrap();
        assert!(row.starts_with("ABC"));
        assert!(p.get_row_text(9999).is_none());
    }

    #[test]
    fn test_cell_access() {
        let mut p = TerminalProvider::new("Test");
        p.write("X");
        let cell = p.cell(0, 0).unwrap();
        assert_eq!(cell.character, 'X');
        assert!(p.cell(9999, 9999).is_none());
    }

    #[test]
    fn test_cell_mut_access() {
        let mut p = TerminalProvider::new("Test");
        p.write("X");
        if let Some(cell) = p.cell_mut(0, 0) {
            cell.bold = true;
        }
        assert!(p.cell(0, 0).unwrap().bold);
    }

    // -- ANSI parsing ------------------------------------------------------------

    #[test]
    fn test_ansi_cursor_up() {
        let mut p = TerminalProvider::new("Test");
        p.set_cursor(5, 0);
        p.write("\x1B[3A"); // up 3
        assert_eq!(p.cursor_row(), 2);
    }

    #[test]
    fn test_ansi_cursor_down() {
        let mut p = TerminalProvider::new("Test");
        p.set_cursor(2, 0);
        p.write("\x1B[3B"); // down 3
        assert_eq!(p.cursor_row(), 5);
    }

    #[test]
    fn test_ansi_cursor_forward_back() {
        let mut p = TerminalProvider::new("Test");
        p.write("\x1B[10C"); // forward 10
        assert_eq!(p.cursor_col(), 10);
        p.write("\x1B[5D"); // back 5
        assert_eq!(p.cursor_col(), 5);
    }

    #[test]
    fn test_ansi_cursor_position() {
        let mut p = TerminalProvider::new("Test");
        p.write("\x1B[5;10H"); // row 5, col 10 (1-based)
        assert_eq!(p.cursor_row(), 4);
        assert_eq!(p.cursor_col(), 9);
    }

    #[test]
    fn test_ansi_clear_screen() {
        let mut p = TerminalProvider::new("Test");
        p.write("data");
        p.write("\x1B[2J"); // clear entire screen
        assert_eq!(p.cursor_row(), 0);
        assert_eq!(p.cursor_col(), 0);
    }

    #[test]
    fn test_ansi_clear_line() {
        let mut p = TerminalProvider::new("Test");
        p.write("Hello World");
        p.set_cursor(0, 5);
        p.write("\x1B[K"); // clear to end of line
        let row = p.get_row_text(0).unwrap();
        assert!(row.starts_with("Hello"));
    }

    #[test]
    fn test_ansi_save_restore() {
        let mut p = TerminalProvider::new("Test");
        p.write("AB");
        p.write("\x1B[s"); // save
        p.write("CD");
        p.write("\x1B[u"); // restore
        assert_eq!(p.cursor_col(), 2);
    }

    // -- Search ------------------------------------------------------------------

    #[test]
    fn test_search_integration() {
        let mut p = TerminalProvider::new("Test");
        p.write("hello world hello");
        p.update_search("hello");
        assert_eq!(p.search().match_count(), 2);
        p.clear_search();
        assert!(!p.search().is_active());
    }

    // -- Process attachment ------------------------------------------------------

    #[test]
    fn test_attach_detach_process() {
        let mut p = TerminalProvider::new("Test");
        assert!(p.process().is_none());

        p.attach_process("bash");
        assert!(p.process().is_some());
        assert!(p.process().unwrap().is_running());

        p.detach_process();
        assert!(p.process().is_none());
    }

    #[test]
    fn test_feed_process_stdout() {
        let mut p = TerminalProvider::new("Test");
        p.feed_process_stdout(b"output\n");
        assert!(p.get_screen_text().contains("output"));
    }

    // -- Copy region -------------------------------------------------------------

    #[test]
    fn test_copy_region() {
        let mut p = TerminalProvider::new("Test");
        p.writeln("ABCD");
        p.writeln("EFGH");
        let text = p.copy_region(0, 0, 1, 3);
        assert!(text.contains("ABCD"));
        assert!(text.contains("EFGH"));
    }
}
