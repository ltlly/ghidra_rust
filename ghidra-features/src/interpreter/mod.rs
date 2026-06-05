//! Interpreter panel plugin for embedded script execution.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.interpreter` package.
//!
//! Provides the interpreter console panel that allows running scripts
//! (Jython, Groovy, etc.) interactively within Ghidra. Includes ANSI
//! terminal rendering, command history, and code completion.
//!
//! # Key Types
//!
//! - [`InterpreterPanelPlugin`] -- Plugin providing the interpreter panel
//! - [`InterpreterConsole`] -- Trait for interpreter console operations
//! - [`HistoryManager`] -- Manages command history
//! - [`AnsiStyle`] -- ANSI escape code style attributes
//! - [`InterpreterOptions`] -- Configuration for the interpreter

use std::collections::VecDeque;

/// Default history size.
pub const DEFAULT_HISTORY_SIZE: usize = 500;

/// Maximum output buffer size in characters.
pub const MAX_OUTPUT_BUFFER: usize = 100_000;

// ---------------------------------------------------------------------------
// ANSI styling
// ---------------------------------------------------------------------------

/// ANSI style attributes parsed from terminal escape sequences.
///
/// Ported from `ghidra.app.plugin.core.interpreter.AnsiParser`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsiStyle {
    /// Foreground color index (0-255) or None for default.
    pub foreground: Option<u8>,
    /// Background color index (0-255) or None for default.
    pub background: Option<u8>,
    /// Whether the text is bold.
    pub bold: bool,
    /// Whether the text is italic.
    pub italic: bool,
    /// Whether the text is underlined.
    pub underline: bool,
    /// Whether the text has strikethrough.
    pub strikethrough: bool,
}

impl Default for AnsiStyle {
    fn default() -> Self {
        Self {
            foreground: None,
            background: None,
            bold: false,
            italic: false,
            underline: false,
            strikethrough: false,
        }
    }
}

impl AnsiStyle {
    /// Reset to default style.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Whether this style has any non-default attributes.
    pub fn has_attributes(&self) -> bool {
        self.foreground.is_some()
            || self.background.is_some()
            || self.bold
            || self.italic
            || self.underline
            || self.strikethrough
    }
}

/// A styled text segment (text with ANSI attributes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StyledSegment {
    /// The text content.
    pub text: String,
    /// The style applied to this segment.
    pub style: AnsiStyle,
}

impl StyledSegment {
    /// Create a plain (unstyled) segment.
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            style: AnsiStyle::default(),
        }
    }

    /// Create a styled segment.
    pub fn styled(text: impl Into<String>, style: AnsiStyle) -> Self {
        Self {
            text: text.into(),
            style,
        }
    }
}

// ---------------------------------------------------------------------------
// History manager
// ---------------------------------------------------------------------------

/// Manages command history for the interpreter.
///
/// Ported from `ghidra.app.plugin.core.interpreter.HistoryManagerImpl`.
#[derive(Debug)]
pub struct HistoryManager {
    /// Previous commands.
    history: VecDeque<String>,
    /// Current position in history navigation.
    position: Option<usize>,
    /// Maximum history size.
    max_size: usize,
    /// Current input being edited (saved when navigating history).
    saved_input: String,
}

impl HistoryManager {
    /// Create a new history manager.
    pub fn new() -> Self {
        Self {
            history: VecDeque::new(),
            position: None,
            max_size: DEFAULT_HISTORY_SIZE,
            saved_input: String::new(),
        }
    }

    /// Create a history manager with a custom max size.
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            max_size,
            ..Self::new()
        }
    }

    /// Add a command to the history.
    pub fn add(&mut self, command: impl Into<String>) {
        let cmd = command.into();
        if cmd.is_empty() {
            return;
        }
        // Remove duplicate if it's the same as the last entry
        if self.history.back() != Some(&cmd) {
            if self.history.len() >= self.max_size {
                self.history.pop_front();
            }
            self.history.push_back(cmd);
        }
        self.position = None;
        self.saved_input.clear();
    }

    /// Navigate to the previous command (up arrow).
    pub fn previous(&mut self, current_input: &str) -> Option<&str> {
        if self.history.is_empty() {
            return None;
        }

        let new_pos = match self.position {
            None => self.history.len() - 1,
            Some(0) => return Some(&self.history[0]),
            Some(p) => p - 1,
        };

        if self.position.is_none() {
            self.saved_input = current_input.to_string();
        }
        self.position = Some(new_pos);
        self.history.get(new_pos).map(|s| s.as_str())
    }

    /// Navigate to the next command (down arrow).
    pub fn next(&mut self) -> Option<&str> {
        match self.position {
            None => None,
            Some(p) if p >= self.history.len() - 1 => {
                self.position = None;
                Some(&self.saved_input)
            }
            Some(p) => {
                self.position = Some(p + 1);
                self.history.get(p + 1).map(|s| s.as_str())
            }
        }
    }

    /// Get the current history size.
    pub fn len(&self) -> usize {
        self.history.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }

    /// Get all history entries.
    pub fn entries(&self) -> &VecDeque<String> {
        &self.history
    }

    /// Clear the history.
    pub fn clear(&mut self) {
        self.history.clear();
        self.position = None;
        self.saved_input.clear();
    }
}

impl Default for HistoryManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Interpreter console trait
// ---------------------------------------------------------------------------

/// Trait for interpreter console operations.
///
/// Ported from `ghidra.app.plugin.core.interpreter.InterpreterConsole`.
pub trait InterpreterConsole: Send + Sync {
    /// Append text to the console output.
    fn append_output(&mut self, text: &str);

    /// Append styled text to the console output.
    fn append_styled_output(&mut self, segment: &StyledSegment);

    /// Clear the console.
    fn clear(&mut self);

    /// Set the input prompt.
    fn set_prompt(&mut self, prompt: &str);

    /// Whether the console is ready for input.
    fn is_ready(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Interpreter options
// ---------------------------------------------------------------------------

/// Configuration for the interpreter panel.
#[derive(Debug, Clone)]
pub struct InterpreterOptions {
    /// The interpreter language (e.g., "jython", "groovy").
    pub language: String,
    /// The initial script to run on startup.
    pub startup_script: Option<String>,
    /// Maximum number of history entries.
    pub history_size: usize,
    /// Whether to show timestamps in output.
    pub show_timestamps: bool,
    /// The prompt string.
    pub prompt: String,
}

impl Default for InterpreterOptions {
    fn default() -> Self {
        Self {
            language: "jython".to_string(),
            startup_script: None,
            history_size: DEFAULT_HISTORY_SIZE,
            show_timestamps: false,
            prompt: ">>> ".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Interpreter panel plugin
// ---------------------------------------------------------------------------

/// Plugin providing the interpreter panel.
///
/// Ported from `ghidra.app.plugin.core.interpreter.InterpreterPanelPlugin`.
#[derive(Debug)]
pub struct InterpreterPanelPlugin {
    /// Command history.
    history: HistoryManager,
    /// Configuration options.
    options: InterpreterOptions,
    /// Output buffer.
    output: Vec<StyledSegment>,
    /// Whether the panel is visible.
    visible: bool,
}

impl InterpreterPanelPlugin {
    /// Create a new interpreter panel plugin.
    pub fn new() -> Self {
        Self {
            history: HistoryManager::new(),
            options: InterpreterOptions::default(),
            output: Vec::new(),
            visible: false,
        }
    }

    /// Get the history manager.
    pub fn history(&self) -> &HistoryManager {
        &self.history
    }

    /// Get a mutable reference to the history manager.
    pub fn history_mut(&mut self) -> &mut HistoryManager {
        &mut self.history
    }

    /// Get the options.
    pub fn options(&self) -> &InterpreterOptions {
        &self.options
    }

    /// Submit a command for execution.
    pub fn submit_command(&mut self, command: impl Into<String>) {
        let cmd = command.into();
        self.history.add(&cmd);
        self.output.push(StyledSegment::plain(format!(
            "{}{}\n",
            self.options.prompt, cmd
        )));
        // Trim output buffer if too large
        while self.output.len() > MAX_OUTPUT_BUFFER / 80 {
            self.output.remove(0);
        }
    }

    /// Append output text.
    pub fn append_output(&mut self, text: impl Into<String>) {
        self.output.push(StyledSegment::plain(text.into()));
    }

    /// Get the output buffer.
    pub fn output(&self) -> &[StyledSegment] {
        &self.output
    }

    /// Clear the output.
    pub fn clear_output(&mut self) {
        self.output.clear();
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the panel is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

impl Default for InterpreterPanelPlugin {
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
    fn test_ansi_style_default() {
        let style = AnsiStyle::default();
        assert!(!style.has_attributes());
        assert!(!style.bold);
        assert!(style.foreground.is_none());
    }

    #[test]
    fn test_ansi_style_reset() {
        let mut style = AnsiStyle {
            foreground: Some(1),
            bold: true,
            ..Default::default()
        };
        assert!(style.has_attributes());
        style.reset();
        assert!(!style.has_attributes());
    }

    #[test]
    fn test_styled_segment() {
        let seg = StyledSegment::plain("hello");
        assert_eq!(seg.text, "hello");
        assert!(!seg.style.has_attributes());
    }

    #[test]
    fn test_history_manager_add() {
        let mut hm = HistoryManager::new();
        assert!(hm.is_empty());

        hm.add("first");
        hm.add("second");
        hm.add("third");
        assert_eq!(hm.len(), 3);
    }

    #[test]
    fn test_history_manager_duplicate() {
        let mut hm = HistoryManager::new();
        hm.add("cmd");
        hm.add("cmd");
        assert_eq!(hm.len(), 1);
    }

    #[test]
    fn test_history_manager_navigation() {
        let mut hm = HistoryManager::new();
        hm.add("first");
        hm.add("second");
        hm.add("third");

        assert_eq!(hm.previous(""), Some("third"));
        assert_eq!(hm.previous(""), Some("second"));
        assert_eq!(hm.previous(""), Some("first"));
        assert_eq!(hm.previous(""), Some("first")); // at top

        assert_eq!(hm.next(), Some("second"));
        assert_eq!(hm.next(), Some("third"));
    }

    #[test]
    fn test_history_manager_max_size() {
        let mut hm = HistoryManager::with_max_size(2);
        hm.add("a");
        hm.add("b");
        hm.add("c");
        assert_eq!(hm.len(), 2);
        let entries: Vec<&str> = hm.entries().iter().map(|s| s.as_str()).collect();
        assert_eq!(entries, vec!["b", "c"]);
    }

    #[test]
    fn test_history_manager_empty_navigation() {
        let mut hm = HistoryManager::new();
        assert!(hm.previous("").is_none());
        assert!(hm.next().is_none());
    }

    #[test]
    fn test_history_manager_clear() {
        let mut hm = HistoryManager::new();
        hm.add("a");
        hm.add("b");
        hm.clear();
        assert!(hm.is_empty());
    }

    #[test]
    fn test_interpreter_options_default() {
        let opts = InterpreterOptions::default();
        assert_eq!(opts.language, "jython");
        assert_eq!(opts.prompt, ">>> ");
        assert!(!opts.show_timestamps);
    }

    #[test]
    fn test_interpreter_panel_plugin() {
        let mut plugin = InterpreterPanelPlugin::new();
        assert!(!plugin.is_visible());
        assert!(plugin.output().is_empty());

        plugin.set_visible(true);
        plugin.submit_command("print('hello')");
        assert_eq!(plugin.history().len(), 1);
        assert_eq!(plugin.output().len(), 1);

        plugin.append_output("hello\n");
        assert_eq!(plugin.output().len(), 2);

        plugin.clear_output();
        assert!(plugin.output().is_empty());
    }
}

// ============================================================================
// ANSI Parser -- regex-based CSI/OSC sequence parsing
//
// Ported from Ghidra's `AnsiParser.java` and `AnsiRenderer.java`.
//
// Processes a text stream and invokes callbacks for ANSI escape sequences
// including CSI (Control Sequence Introducer) and OSC (Operating System
// Command) sequences.
// ============================================================================

/// Callbacks for ANSI escape sequence parsing.
///
/// Ported from `AnsiParser.AnsiParserHandler`.
pub trait AnsiParserHandler {
    /// A portion of plain text (no escape sequences).
    fn handle_string(&mut self, text: &str);

    /// A CSI sequence was parsed.
    ///
    /// * `param` -- parameter bytes (0-9:;<=\>?)
    /// * `inter` -- intermediate bytes (space through /)
    /// * `final_char` -- the final byte (@ through ~)
    fn handle_csi(&mut self, param: &str, inter: &str, final_char: char);

    /// An OSC sequence was parsed.
    ///
    /// * `param` -- the OSC parameter text
    fn handle_osc(&mut self, param: &str);
}

/// ANSI escape sequence parser with buffered streaming support.
///
/// Ported from `ghidra.app.plugin.core.interpreter.AnsiParser`.
///
/// The parser uses regex-like pattern matching to detect CSI and OSC
/// sequences. It buffers incomplete sequences across calls to
/// [`process_string`](AnsiParser::process_string).
pub struct AnsiParser {
    buffer: String,
}

impl AnsiParser {
    /// Create a new ANSI parser.
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
        }
    }

    /// Process input text, invoking callbacks on the handler.
    ///
    /// The parser buffers incomplete escape sequences so that input can be
    /// streamed incrementally.
    pub fn process_string<H: AnsiParserHandler>(&mut self, text: &str, handler: &mut H) {
        self.buffer.push_str(text);
        let bytes = self.buffer.as_bytes();
        let len = bytes.len();
        let mut pos = 0;
        let mut last_emit = 0;

        while pos < len {
            if bytes[pos] == 0x1b {
                // ESC -- potential escape sequence
                if pos + 1 >= len {
                    // Incomplete ESC at end of buffer
                    break;
                }

                match bytes[pos + 1] {
                    b'[' => {
                        // CSI sequence: ESC [ <param> <inter> <final>
                        if let Some((consumed, param, inter, final_char)) =
                            parse_csi(&bytes[pos..])
                        {
                            if last_emit < pos {
                                handler.handle_string(&self.buffer[last_emit..pos]);
                            }
                            handler.handle_csi(&param, &inter, final_char);
                            pos += consumed;
                            last_emit = pos;
                            continue;
                        } else {
                            // Incomplete CSI
                            break;
                        }
                    }
                    b']' => {
                        // OSC sequence: ESC ] <param> (ST | BEL)
                        if let Some((consumed, param)) = parse_osc(&bytes[pos..]) {
                            if last_emit < pos {
                                handler.handle_string(&self.buffer[last_emit..pos]);
                            }
                            handler.handle_osc(&param);
                            pos += consumed;
                            last_emit = pos;
                            continue;
                        } else {
                            // Incomplete OSC
                            break;
                        }
                    }
                    _ => {
                        // Not a recognized sequence start; emit ESC as text
                        pos += 1;
                    }
                }
            } else if bytes[pos] == 0x00 {
                // NUL byte -- suppress (TTY padding)
                if last_emit < pos {
                    handler.handle_string(&self.buffer[last_emit..pos]);
                }
                pos += 1;
                last_emit = pos;
            } else {
                pos += 1;
            }
        }

        // Emit any remaining text before an incomplete sequence
        if last_emit < pos {
            handler.handle_string(&self.buffer[last_emit..pos]);
        }

        // Keep only the incomplete tail in the buffer
        if pos < len {
            self.buffer = self.buffer[pos..].to_string();
        } else {
            self.buffer.clear();
        }
    }
}

impl Default for AnsiParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Try to parse a CSI sequence from the byte slice.
///
/// CSI: ESC [ <param bytes 0x30-0x3F>* <inter bytes 0x20-0x2F>* <final 0x40-0x7E>
///
/// Returns `(consumed_bytes, param, inter, final_char)` or `None` if incomplete.
fn parse_csi(bytes: &[u8]) -> Option<(usize, String, String, char)> {
    if bytes.len() < 3 || bytes[0] != 0x1b || bytes[1] != b'[' {
        return None;
    }

    let mut pos = 2;
    let param_start = pos;

    // Parameter bytes: 0x30-0x3F
    while pos < bytes.len() && (0x30..=0x3F).contains(&bytes[pos]) {
        pos += 1;
    }
    let param = String::from_utf8_lossy(&bytes[param_start..pos]).to_string();

    let inter_start = pos;
    // Intermediate bytes: 0x20-0x2F
    while pos < bytes.len() && (0x20..=0x2F).contains(&bytes[pos]) {
        pos += 1;
    }
    let inter = String::from_utf8_lossy(&bytes[inter_start..pos]).to_string();

    // Final byte: 0x40-0x7E
    if pos < bytes.len() && (0x40..=0x7E).contains(&bytes[pos]) {
        let final_char = bytes[pos] as char;
        pos += 1;
        Some((pos, param, inter, final_char))
    } else {
        None // incomplete sequence
    }
}

/// Try to parse an OSC sequence from the byte slice.
///
/// OSC: ESC ] <param> (BEL | ST)
///   where BEL = 0x07, ST = ESC \
///
/// Returns `(consumed_bytes, param)` or `None` if incomplete.
fn parse_osc(bytes: &[u8]) -> Option<(usize, String)> {
    if bytes.len() < 2 || bytes[0] != 0x1b || bytes[1] != b']' {
        return None;
    }

    let mut pos = 2;
    let param_start = pos;

    // Parameter: any non-control byte (0x20-0x7F)
    while pos < bytes.len() && bytes[pos] >= 0x20 && bytes[pos] != 0x7f {
        pos += 1;
    }
    let param = String::from_utf8_lossy(&bytes[param_start..pos]).to_string();

    // Terminated by BEL (0x07) or ST (ESC \)
    if pos < bytes.len() {
        if bytes[pos] == 0x07 {
            return Some((pos + 1, param));
        }
        if bytes[pos] == 0x1b && pos + 1 < bytes.len() && bytes[pos + 1] == b'\\' {
            return Some((pos + 2, param));
        }
    }

    None // incomplete
}

// ---------------------------------------------------------------------------
// ANSI Renderer -- applies SGR attributes to produce styled segments
// ---------------------------------------------------------------------------

/// ANSI 256-color palette.
///
/// Ported from `AnsiRenderer.BASIC_COLORS` and `CUBE_STEPS`.
pub mod ansi_colors {
    /// Standard ANSI colors (0-7).
    pub const STANDARD_COLORS: [(u8, u8, u8); 8] = [
        (0, 0, 0),       // 0: Black
        (128, 0, 0),     // 1: Red
        (0, 128, 0),     // 2: Green
        (128, 128, 0),   // 3: Yellow
        (0, 0, 128),     // 4: Blue
        (128, 0, 128),   // 5: Magenta
        (0, 128, 128),   // 6: Cyan
        (192, 192, 192), // 7: White
    ];

    /// High-intensity ANSI colors (8-15).
    pub const HIGH_INTENSITY_COLORS: [(u8, u8, u8); 8] = [
        (128, 128, 128), // 8: Bright Black (Gray)
        (255, 0, 0),     // 9: Bright Red
        (0, 255, 0),     // 10: Bright Green
        (255, 255, 0),   // 11: Bright Yellow
        (0, 0, 255),     // 12: Bright Blue
        (255, 0, 255),   // 13: Bright Magenta
        (0, 255, 255),   // 14: Bright Cyan
        (255, 255, 255), // 15: Bright White
    ];

    /// The 6x6x6 color cube steps (values mapped to 0-255).
    pub const CUBE_STEPS: [u8; 6] = [0, 95, 135, 175, 215, 255];

    /// Get the RGB color for an 8-bit ANSI color code.
    pub fn get_256_color(code: u8) -> (u8, u8, u8) {
        match code {
            0..=7 => STANDARD_COLORS[code as usize],
            8..=15 => HIGH_INTENSITY_COLORS[(code - 8) as usize],
            16..=231 => {
                let v = (code - 16) as usize;
                let b = CUBE_STEPS[v % 6];
                let g = CUBE_STEPS[(v / 6) % 6];
                let r = CUBE_STEPS[(v / 36) % 6];
                (r, g, b)
            }
            232..=255 => {
                let gray = (code - 232) * 10 + 8;
                (gray, gray, gray)
            }
        }
    }
}

/// The result of processing a single SGR (Select Graphic Rendition) attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SgrEffect {
    /// Reset all attributes to default.
    Reset,
    /// Set bold.
    SetBold(bool),
    /// Set italic.
    SetItalic(bool),
    /// Set underline.
    SetUnderline(bool),
    /// Set strikethrough.
    SetStrikethrough(bool),
    /// Set foreground color.
    SetForeground((u8, u8, u8)),
    /// Set background color.
    SetBackground((u8, u8, u8)),
    /// Reset foreground to default.
    ResetForeground,
    /// Reset background to default.
    ResetBackground,
}

/// Parse SGR (Select Graphic Rendition) parameter codes.
///
/// Ported from `AnsiRenderer.ParserHandler.handleSGRAttribute()`.
///
/// Takes the semicolon-separated parameter string and returns a list of
/// style effects to apply.
pub fn parse_sgr(params: &str) -> Vec<SgrEffect> {
    if params.is_empty() {
        return vec![SgrEffect::Reset];
    }

    let bits: Vec<&str> = params.split(&[':', ';'][..]).collect();
    let mut effects = Vec::new();
    let mut i = 0;

    while i < bits.len() {
        let code: u32 = match bits[i].parse() {
            Ok(v) => v,
            Err(_) => {
                i += 1;
                continue;
            }
        };

        match code {
            0 => effects.push(SgrEffect::Reset),
            1 => effects.push(SgrEffect::SetBold(true)),
            2 => effects.push(SgrEffect::SetBold(false)),
            3 => effects.push(SgrEffect::SetItalic(true)),
            4 | 21 => effects.push(SgrEffect::SetUnderline(true)),
            9 => effects.push(SgrEffect::SetStrikethrough(true)),
            22 => effects.push(SgrEffect::SetBold(false)),
            23 => effects.push(SgrEffect::SetItalic(false)),
            24 => effects.push(SgrEffect::SetUnderline(false)),
            29 => effects.push(SgrEffect::SetStrikethrough(false)),
            30..=37 => {
                let color = ansi_colors::STANDARD_COLORS[(code - 30) as usize];
                effects.push(SgrEffect::SetForeground(color));
            }
            38 => {
                // Extended foreground color
                if i + 1 < bits.len() {
                    match bits[i + 1].parse::<u32>() {
                        Ok(5) if i + 2 < bits.len() => {
                            if let Ok(c) = bits[i + 2].parse::<u8>() {
                                effects.push(SgrEffect::SetForeground(ansi_colors::get_256_color(c)));
                                i += 3;
                                continue;
                            }
                        }
                        Ok(2) if i + 4 < bits.len() => {
                            if let (Ok(r), Ok(g), Ok(b)) = (
                                bits[i + 2].parse::<u8>(),
                                bits[i + 3].parse::<u8>(),
                                bits[i + 4].parse::<u8>(),
                            ) {
                                effects.push(SgrEffect::SetForeground((r, g, b)));
                                i += 5;
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
            }
            39 => effects.push(SgrEffect::ResetForeground),
            40..=47 => {
                let color = ansi_colors::STANDARD_COLORS[(code - 40) as usize];
                effects.push(SgrEffect::SetBackground(color));
            }
            48 => {
                // Extended background color
                if i + 1 < bits.len() {
                    match bits[i + 1].parse::<u32>() {
                        Ok(5) if i + 2 < bits.len() => {
                            if let Ok(c) = bits[i + 2].parse::<u8>() {
                                effects.push(SgrEffect::SetBackground(ansi_colors::get_256_color(c)));
                                i += 3;
                                continue;
                            }
                        }
                        Ok(2) if i + 4 < bits.len() => {
                            if let (Ok(r), Ok(g), Ok(b)) = (
                                bits[i + 2].parse::<u8>(),
                                bits[i + 3].parse::<u8>(),
                                bits[i + 4].parse::<u8>(),
                            ) {
                                effects.push(SgrEffect::SetBackground((r, g, b)));
                                i += 5;
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
            }
            49 => effects.push(SgrEffect::ResetBackground),
            90..=97 => {
                let color = ansi_colors::HIGH_INTENSITY_COLORS[(code - 90) as usize];
                effects.push(SgrEffect::SetForeground(color));
            }
            100..=107 => {
                let color = ansi_colors::HIGH_INTENSITY_COLORS[(code - 100) as usize];
                effects.push(SgrEffect::SetBackground(color));
            }
            _ => {} // Unknown code, ignore
        }
        i += 1;
    }

    effects
}

/// A simple ANSI renderer that converts text with ANSI escape codes
/// into a sequence of styled segments.
///
/// Ported from `ghidra.app.plugin.core.interpreter.AnsiRenderer`.
pub struct AnsiRenderer {
    parser: AnsiParser,
    segments: Vec<StyledSegment>,
    current_style: AnsiStyle,
}

impl AnsiRenderer {
    /// Create a new ANSI renderer.
    pub fn new() -> Self {
        Self {
            parser: AnsiParser::new(),
            segments: Vec::new(),
            current_style: AnsiStyle::default(),
        }
    }

    /// Render text with ANSI escape codes into styled segments.
    pub fn render(&mut self, text: &str) -> &[StyledSegment] {
        // Temporarily take the parser out to avoid double mutable borrow.
        let mut parser = std::mem::replace(&mut self.parser, AnsiParser::new());
        parser.process_string(text, self);
        self.parser = parser;
        &self.segments
    }

    /// Get the current segments and clear them.
    pub fn take_segments(&mut self) -> Vec<StyledSegment> {
        std::mem::take(&mut self.segments)
    }

    /// Reset the renderer state.
    pub fn reset(&mut self) {
        self.segments.clear();
        self.current_style = AnsiStyle::default();
        self.parser = AnsiParser::new();
    }
}

impl Default for AnsiRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl AnsiParserHandler for AnsiRenderer {
    fn handle_string(&mut self, text: &str) {
        if !text.is_empty() {
            self.segments
                .push(StyledSegment::styled(text, self.current_style.clone()));
        }
    }

    fn handle_csi(&mut self, param: &str, _inter: &str, final_char: char) {
        if final_char == 'm' {
            // SGR -- Select Graphic Rendition
            let effects = parse_sgr(param);
            for effect in effects {
                match effect {
                    SgrEffect::Reset => self.current_style.reset(),
                    SgrEffect::SetBold(v) => self.current_style.bold = v,
                    SgrEffect::SetItalic(v) => self.current_style.italic = v,
                    SgrEffect::SetUnderline(v) => self.current_style.underline = v,
                    SgrEffect::SetStrikethrough(v) => self.current_style.strikethrough = v,
                    SgrEffect::SetForeground(_color) => {
                        // Map RGB to a palette index (simplified)
                        self.current_style.foreground = Some(7); // default white
                    }
                    SgrEffect::SetBackground(_color) => {
                        self.current_style.background = Some(0); // default black
                    }
                    SgrEffect::ResetForeground => self.current_style.foreground = None,
                    SgrEffect::ResetBackground => self.current_style.background = None,
                }
            }
        }
        // All other CSI commands are ignored
    }

    fn handle_osc(&mut self, _param: &str) {
        // Ignore OSC commands
    }
}

// ---------------------------------------------------------------------------
// Code Completion Window model
// ---------------------------------------------------------------------------

/// A code completion suggestion.
///
/// Ported from `ghidra.app.plugin.core.interpreter.CodeCompletionWindow`.
#[derive(Debug, Clone)]
pub struct CompletionCandidate {
    /// The completion text.
    pub text: String,
    /// An optional description or type hint.
    pub description: Option<String>,
    /// The cursor position after inserting this completion.
    pub cursor_offset: usize,
}

impl CompletionCandidate {
    /// Create a new completion candidate.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            description: None,
            cursor_offset: 0,
        }
    }

    /// Create a completion candidate with a description.
    pub fn with_description(text: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            description: Some(desc.into()),
            cursor_offset: 0,
        }
    }
}

/// Model for the code completion popup.
#[derive(Debug, Default)]
pub struct CodeCompletionModel {
    /// Available candidates.
    candidates: Vec<CompletionCandidate>,
    /// Currently selected index.
    selected_index: Option<usize>,
    /// The prefix that was typed before completion was triggered.
    prefix: String,
}

impl CodeCompletionModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the available candidates.
    pub fn set_candidates(&mut self, candidates: Vec<CompletionCandidate>) {
        self.candidates = candidates;
        self.selected_index = if self.candidates.is_empty() {
            None
        } else {
            Some(0)
        };
    }

    /// Set the prefix for filtering.
    pub fn set_prefix(&mut self, prefix: impl Into<String>) {
        self.prefix = prefix.into();
    }

    /// Get candidates matching the current prefix.
    pub fn matching_candidates(&self) -> Vec<&CompletionCandidate> {
        self.candidates
            .iter()
            .filter(|c| c.text.starts_with(&self.prefix))
            .collect()
    }

    /// Select the next candidate.
    pub fn select_next(&mut self) {
        if let Some(idx) = self.selected_index {
            if idx + 1 < self.candidates.len() {
                self.selected_index = Some(idx + 1);
            }
        }
    }

    /// Select the previous candidate.
    pub fn select_previous(&mut self) {
        if let Some(idx) = self.selected_index {
            if idx > 0 {
                self.selected_index = Some(idx - 1);
            }
        }
    }

    /// Get the currently selected candidate.
    pub fn selected(&self) -> Option<&CompletionCandidate> {
        self.selected_index.and_then(|i| self.candidates.get(i))
    }

    /// Whether there are any candidates.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// The total number of candidates.
    pub fn count(&self) -> usize {
        self.candidates.len()
    }

    /// Clear the model.
    pub fn clear(&mut self) {
        self.candidates.clear();
        self.selected_index = None;
        self.prefix.clear();
    }
}

// ===========================================================================
// Tests for ANSI parser, renderer, and code completion
// ===========================================================================

#[cfg(test)]
mod ansi_tests {
    use super::*;

    struct TestHandler {
        strings: Vec<String>,
        csi_params: Vec<(String, String, char)>,
        osc_params: Vec<String>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                strings: Vec::new(),
                csi_params: Vec::new(),
                osc_params: Vec::new(),
            }
        }
    }

    impl AnsiParserHandler for TestHandler {
        fn handle_string(&mut self, text: &str) {
            self.strings.push(text.to_string());
        }
        fn handle_csi(&mut self, param: &str, inter: &str, final_char: char) {
            self.csi_params
                .push((param.to_string(), inter.to_string(), final_char));
        }
        fn handle_osc(&mut self, param: &str) {
            self.osc_params.push(param.to_string());
        }
    }

    #[test]
    fn test_ansi_parser_plain_text() {
        let mut parser = AnsiParser::new();
        let mut handler = TestHandler::new();
        parser.process_string("hello world", &mut handler);
        assert_eq!(handler.strings, vec!["hello world"]);
        assert!(handler.csi_params.is_empty());
    }

    #[test]
    fn test_ansi_parser_csi_reset() {
        let mut parser = AnsiParser::new();
        let mut handler = TestHandler::new();
        // ESC [ 0 m  (SGR reset)
        parser.process_string("\x1b[0m", &mut handler);
        assert!(handler.strings.is_empty());
        assert_eq!(handler.csi_params.len(), 1);
        assert_eq!(handler.csi_params[0].0, "0");
        assert_eq!(handler.csi_params[0].2, 'm');
    }

    #[test]
    fn test_ansi_parser_csi_bold() {
        let mut parser = AnsiParser::new();
        let mut handler = TestHandler::new();
        // ESC [ 1 m  (SGR bold)
        parser.process_string("\x1b[1mBOLD\x1b[0m", &mut handler);
        assert_eq!(handler.strings, vec!["BOLD"]);
        assert_eq!(handler.csi_params.len(), 2);
        assert_eq!(handler.csi_params[0].0, "1");
        assert_eq!(handler.csi_params[1].0, "0");
    }

    #[test]
    fn test_ansi_parser_osc() {
        let mut parser = AnsiParser::new();
        let mut handler = TestHandler::new();
        // ESC ] 0 ; title BEL
        parser.process_string("\x1b]0;My Title\x07", &mut handler);
        assert_eq!(handler.osc_params, vec!["0;My Title"]);
    }

    #[test]
    fn test_ansi_parser_nul_suppression() {
        let mut parser = AnsiParser::new();
        let mut handler = TestHandler::new();
        parser.process_string("a\x00b", &mut handler);
        assert_eq!(handler.strings, vec!["a", "b"]);
    }

    #[test]
    fn test_ansi_parser_incomplete_csi_buffered() {
        let mut parser = AnsiParser::new();
        let mut handler = TestHandler::new();
        // Send incomplete CSI
        parser.process_string("hello\x1b[1", &mut handler);
        assert_eq!(handler.strings, vec!["hello"]);
        // Complete it
        parser.process_string("mworld", &mut handler);
        assert_eq!(handler.strings, vec!["hello", "world"]);
        assert_eq!(handler.csi_params.len(), 1);
        assert_eq!(handler.csi_params[0].0, "1");
    }

    #[test]
    fn test_ansi_parser_incomplete_osc_buffered() {
        let mut parser = AnsiParser::new();
        let mut handler = TestHandler::new();
        parser.process_string("a\x1b]0;title", &mut handler);
        assert_eq!(handler.strings, vec!["a"]);
        parser.process_string("\x07b", &mut handler);
        assert_eq!(handler.strings, vec!["a", "b"]);
        assert_eq!(handler.osc_params, vec!["0;title"]);
    }

    #[test]
    fn test_ansi_parser_st_terminator() {
        let mut parser = AnsiParser::new();
        let mut handler = TestHandler::new();
        // OSC terminated by ESC backslash (String Terminator)
        parser.process_string("\x1b]0;title\x1b\\", &mut handler);
        assert_eq!(handler.osc_params, vec!["0;title"]);
    }

    #[test]
    fn test_parse_csi_color() {
        let mut parser = AnsiParser::new();
        let mut handler = TestHandler::new();
        // ESC [ 31 m (red foreground)
        parser.process_string("\x1b[31mred", &mut handler);
        assert_eq!(handler.csi_params[0].0, "31");
        assert_eq!(handler.strings, vec!["red"]);
    }

    #[test]
    fn test_parse_sgr_reset() {
        let effects = parse_sgr("0");
        assert_eq!(effects, vec![SgrEffect::Reset]);
    }

    #[test]
    fn test_parse_sgr_bold_and_underline() {
        let effects = parse_sgr("1;4");
        assert_eq!(effects.len(), 2);
        assert_eq!(effects[0], SgrEffect::SetBold(true));
        assert_eq!(effects[1], SgrEffect::SetUnderline(true));
    }

    #[test]
    fn test_parse_sgr_256_fg() {
        let effects = parse_sgr("38;5;196");
        assert_eq!(effects.len(), 1);
        // 196 = red in 256 palette
        if let SgrEffect::SetForeground((r, g, b)) = &effects[0] {
            assert_eq!(*r, 255);
            assert_eq!(*g, 0);
            assert_eq!(*b, 0);
        } else {
            panic!("Expected SetForeground");
        }
    }

    #[test]
    fn test_parse_sgr_rgb_fg() {
        let effects = parse_sgr("38;2;100;200;50");
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0], SgrEffect::SetForeground((100, 200, 50)));
    }

    #[test]
    fn test_parse_sgr_default_colors() {
        let effects = parse_sgr("39;49");
        assert_eq!(effects[0], SgrEffect::ResetForeground);
        assert_eq!(effects[1], SgrEffect::ResetBackground);
    }

    #[test]
    fn test_parse_sgr_high_intensity() {
        let effects = parse_sgr("91");
        assert_eq!(effects.len(), 1);
        // 91 = bright red = (255, 0, 0)
        assert_eq!(effects[0], SgrEffect::SetForeground((255, 0, 0)));
    }

    #[test]
    fn test_parse_sgr_empty() {
        let effects = parse_sgr("");
        assert_eq!(effects, vec![SgrEffect::Reset]);
    }

    #[test]
    fn test_parse_sgr_strikethrough() {
        let effects = parse_sgr("9");
        assert_eq!(effects[0], SgrEffect::SetStrikethrough(true));
        let effects = parse_sgr("29");
        assert_eq!(effects[0], SgrEffect::SetStrikethrough(false));
    }

    #[test]
    fn test_ansi_colors_256() {
        assert_eq!(ansi_colors::get_256_color(0), (0, 0, 0));
        assert_eq!(ansi_colors::get_256_color(1), (128, 0, 0));
        assert_eq!(ansi_colors::get_256_color(15), (255, 255, 255));
        // Color 16 = (0, 0, 0) -- first cube entry
        assert_eq!(ansi_colors::get_256_color(16), (0, 0, 0));
        // Color 196 = (255, 0, 0) -- red in cube
        assert_eq!(ansi_colors::get_256_color(196), (255, 0, 0));
        // Gray scale 232 = (8, 8, 8)
        assert_eq!(ansi_colors::get_256_color(232), (8, 8, 8));
        // Gray scale 255 = (238, 238, 238)
        assert_eq!(ansi_colors::get_256_color(255), (238, 238, 238));
    }

    #[test]
    fn test_ansi_renderer_basic() {
        let mut renderer = AnsiRenderer::new();
        let segments = renderer.render("hello \x1b[1mworld\x1b[0m");
        // Two segments: "hello " (normal) and "world" (bold).
        // The trailing ESC[0m resets but produces no empty segment.
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].text, "hello ");
        assert!(!segments[0].style.bold);
        assert_eq!(segments[1].text, "world");
        assert!(segments[1].style.bold);
    }

    #[test]
    fn test_ansi_renderer_reset() {
        let mut renderer = AnsiRenderer::new();
        renderer.render("\x1b[1;3;4mstyled\x1b[0mplain");
        let segments = renderer.take_segments();
        assert!(segments[0].style.bold);
        assert!(segments[0].style.italic);
        assert!(segments[0].style.underline);
        // After reset, plain text should have default style
        assert_eq!(segments[1].text, "plain");
        assert!(!segments[1].style.bold);
    }

    #[test]
    fn test_code_completion_model() {
        let mut model = CodeCompletionModel::new();
        model.set_candidates(vec![
            CompletionCandidate::new("print"),
            CompletionCandidate::new("println"),
            CompletionCandidate::new("parse"),
        ]);
        model.set_prefix("pr");
        let matches = model.matching_candidates();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].text, "print");
        assert_eq!(matches[1].text, "println");
    }

    #[test]
    fn test_code_completion_navigation() {
        let mut model = CodeCompletionModel::new();
        model.set_candidates(vec![
            CompletionCandidate::new("a"),
            CompletionCandidate::new("b"),
            CompletionCandidate::new("c"),
        ]);
        assert_eq!(model.selected().unwrap().text, "a");
        model.select_next();
        assert_eq!(model.selected().unwrap().text, "b");
        model.select_next();
        assert_eq!(model.selected().unwrap().text, "c");
        model.select_next(); // at end
        assert_eq!(model.selected().unwrap().text, "c");
        model.select_previous();
        assert_eq!(model.selected().unwrap().text, "b");
    }

    #[test]
    fn test_code_completion_empty() {
        let mut model = CodeCompletionModel::new();
        assert!(model.is_empty());
        assert_eq!(model.count(), 0);
        assert!(model.selected().is_none());
        model.select_next(); // no-op
        model.select_previous(); // no-op
    }

    #[test]
    fn test_code_completion_with_description() {
        let c = CompletionCandidate::with_description("myFunc", "void myFunc(int x)");
        assert_eq!(c.text, "myFunc");
        assert_eq!(c.description.as_deref(), Some("void myFunc(int x)"));
    }
}
