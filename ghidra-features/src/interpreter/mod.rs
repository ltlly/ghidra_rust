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
