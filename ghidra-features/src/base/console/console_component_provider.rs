//! Console component provider implementation.
//!
//! Port of Ghidra's `ghidra.app.plugin.core.console.ConsoleComponentProvider`.
//!
//! This is the main console implementation that manages a text buffer,
//! supports regular and error messages, find functionality, and provides
//! the console service interface.

use std::collections::VecDeque;
use std::io::Write;

use super::console_service::ConsoleService;
use super::console_word::{get_word_at_position, ConsoleWord};

/// Maximum number of lines to retain in the console buffer.
const MAX_CONSOLE_LINES: usize = 100_000;

/// Message type for console entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleMessageType {
    /// Regular informational message.
    Normal,
    /// Error message (typically displayed in red).
    Error,
}

/// A single line in the console buffer.
#[derive(Debug, Clone)]
pub struct ConsoleEntry {
    /// The text content of this entry.
    pub text: String,
    /// Whether this is an error message.
    pub message_type: ConsoleMessageType,
}

/// Console component provider.
///
/// Manages a text buffer for the scripting console, supporting:
/// - Regular and error messages with color differentiation
/// - Search/find functionality
/// - Word-at-cursor extraction for address/symbol navigation
/// - Stdout/stderr writer access
#[derive(Debug)]
pub struct ConsoleComponentProvider {
    /// The display name of this console.
    name: String,
    /// Console text buffer (line-oriented).
    lines: VecDeque<ConsoleEntry>,
    /// Current scroll lock state.
    scroll_lock: bool,
    /// Total character count in the buffer.
    total_chars: usize,
    /// Whether the console is currently visible.
    visible: bool,
    /// Current partial message being built (for `print()` calls).
    partial_buffer: String,
    /// Whether the partial buffer is an error message.
    partial_is_error: bool,
}

impl ConsoleComponentProvider {
    /// Create a new console component provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            lines: VecDeque::new(),
            scroll_lock: false,
            total_chars: 0,
            visible: true,
            partial_buffer: String::new(),
            partial_is_error: false,
        }
    }

    /// Get the console name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if scroll lock is enabled.
    pub fn is_scroll_locked(&self) -> bool {
        self.scroll_lock
    }

    /// Set scroll lock state.
    pub fn set_scroll_lock(&mut self, locked: bool) {
        self.scroll_lock = locked;
    }

    /// Check if the console is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the console visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Get all console text as a single string.
    pub fn text(&self) -> String {
        self.lines
            .iter()
            .map(|entry| entry.text.as_str())
            .collect::<String>()
    }

    /// Get the total character count in the buffer.
    pub fn text_len(&self) -> usize {
        self.total_chars
    }

    /// Get a reference to the console lines.
    pub fn lines(&self) -> &VecDeque<ConsoleEntry> {
        &self.lines
    }

    /// Find all occurrences of `query` in the console text.
    ///
    /// Returns a list of `(start, end)` offset pairs for each match.
    pub fn find_all(&self, query: &str) -> Vec<(usize, usize)> {
        if query.is_empty() {
            return Vec::new();
        }

        let full_text = self.text();
        let mut results = Vec::new();
        let mut start = 0;

        while let Some(pos) = full_text[start..].find(query) {
            let absolute = start + pos;
            results.push((absolute, absolute + query.len()));
            start = absolute + 1;
        }

        results
    }

    /// Get a word at the given character offset, for navigation purposes.
    pub fn word_at_offset(&self, offset: usize) -> Option<ConsoleWord> {
        let text = self.text();
        get_word_at_position(&text, offset)
    }

    /// Flush any pending partial message into the buffer.
    fn flush_partial(&mut self) {
        if !self.partial_buffer.is_empty() {
            let text = std::mem::take(&mut self.partial_buffer);
            let msg_type = if self.partial_is_error {
                ConsoleMessageType::Error
            } else {
                ConsoleMessageType::Normal
            };
            self.push_line(text, msg_type);
            self.partial_is_error = false;
        }
    }

    /// Push a line into the buffer, trimming if it exceeds the maximum.
    fn push_line(&mut self, text: String, msg_type: ConsoleMessageType) {
        let len = text.len();
        self.lines.push_back(ConsoleEntry {
            text,
            message_type: msg_type,
        });
        self.total_chars += len;

        // Trim old lines if we exceed the limit
        while self.lines.len() > MAX_CONSOLE_LINES {
            if let Some(removed) = self.lines.pop_front() {
                self.total_chars -= removed.text.len();
            }
        }
    }

    /// Make the console visible if it isn't already.
    fn ensure_visible(&mut self) {
        if !self.visible {
            self.visible = true;
        }
    }
}

impl ConsoleService for ConsoleComponentProvider {
    fn add_message(&mut self, originator: &str, message: &str) {
        self.ensure_visible();
        self.flush_partial();
        let text = format!("{}> {}\n", originator, message);
        self.push_line(text, ConsoleMessageType::Normal);
    }

    fn add_error_message(&mut self, originator: &str, message: &str) {
        self.ensure_visible();
        self.flush_partial();
        let text = format!("{}> {}\n", originator, message);
        self.push_line(text, ConsoleMessageType::Error);
    }

    fn add_exception(&mut self, _originator: &str, message: &str) {
        log::error!("Unexpected Exception: {}", message);
    }

    fn clear_messages(&mut self) {
        self.ensure_visible();
        self.lines.clear();
        self.total_chars = 0;
        self.partial_buffer.clear();
    }

    fn print(&mut self, msg: &str) {
        self.ensure_visible();
        if self.partial_is_error {
            self.flush_partial();
        }
        self.partial_buffer.push_str(msg);
    }

    fn print_error(&mut self, errmsg: &str) {
        self.ensure_visible();
        if !self.partial_is_error {
            self.flush_partial();
        }
        self.partial_is_error = true;
        self.partial_buffer.push_str(errmsg);
    }

    fn println(&mut self, msg: &str) {
        self.ensure_visible();
        self.flush_partial();
        let text = format!("{}\n", msg);
        self.push_line(text, ConsoleMessageType::Normal);
    }

    fn println_error(&mut self, errmsg: &str) {
        self.ensure_visible();
        self.flush_partial();
        let text = format!("{}\n", errmsg);
        self.push_line(text, ConsoleMessageType::Error);
    }

    fn get_stdout(&self) -> Box<dyn Write> {
        Box::new(ConsoleWriter::new(false))
    }

    fn get_stderr(&self) -> Box<dyn Write> {
        Box::new(ConsoleWriter::new(true))
    }

    fn get_text(&self, offset: usize, length: usize) -> Option<String> {
        let text = self.text();
        if offset + length > text.len() {
            return None;
        }
        Some(text[offset..offset + length].to_string())
    }

    fn get_text_length(&self) -> usize {
        self.total_chars
    }
}

/// A `Write` implementation that buffers output for the console.
///
/// This writer collects bytes written to it and can be flushed
/// to the console when appropriate.
pub struct ConsoleWriter {
    is_error: bool,
    buffer: Vec<u8>,
}

impl ConsoleWriter {
    /// Create a new console writer.
    pub fn new(is_error: bool) -> Self {
        Self {
            is_error,
            buffer: Vec::new(),
        }
    }

    /// Check if this is an error writer.
    pub fn is_error(&self) -> bool {
        self.is_error
    }

    /// Take the buffered contents.
    pub fn take_buffer(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }
}

impl Write for ConsoleWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_console() -> ConsoleComponentProvider {
        ConsoleComponentProvider::new("Test")
    }

    #[test]
    fn test_console_creation() {
        let console = make_console();
        assert_eq!(console.name(), "Test");
        assert!(console.is_visible());
        assert!(!console.is_scroll_locked());
        assert_eq!(console.get_text_length(), 0);
    }

    #[test]
    fn test_add_message() {
        let mut console = make_console();
        console.add_message("script", "hello");
        assert_eq!(console.get_text_length(), "script> hello\n".len());
        assert_eq!(console.text(), "script> hello\n");
    }

    #[test]
    fn test_add_error_message() {
        let mut console = make_console();
        console.add_error_message("script", "error occurred");
        let text = console.text();
        assert!(text.contains("error occurred"));
        assert!(console.lines()[0].message_type == ConsoleMessageType::Error);
    }

    #[test]
    fn test_multiple_messages() {
        let mut console = make_console();
        console.add_message("a", "first");
        console.add_message("b", "second");
        assert_eq!(console.lines().len(), 2);
    }

    #[test]
    fn test_clear_messages() {
        let mut console = make_console();
        console.add_message("s", "hello");
        console.clear_messages();
        assert_eq!(console.get_text_length(), 0);
        assert!(console.text().is_empty());
    }

    #[test]
    fn test_print() {
        let mut console = make_console();
        console.print("hello ");
        console.print("world");
        // Partial buffer not yet flushed
        assert_eq!(console.get_text_length(), 0);

        // Trigger a flush
        console.println("!");
        assert!(console.text().contains("hello world"));
    }

    #[test]
    fn test_print_error() {
        let mut console = make_console();
        console.print_error("err1 ");
        console.print_error("err2");
        console.println("end");
        assert!(console.text().contains("err1 err2"));
    }

    #[test]
    fn test_print_mixed_normal_error() {
        let mut console = make_console();
        console.print("normal ");
        console.print_error("error "); // flushes normal, starts error
        console.println("done"); // flushes error, adds done
        let text = console.text();
        assert!(text.contains("normal "));
        assert!(text.contains("error "));
        assert!(text.contains("done"));
    }

    #[test]
    fn test_println() {
        let mut console = make_console();
        console.println("line1");
        console.println("line2");
        assert!(console.text().contains("line1\n"));
        assert!(console.text().contains("line2\n"));
    }

    #[test]
    fn test_println_error() {
        let mut console = make_console();
        console.println_error("err line");
        assert!(console.lines()[0].message_type == ConsoleMessageType::Error);
    }

    #[test]
    fn test_get_text() {
        let mut console = make_console();
        console.add_message("s", "hello");
        let text = console.get_text(0, 2).unwrap();
        assert_eq!(text, "s>");
    }

    #[test]
    fn test_get_text_out_of_bounds() {
        let mut console = make_console();
        console.add_message("s", "hi");
        assert!(console.get_text(0, 1000).is_none());
    }

    #[test]
    fn test_find_all() {
        let mut console = make_console();
        console.add_message("s", "hello world hello");
        let matches = console.find_all("hello");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_find_all_no_match() {
        let mut console = make_console();
        console.add_message("s", "hello world");
        let matches = console.find_all("xyz");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_find_all_empty_query() {
        let mut console = make_console();
        console.add_message("s", "hello");
        let matches = console.find_all("");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scroll_lock() {
        let mut console = make_console();
        assert!(!console.is_scroll_locked());
        console.set_scroll_lock(true);
        assert!(console.is_scroll_locked());
    }

    #[test]
    fn test_visibility() {
        let mut console = make_console();
        assert!(console.is_visible());
        console.set_visible(false);
        assert!(!console.is_visible());
        console.add_message("s", "msg");
        assert!(console.is_visible()); // add_message ensures visibility
    }

    #[test]
    fn test_console_writer() {
        let mut writer = ConsoleWriter::new(false);
        writer.write_all(b"hello").unwrap();
        let buf = writer.take_buffer();
        assert_eq!(buf, b"hello");
        assert!(writer.take_buffer().is_empty());
    }

    #[test]
    fn test_console_writer_error() {
        let writer = ConsoleWriter::new(true);
        assert!(writer.is_error());
    }

    #[test]
    fn test_max_lines_trim() {
        let mut console = make_console();
        for i in 0..MAX_CONSOLE_LINES + 10 {
            console.add_message("s", &format!("line {}", i));
        }
        // Should be trimmed to MAX_CONSOLE_LINES
        assert!(console.lines().len() <= MAX_CONSOLE_LINES);
    }

    #[test]
    fn test_word_at_offset() {
        let mut console = make_console();
        console.add_message("s", "hello world");
        let word = console.word_at_offset(3);
        assert!(word.is_some());
        assert_eq!(word.unwrap().word, "hello");
    }
}
