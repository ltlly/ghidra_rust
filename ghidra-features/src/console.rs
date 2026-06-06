//! Console plugin -- I/O console service for the Ghidra scripting environment.
//!
//! Ported from `ghidra.app.plugin.core.console` in Ghidra's Features/Base.
//!
//! This module re-exports the core console types from [`crate::base::console`]
//! and adds feature-level convenience types for console message management,
//! word-at-cursor navigation, and plugin integration.
//!
//! # Architecture
//!
//! - [`ConsoleService`] -- trait for console I/O (message display, error output)
//! - [`ConsoleComponentProvider`] -- text-based console with message history,
//!   error output, and search capabilities
//! - [`ConsolePlugin`] -- plugin wrapper that registers the console service
//! - [`CodeCompletion`] -- code completion data model
//! - [`ConsoleWord`] -- word-at-cursor extraction for navigation
//! - [`ConsoleMessage`] -- individual message entry with timestamp and type
//! - [`ConsoleBuffer`] -- ring-buffer console output accumulator
//!
//! # Example
//!
//! ```
//! use ghidra_features::console::*;
//!
//! let mut buffer = ConsoleBuffer::new(1000);
//! buffer.add_info("script", "Starting analysis");
//! buffer.add_error("script", "Failed to resolve symbol");
//! assert_eq!(buffer.len(), 2);
//! assert_eq!(buffer.error_count(), 1);
//! ```

// Re-export core console types from base module.
pub use crate::base::console::{
    CodeCompletion, ConsoleComponentProvider, ConsolePlugin, ConsoleService, ConsoleWord,
};

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// ConsoleMessageType -- severity of a console message
// ---------------------------------------------------------------------------

/// Severity of a console message.
///
/// Ported from the message-level constants in `ConsoleComponentProvider.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsoleMessageType {
    /// Informational message (normal output).
    Info,
    /// Error message (stderr / error output).
    Error,
    /// Warning message.
    Warning,
}

impl Default for ConsoleMessageType {
    fn default() -> Self {
        ConsoleMessageType::Info
    }
}

impl std::fmt::Display for ConsoleMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsoleMessageType::Info => write!(f, "INFO"),
            ConsoleMessageType::Error => write!(f, "ERROR"),
            ConsoleMessageType::Warning => write!(f, "WARN"),
        }
    }
}

// ---------------------------------------------------------------------------
// ConsoleMessage -- single message entry
// ---------------------------------------------------------------------------

/// A single message entry in the console history.
///
/// Corresponds to a line in the console component provider's output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleMessage {
    /// Source tag (e.g. "script", "plugin", "analysis").
    pub source: String,
    /// The message text.
    pub text: String,
    /// Severity of the message.
    pub msg_type: ConsoleMessageType,
}

impl ConsoleMessage {
    /// Create a new console message.
    pub fn new(source: impl Into<String>, text: impl Into<String>, msg_type: ConsoleMessageType) -> Self {
        Self {
            source: source.into(),
            text: text.into(),
            msg_type,
        }
    }

    /// Format the message for display.
    pub fn format(&self) -> String {
        format!("[{}] {}: {}", self.msg_type, self.source, self.text)
    }
}

// ---------------------------------------------------------------------------
// ConsoleBuffer -- ring-buffer accumulator for console output
// ---------------------------------------------------------------------------

/// Ring-buffer console output accumulator with a configurable maximum size.
///
/// Used by [`ConsoleComponentProvider`] to store message history. Old messages
/// are discarded when the buffer is full.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleBuffer {
    /// Internal ring buffer of messages.
    messages: VecDeque<ConsoleMessage>,
    /// Maximum number of messages to retain.
    max_size: usize,
}

impl ConsoleBuffer {
    /// Create a new console buffer with the given maximum capacity.
    pub fn new(max_size: usize) -> Self {
        Self {
            messages: VecDeque::with_capacity(max_size.min(4096)),
            max_size,
        }
    }

    /// Add an informational message.
    pub fn add_info(&mut self, source: impl Into<String>, text: impl Into<String>) {
        self.push(ConsoleMessage::new(source, text, ConsoleMessageType::Info));
    }

    /// Add an error message.
    pub fn add_error(&mut self, source: impl Into<String>, text: impl Into<String>) {
        self.push(ConsoleMessage::new(source, text, ConsoleMessageType::Error));
    }

    /// Add a warning message.
    pub fn add_warning(&mut self, source: impl Into<String>, text: impl Into<String>) {
        self.push(ConsoleMessage::new(source, text, ConsoleMessageType::Warning));
    }

    /// Push a message into the buffer, discarding the oldest if full.
    pub fn push(&mut self, msg: ConsoleMessage) {
        if self.messages.len() >= self.max_size {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
    }

    /// Number of messages currently in the buffer.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Count of error messages in the buffer.
    pub fn error_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.msg_type == ConsoleMessageType::Error)
            .count()
    }

    /// Count of warning messages in the buffer.
    pub fn warning_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.msg_type == ConsoleMessageType::Warning)
            .count()
    }

    /// Return all messages matching a given source tag.
    pub fn messages_by_source(&self, source: &str) -> Vec<&ConsoleMessage> {
        self.messages.iter().filter(|m| m.source == source).collect()
    }

    /// Return all messages of a given type.
    pub fn messages_by_type(&self, msg_type: ConsoleMessageType) -> Vec<&ConsoleMessage> {
        self.messages.iter().filter(|m| m.msg_type == msg_type).collect()
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Get the maximum capacity.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Return the last N messages.
    pub fn last_n(&self, n: usize) -> Vec<&ConsoleMessage> {
        let skip = self.messages.len().saturating_sub(n);
        self.messages.iter().skip(skip).collect()
    }

    /// Return all messages as a formatted string.
    pub fn to_text(&self) -> String {
        self.messages.iter().map(|m| m.format()).collect::<Vec<_>>().join("\n")
    }

    /// Iterate over all messages.
    pub fn iter(&self) -> impl Iterator<Item = &ConsoleMessage> {
        self.messages.iter()
    }
}

impl Default for ConsoleBuffer {
    fn default() -> Self {
        Self::new(10000)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_message_format() {
        let msg = ConsoleMessage::new("script", "Hello", ConsoleMessageType::Info);
        assert_eq!(msg.format(), "[INFO] script: Hello");
    }

    #[test]
    fn test_console_message_display_type() {
        assert_eq!(format!("{}", ConsoleMessageType::Info), "INFO");
        assert_eq!(format!("{}", ConsoleMessageType::Error), "ERROR");
        assert_eq!(format!("{}", ConsoleMessageType::Warning), "WARN");
    }

    #[test]
    fn test_console_buffer_add_messages() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("s1", "msg1");
        buf.add_error("s1", "err1");
        buf.add_warning("s2", "warn1");
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.error_count(), 1);
        assert_eq!(buf.warning_count(), 1);
    }

    #[test]
    fn test_console_buffer_ring_eviction() {
        let mut buf = ConsoleBuffer::new(3);
        buf.add_info("s", "a");
        buf.add_info("s", "b");
        buf.add_info("s", "c");
        assert_eq!(buf.len(), 3);
        buf.add_info("s", "d");
        assert_eq!(buf.len(), 3);
        // "a" should have been evicted
        let texts: Vec<_> = buf.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(texts, vec!["b", "c", "d"]);
    }

    #[test]
    fn test_console_buffer_filter_by_source() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("script", "a");
        buf.add_info("plugin", "b");
        buf.add_info("script", "c");
        let script_msgs = buf.messages_by_source("script");
        assert_eq!(script_msgs.len(), 2);
    }

    #[test]
    fn test_console_buffer_filter_by_type() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("s", "a");
        buf.add_error("s", "b");
        buf.add_info("s", "c");
        let errors = buf.messages_by_type(ConsoleMessageType::Error);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].text, "b");
    }

    #[test]
    fn test_console_buffer_last_n() {
        let mut buf = ConsoleBuffer::new(100);
        for i in 0..10 {
            buf.add_info("s", format!("msg{i}"));
        }
        let last3 = buf.last_n(3);
        assert_eq!(last3.len(), 3);
        assert_eq!(last3[0].text, "msg7");
    }

    #[test]
    fn test_console_buffer_to_text() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("s", "line1");
        buf.add_error("s", "line2");
        let text = buf.to_text();
        assert!(text.contains("[INFO] s: line1"));
        assert!(text.contains("[ERROR] s: line2"));
    }

    #[test]
    fn test_console_buffer_clear() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("s", "msg");
        assert_eq!(buf.len(), 1);
        buf.clear();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_console_buffer_default() {
        let buf = ConsoleBuffer::default();
        assert_eq!(buf.max_size(), 10000);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_reexported_types() {
        // Verify the re-exported types are accessible
        let _cc = CodeCompletion::new("test_completion", Some("test"));
        let _word = ConsoleWord::new("test", 0, 4);
    }
}
