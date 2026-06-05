//! DebuggerConsoleService - service for the debug console.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerConsoleService`.

use serde::{Deserialize, Serialize};

/// Log level for console messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConsoleLevel {
    /// Informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
    /// Debug message.
    Debug,
}

/// A console entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleEntry {
    /// The message text.
    pub message: String,
    /// The log level.
    pub level: ConsoleLevel,
    /// Timestamp (epoch millis).
    pub timestamp: i64,
    /// The source (plugin or component) that emitted this message.
    pub source: Option<String>,
}

impl ConsoleEntry {
    /// Create a new console entry.
    pub fn new(message: impl Into<String>, level: ConsoleLevel) -> Self {
        Self {
            message: message.into(),
            level,
            timestamp: 0,
            source: None,
        }
    }

    /// Create an info entry.
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(message, ConsoleLevel::Info)
    }

    /// Create a warning entry.
    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(message, ConsoleLevel::Warning)
    }

    /// Create an error entry.
    pub fn error(message: impl Into<String>) -> Self {
        Self::new(message, ConsoleLevel::Error)
    }
}

/// Service interface for the debug console.
pub trait DebuggerConsoleServiceExt {
    /// Print a message to the console.
    fn print(&mut self, message: &str, level: ConsoleLevel);

    /// Print an info message.
    fn print_info(&mut self, message: &str) {
        self.print(message, ConsoleLevel::Info);
    }

    /// Print a warning message.
    fn print_warning(&mut self, message: &str) {
        self.print(message, ConsoleLevel::Warning);
    }

    /// Print an error message.
    fn print_error(&mut self, message: &str) {
        self.print(message, ConsoleLevel::Error);
    }

    /// Get recent console entries.
    fn recent_entries(&self, count: usize) -> Vec<&ConsoleEntry>;

    /// Clear the console.
    fn clear(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_level_ordering() {
        assert!(ConsoleLevel::Info < ConsoleLevel::Warning);
        assert!(ConsoleLevel::Warning < ConsoleLevel::Error);
    }

    #[test]
    fn test_console_entry() {
        let entry = ConsoleEntry::info("test message");
        assert_eq!(entry.level, ConsoleLevel::Info);
        assert_eq!(entry.message, "test message");
    }

    #[test]
    fn test_console_entry_error() {
        let entry = ConsoleEntry::error("something failed");
        assert_eq!(entry.level, ConsoleLevel::Error);
    }
}
