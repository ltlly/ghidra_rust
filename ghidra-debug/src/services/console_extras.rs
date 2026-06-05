//! Extended console service types for the debugger.
//!
//! Ported from Ghidra's console service types in the Debugger module.
//! Provides enhanced console functionality including log filtering,
//! message queuing, and terminal session management.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// A log level for console messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConsoleLogLevel {
    /// Trace-level messages (very verbose).
    Trace,
    /// Debug-level messages.
    Debug,
    /// Informational messages.
    Info,
    /// Warning messages.
    Warning,
    /// Error messages.
    Error,
    /// Fatal messages.
    Fatal,
}

impl ConsoleLogLevel {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        }
    }

    /// Get the default color as ARGB.
    pub fn default_color(&self) -> u32 {
        match self {
            Self::Trace => 0xff_888888,
            Self::Debug => 0xff_aaaaaa,
            Self::Info => 0xff_ffffff,
            Self::Warning => 0xff_ffcc00,
            Self::Error => 0xff_ff4444,
            Self::Fatal => 0xff_ff0000,
        }
    }
}

/// A console log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleLogEntry {
    /// The log level.
    pub level: ConsoleLogLevel,
    /// The message text.
    pub message: String,
    /// The source category (e.g., "GDB", "Emulation").
    pub category: String,
    /// Timestamp as seconds since epoch.
    pub timestamp: f64,
}

/// Console filter settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleFilter {
    /// Minimum log level to display.
    pub min_level: ConsoleLogLevel,
    /// Category filter (empty = show all).
    pub category_filter: Option<String>,
    /// Text search filter.
    pub text_filter: Option<String>,
}

impl Default for ConsoleFilter {
    fn default() -> Self {
        Self {
            min_level: ConsoleLogLevel::Info,
            category_filter: None,
            text_filter: None,
        }
    }
}

impl ConsoleFilter {
    /// Check whether a log entry passes this filter.
    pub fn matches(&self, entry: &ConsoleLogEntry) -> bool {
        if entry.level < self.min_level {
            return false;
        }
        if let Some(ref cat) = self.category_filter {
            if !entry.category.contains(cat.as_str()) {
                return false;
            }
        }
        if let Some(ref text) = self.text_filter {
            if !entry.message.contains(text.as_str()) {
                return false;
            }
        }
        true
    }
}

/// A buffered console that stores log entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferedConsole {
    /// Stored entries.
    entries: VecDeque<ConsoleLogEntry>,
    /// Maximum number of entries to keep.
    pub max_entries: usize,
    /// Current filter.
    pub filter: ConsoleFilter,
}

impl BufferedConsole {
    /// Create a new buffered console.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries,
            filter: ConsoleFilter::default(),
        }
    }

    /// Add a log entry.
    pub fn log(&mut self, entry: ConsoleLogEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Log a message at a specific level.
    pub fn log_message(
        &mut self,
        level: ConsoleLogLevel,
        category: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.log(ConsoleLogEntry {
            level,
            message: message.into(),
            category: category.into(),
            timestamp: 0.0,
        });
    }

    /// Get all entries that pass the current filter.
    pub fn filtered_entries(&self) -> Vec<&ConsoleLogEntry> {
        self.entries.iter().filter(|e| self.filter.matches(e)).collect()
    }

    /// Get all entries (unfiltered).
    pub fn all_entries(&self) -> &VecDeque<ConsoleLogEntry> {
        &self.entries
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the console is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(ConsoleLogLevel::Trace < ConsoleLogLevel::Debug);
        assert!(ConsoleLogLevel::Debug < ConsoleLogLevel::Info);
        assert!(ConsoleLogLevel::Warning < ConsoleLogLevel::Error);
        assert!(ConsoleLogLevel::Error < ConsoleLogLevel::Fatal);
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(ConsoleLogLevel::Info.display_name(), "INFO");
        assert_eq!(ConsoleLogLevel::Error.display_name(), "ERROR");
    }

    #[test]
    fn test_console_filter_matches() {
        let filter = ConsoleFilter {
            min_level: ConsoleLogLevel::Warning,
            category_filter: None,
            text_filter: None,
        };

        let info_entry = ConsoleLogEntry {
            level: ConsoleLogLevel::Info,
            message: "test".into(),
            category: "GDB".into(),
            timestamp: 0.0,
        };
        assert!(!filter.matches(&info_entry));

        let error_entry = ConsoleLogEntry {
            level: ConsoleLogLevel::Error,
            message: "test".into(),
            category: "GDB".into(),
            timestamp: 0.0,
        };
        assert!(filter.matches(&error_entry));
    }

    #[test]
    fn test_console_filter_category() {
        let filter = ConsoleFilter {
            min_level: ConsoleLogLevel::Info,
            category_filter: Some("GDB".into()),
            text_filter: None,
        };

        let gdb_entry = ConsoleLogEntry {
            level: ConsoleLogLevel::Info,
            message: "test".into(),
            category: "GDB".into(),
            timestamp: 0.0,
        };
        assert!(filter.matches(&gdb_entry));

        let emu_entry = ConsoleLogEntry {
            level: ConsoleLogLevel::Info,
            message: "test".into(),
            category: "Emulation".into(),
            timestamp: 0.0,
        };
        assert!(!filter.matches(&emu_entry));
    }

    #[test]
    fn test_console_filter_text() {
        let filter = ConsoleFilter {
            min_level: ConsoleLogLevel::Info,
            category_filter: None,
            text_filter: Some("error".into()),
        };

        let matching = ConsoleLogEntry {
            level: ConsoleLogLevel::Info,
            message: "found an error".into(),
            category: "test".into(),
            timestamp: 0.0,
        };
        assert!(filter.matches(&matching));

        let non_matching = ConsoleLogEntry {
            level: ConsoleLogLevel::Info,
            message: "all good".into(),
            category: "test".into(),
            timestamp: 0.0,
        };
        assert!(!filter.matches(&non_matching));
    }

    #[test]
    fn test_buffered_console() {
        let mut console = BufferedConsole::new(100);
        assert!(console.is_empty());

        console.log_message(ConsoleLogLevel::Info, "GDB", "Connected");
        console.log_message(ConsoleLogLevel::Error, "GDB", "Connection lost");

        assert_eq!(console.len(), 2);
        assert!(!console.is_empty());
    }

    #[test]
    fn test_buffered_console_max_entries() {
        let mut console = BufferedConsole::new(3);
        console.log_message(ConsoleLogLevel::Info, "GDB", "msg1");
        console.log_message(ConsoleLogLevel::Info, "GDB", "msg2");
        console.log_message(ConsoleLogLevel::Info, "GDB", "msg3");
        console.log_message(ConsoleLogLevel::Info, "GDB", "msg4");

        assert_eq!(console.len(), 3);
        assert_eq!(console.all_entries().front().unwrap().message, "msg2");
    }

    #[test]
    fn test_buffered_console_filtered() {
        let mut console = BufferedConsole::new(100);
        console.filter = ConsoleFilter {
            min_level: ConsoleLogLevel::Warning,
            ..Default::default()
        };

        console.log_message(ConsoleLogLevel::Info, "GDB", "info msg");
        console.log_message(ConsoleLogLevel::Warning, "GDB", "warn msg");
        console.log_message(ConsoleLogLevel::Error, "GDB", "error msg");

        let filtered = console.filtered_entries();
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_buffered_console_clear() {
        let mut console = BufferedConsole::new(100);
        console.log_message(ConsoleLogLevel::Info, "GDB", "test");
        console.clear();
        assert!(console.is_empty());
    }
}
