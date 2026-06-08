//! Analysis message log.
//!
//! Ported from `ghidra.app.util.importer.MessageLog`.
//!
//! Provides a thread-safe log for collecting warnings, errors, and
//! informational messages during analysis. Used by analyzers to report
//! issues and by the analysis manager to display summaries.

use std::fmt;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// MessageSeverity
// ---------------------------------------------------------------------------

/// Severity level for log messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessageSeverity {
    /// Informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
}

impl fmt::Display for MessageSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

// ---------------------------------------------------------------------------
// LogEntry
// ---------------------------------------------------------------------------

/// A single entry in the message log.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// The severity of this message.
    pub severity: MessageSeverity,
    /// The source/analyzer that generated the message.
    pub source: Option<String>,
    /// The message text.
    pub message: String,
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(src) => write!(f, "[{}] {}: {}", self.severity, src, self.message),
            None => write!(f, "[{}] {}", self.severity, self.message),
        }
    }
}

// ---------------------------------------------------------------------------
// MessageLog
// ---------------------------------------------------------------------------

/// Thread-safe log for analysis messages.
///
/// Ported from `MessageLog.java`. Collects messages during analysis
/// and provides methods to query and format them.
///
/// # Usage
///
/// ```ignore
/// let log = MessageLog::new();
/// log.append_msg("MyAnalyzer", "Found 5 undefined functions");
/// log.append_warning("MyAnalyzer", "Suspicious instruction at 0x1000");
/// log.append_error("MyAnalyzer", "Failed to resolve symbol");
///
/// if log.has_messages() {
///     println!("{}", log.as_string());
/// }
/// ```
#[derive(Clone)]
pub struct MessageLog {
    entries: Arc<Mutex<Vec<LogEntry>>>,
}

impl fmt::Debug for MessageLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.entries.lock().unwrap().len();
        write!(f, "MessageLog({} entries)", count)
    }
}

impl MessageLog {
    /// Create a new empty message log.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Append an informational message.
    pub fn append_msg(&self, source: &str, msg: &str) {
        self.entries.lock().unwrap().push(LogEntry {
            severity: MessageSeverity::Info,
            source: Some(source.to_string()),
            message: msg.to_string(),
        });
    }

    /// Append an informational message without a source.
    pub fn append_msg_plain(&self, msg: &str) {
        self.entries.lock().unwrap().push(LogEntry {
            severity: MessageSeverity::Info,
            source: None,
            message: msg.to_string(),
        });
    }

    /// Append a warning message.
    pub fn append_warning(&self, source: &str, msg: &str) {
        self.entries.lock().unwrap().push(LogEntry {
            severity: MessageSeverity::Warning,
            source: Some(source.to_string()),
            message: msg.to_string(),
        });
    }

    /// Append an error message.
    pub fn append_error(&self, source: &str, msg: &str) {
        self.entries.lock().unwrap().push(LogEntry {
            severity: MessageSeverity::Error,
            source: Some(source.to_string()),
            message: msg.to_string(),
        });
    }

    /// Append a raw log entry.
    pub fn append_entry(&self, entry: LogEntry) {
        self.entries.lock().unwrap().push(entry);
    }

    /// Whether the log has any messages.
    pub fn has_messages(&self) -> bool {
        !self.entries.lock().unwrap().is_empty()
    }

    /// Whether the log has any warning or error messages.
    pub fn has_errors_or_warnings(&self) -> bool {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e.severity, MessageSeverity::Warning | MessageSeverity::Error))
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }

    /// Get all entries.
    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Get entries filtered by severity.
    pub fn entries_by_severity(&self, severity: MessageSeverity) -> Vec<LogEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.severity == severity)
            .cloned()
            .collect()
    }

    /// Get a status string summarizing the log contents.
    ///
    /// Returns a human-readable summary like "3 warnings, 1 error" or
    /// an empty string if there are no messages.
    pub fn get_status(&self) -> String {
        let entries = self.entries.lock().unwrap();
        let warnings = entries
            .iter()
            .filter(|e| e.severity == MessageSeverity::Warning)
            .count();
        let errors = entries
            .iter()
            .filter(|e| e.severity == MessageSeverity::Error)
            .count();

        if warnings == 0 && errors == 0 {
            return String::new();
        }

        let mut parts = Vec::new();
        if warnings > 0 {
            parts.push(format!(
                "{} warning{}",
                warnings,
                if warnings == 1 { "" } else { "s" }
            ));
        }
        if errors > 0 {
            parts.push(format!(
                "{} error{}",
                errors,
                if errors == 1 { "" } else { "s" }
            ));
        }
        parts.join(", ")
    }

    /// Get the full log as a formatted string.
    pub fn as_string(&self) -> String {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    /// Get the count of entries by severity.
    pub fn count_by_severity(&self, severity: MessageSeverity) -> usize {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.severity == severity)
            .count()
    }
}

impl Default for MessageLog {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MessageLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_log_basic() {
        let log = MessageLog::new();
        assert!(log.is_empty());
        assert!(!log.has_messages());

        log.append_msg("TestAnalyzer", "Information message");
        assert!(!log.is_empty());
        assert!(log.has_messages());
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_message_log_severities() {
        let log = MessageLog::new();
        log.append_msg("A", "info");
        log.append_warning("A", "warning");
        log.append_error("A", "error");

        assert_eq!(log.count_by_severity(MessageSeverity::Info), 1);
        assert_eq!(log.count_by_severity(MessageSeverity::Warning), 1);
        assert_eq!(log.count_by_severity(MessageSeverity::Error), 1);
    }

    #[test]
    fn test_message_log_has_errors_or_warnings() {
        let log = MessageLog::new();
        assert!(!log.has_errors_or_warnings());

        log.append_msg("A", "info");
        assert!(!log.has_errors_or_warnings());

        log.append_warning("A", "warning");
        assert!(log.has_errors_or_warnings());
    }

    #[test]
    fn test_message_log_status() {
        let log = MessageLog::new();
        assert_eq!(log.get_status(), "");

        log.append_warning("A", "w1");
        log.append_warning("A", "w2");
        log.append_error("A", "e1");
        assert_eq!(log.get_status(), "2 warnings, 1 error");

        let log2 = MessageLog::new();
        log2.append_error("A", "e1");
        assert_eq!(log2.get_status(), "1 error");
    }

    #[test]
    fn test_message_log_as_string() {
        let log = MessageLog::new();
        log.append_msg("Analyzer1", "msg1");
        log.append_warning("Analyzer2", "msg2");

        let s = log.as_string();
        assert!(s.contains("[INFO] Analyzer1: msg1"));
        assert!(s.contains("[WARN] Analyzer2: msg2"));
    }

    #[test]
    fn test_message_log_plain_msg() {
        let log = MessageLog::new();
        log.append_msg_plain("no source");

        let entries = log.entries();
        assert!(entries[0].source.is_none());
        assert_eq!(entries[0].message, "no source");
    }

    #[test]
    fn test_message_log_filter_by_severity() {
        let log = MessageLog::new();
        log.append_msg("A", "i1");
        log.append_msg("A", "i2");
        log.append_warning("A", "w1");
        log.append_error("A", "e1");

        let warnings = log.entries_by_severity(MessageSeverity::Warning);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].message, "w1");
    }

    #[test]
    fn test_message_log_clear() {
        let log = MessageLog::new();
        log.append_msg("A", "msg");
        assert_eq!(log.len(), 1);

        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_log_entry_display() {
        let entry = LogEntry {
            severity: MessageSeverity::Error,
            source: Some("MyAnalyzer".to_string()),
            message: "Something went wrong".to_string(),
        };
        assert_eq!(
            entry.to_string(),
            "[ERROR] MyAnalyzer: Something went wrong"
        );

        let entry = LogEntry {
            severity: MessageSeverity::Info,
            source: None,
            message: "General info".to_string(),
        };
        assert_eq!(entry.to_string(), "[INFO] General info");
    }

    #[test]
    fn test_message_severity_ordering() {
        assert!(MessageSeverity::Info < MessageSeverity::Warning);
        assert!(MessageSeverity::Warning < MessageSeverity::Error);
    }

    #[test]
    fn test_message_log_clone_shares_state() {
        let log1 = MessageLog::new();
        log1.append_msg("A", "shared");

        let log2 = log1.clone();
        assert_eq!(log2.len(), 1);
        log2.append_msg("B", "added via clone");
        assert_eq!(log1.len(), 2); // shared state
    }
}
