//! Logging and error reporting facade.
//!
//! Port of `ghidra.util.Msg`, `ErrorLogger`, `ErrorDisplay`,
//! `DefaultErrorLogger`, and `ConsoleErrorDisplay`.

use std::sync::{Arc, Mutex, OnceLock};

/// Log level for messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// Trace-level detail.
    Trace,
    /// Debug information.
    Debug,
    /// Informational message.
    Info,
    /// Warning message.
    Warn,
    /// Error message.
    Error,
}

impl LogLevel {
    /// Returns the string label for this level.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Trait for logging error/info messages.
///
/// Port of `ghidra.util.ErrorLogger`.
pub trait ErrorLogger: Send + Sync {
    /// Log a message at the given level with the originating class name.
    fn log(&self, level: LogLevel, originator: &str, message: &str, cause: Option<&dyn std::fmt::Display>);

    /// Log an error message.
    fn log_error(&self, originator: &str, message: &str, cause: Option<&dyn std::fmt::Display>) {
        self.log(LogLevel::Error, originator, message, cause);
    }

    /// Log a warning message.
    fn log_warning(&self, originator: &str, message: &str) {
        self.log(LogLevel::Warn, originator, message, None);
    }

    /// Log an info message.
    fn log_info(&self, originator: &str, message: &str) {
        self.log(LogLevel::Info, originator, message, None);
    }

    /// Log a debug message.
    fn log_debug(&self, originator: &str, message: &str) {
        self.log(LogLevel::Debug, originator, message, None);
    }

    /// Log a trace message.
    fn log_trace(&self, originator: &str, message: &str) {
        self.log(LogLevel::Trace, originator, message, None);
    }
}

/// Trait for displaying errors to the user.
///
/// Port of `ghidra.util.ErrorDisplay`.
pub trait ErrorDisplay: Send + Sync {
    /// Display an error message.
    fn show_error(&self, originator: &str, message: &str);
}

/// Default logger that writes to stderr.
///
/// Port of `ghidra.util.DefaultErrorLogger`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultErrorLogger;

impl ErrorLogger for DefaultErrorLogger {
    fn log(&self, level: LogLevel, originator: &str, message: &str, cause: Option<&dyn std::fmt::Display>) {
        match cause {
            Some(c) => eprintln!("[{}] {}: {} - {}", level, originator, message, c),
            None => eprintln!("[{}] {}: {}", level, originator, message),
        }
    }
}

/// Console-based error display.
///
/// Port of `ghidra.util.ConsoleErrorDisplay`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsoleErrorDisplay;

impl ErrorDisplay for ConsoleErrorDisplay {
    fn show_error(&self, originator: &str, message: &str) {
        eprintln!("[ERROR] {}: {}", originator, message);
    }
}

/// Global message/logging facade.
///
/// Port of `ghidra.util.Msg`. Provides static methods for logging at
/// various levels using the configured logger and display.
pub struct Msg;

// Global state for Msg (using OnceLock for lazy initialization).
static ERROR_LOGGER: OnceLock<Mutex<Box<dyn ErrorLogger>>> = OnceLock::new();
static ERROR_DISPLAY: OnceLock<Mutex<Box<dyn ErrorDisplay>>> = OnceLock::new();

fn logger() -> &'static Mutex<Box<dyn ErrorLogger>> {
    ERROR_LOGGER.get_or_init(|| Mutex::new(Box::new(DefaultErrorLogger)))
}

fn display() -> &'static Mutex<Box<dyn ErrorDisplay>> {
    ERROR_DISPLAY.get_or_init(|| Mutex::new(Box::new(ConsoleErrorDisplay)))
}

impl Msg {
    /// Set the global error logger.
    pub fn set_error_logger<L: ErrorLogger + 'static>(logger: L) {
        let lock = ERROR_LOGGER.get_or_init(|| Mutex::new(Box::new(DefaultErrorLogger)));
        if let Ok(mut guard) = lock.lock() {
            *guard = Box::new(logger);
        }
    }

    /// Set the global error display.
    pub fn set_error_display<D: ErrorDisplay + 'static>(disp: D) {
        let lock = ERROR_DISPLAY.get_or_init(|| Mutex::new(Box::new(ConsoleErrorDisplay)));
        if let Ok(mut guard) = lock.lock() {
            *guard = Box::new(disp);
        }
    }

    /// Print a raw message (replacement for `System.out.println`).
    pub fn out(message: &str) {
        println!("{}", message);
    }

    /// Log an error message from the given originator.
    pub fn error(originator: &str, message: &str) {
        if let Ok(guard) = logger().lock() {
            guard.log_error(originator, message, None);
        }
    }

    /// Log an error with a cause.
    pub fn error_with_cause(originator: &str, message: &str, cause: &dyn std::fmt::Display) {
        if let Ok(guard) = logger().lock() {
            guard.log_error(originator, message, Some(cause));
        }
    }

    /// Log a warning message.
    pub fn warn(originator: &str, message: &str) {
        if let Ok(guard) = logger().lock() {
            guard.log_warning(originator, message);
        }
    }

    /// Log an informational message.
    pub fn info(originator: &str, message: &str) {
        if let Ok(guard) = logger().lock() {
            guard.log_info(originator, message);
        }
    }

    /// Log a debug message.
    pub fn debug(originator: &str, message: &str) {
        if let Ok(guard) = logger().lock() {
            guard.log_debug(originator, message);
        }
    }

    /// Log a trace message.
    pub fn trace(originator: &str, message: &str) {
        if let Ok(guard) = logger().lock() {
            guard.log_trace(originator, message);
        }
    }

    /// Display an error to the user.
    pub fn show_error(originator: &str, message: &str) {
        Self::error(originator, message);
        if let Ok(guard) = display().lock() {
            guard.show_error(originator, message);
        }
    }
}

/// Message type classification for issues.
///
/// Port of `ghidra.util.MessageType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// An informational message.
    Info,
    /// A warning message.
    Warning,
    /// An error message.
    Error,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Info => write!(f, "Info"),
            MessageType::Warning => write!(f, "Warning"),
            MessageType::Error => write!(f, "Error"),
        }
    }
}

/// An issue reported during analysis or processing.
///
/// Port of `ghidra.util.Issue`.
#[derive(Debug, Clone)]
pub struct Issue {
    /// The issue message.
    pub message: String,
    /// The severity/type.
    pub message_type: MessageType,
    /// The originating class or component.
    pub originator: String,
}

impl Issue {
    /// Create a new issue.
    pub fn new(message: impl Into<String>, message_type: MessageType, originator: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            message_type,
            originator: originator.into(),
        }
    }

    /// Create an info issue.
    pub fn info(message: impl Into<String>, originator: impl Into<String>) -> Self {
        Self::new(message, MessageType::Info, originator)
    }

    /// Create a warning issue.
    pub fn warning(message: impl Into<String>, originator: impl Into<String>) -> Self {
        Self::new(message, MessageType::Warning, originator)
    }

    /// Create an error issue.
    pub fn error(message: impl Into<String>, originator: impl Into<String>) -> Self {
        Self::new(message, MessageType::Error, originator)
    }
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.message_type, self.originator, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level() {
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
        assert!(LogLevel::Error > LogLevel::Warn);
    }

    #[test]
    fn test_issue() {
        let issue = Issue::warning("something odd", "Analyzer");
        assert_eq!(issue.message_type, MessageType::Warning);
        assert!(format!("{}", issue).contains("something odd"));
    }

    #[test]
    fn test_msg_logging() {
        // These should not panic
        Msg::info("test", "info message");
        Msg::warn("test", "warn message");
        Msg::error("test", "error message");
        Msg::debug("test", "debug message");
    }

    #[test]
    fn test_message_type_display() {
        assert_eq!(format!("{}", MessageType::Info), "Info");
        assert_eq!(format!("{}", MessageType::Warning), "Warning");
        assert_eq!(format!("{}", MessageType::Error), "Error");
    }
}
