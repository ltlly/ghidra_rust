//! Uncaught exception handler for the event dispatch thread.
//!
//! Ported from `ghidra.SwingExceptionHandler` (Framework/Gui).
//!
//! In the Java version this class installs itself as the default uncaught
//! exception handler on the Swing event-dispatch thread and filters out
//! known benign exceptions (e.g. `ThreadDeath`, RMI `ConnectException`,
//! Java Help printing bugs).  In Rust we do not have Swing, but we
//! provide the same categorisation and filtering logic so that callers
//! can decide whether an error is worth surfacing to the user.

use std::collections::HashSet;
use std::fmt;

// ---------------------------------------------------------------------------
// Error severity
// ---------------------------------------------------------------------------

/// Severity level for an uncaught error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorSeverity {
    /// Informational -- can be safely ignored.
    Info,
    /// A warning that should be logged but does not require user action.
    Warning,
    /// A fatal error that should be surfaced to the user.
    Error,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Info => write!(f, "INFO"),
            ErrorSeverity::Warning => write!(f, "WARN"),
            ErrorSeverity::Error => write!(f, "ERROR"),
        }
    }
}

// ---------------------------------------------------------------------------
// ExceptionCategory
// ---------------------------------------------------------------------------

/// Category of an exception, used to decide whether it should be
/// suppressed or surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExceptionCategory {
    /// ThreadDeath -- thread was killed, normal shutdown.
    ThreadDeath,
    /// RMI / network connection refused.
    ConnectException,
    /// A resource or stream was already closed.
    ClosedException,
    /// Known benign exception from the Java Help printing subsystem.
    JavaHelpPrint,
    /// Known benign exception from Java Help theme switching.
    JavaHelpTheme,
    /// Out-of-memory condition.
    OutOfMemory,
    /// Any other exception.
    Unknown,
}

impl ExceptionCategory {
    /// Returns `true` if exceptions in this category should be silently
    /// ignored (the Java `shouldIgnore` check).
    pub fn should_ignore(&self) -> bool {
        matches!(
            self,
            ExceptionCategory::ThreadDeath
                | ExceptionCategory::ConnectException
                | ExceptionCategory::ClosedException
                | ExceptionCategory::JavaHelpPrint
                | ExceptionCategory::JavaHelpTheme
        )
    }

    /// Returns the severity associated with this category.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            ExceptionCategory::ThreadDeath => ErrorSeverity::Info,
            ExceptionCategory::ConnectException => ErrorSeverity::Info,
            ExceptionCategory::ClosedException => ErrorSeverity::Info,
            ExceptionCategory::JavaHelpPrint => ErrorSeverity::Info,
            ExceptionCategory::JavaHelpTheme => ErrorSeverity::Info,
            ExceptionCategory::OutOfMemory => ErrorSeverity::Error,
            ExceptionCategory::Unknown => ErrorSeverity::Error,
        }
    }
}

impl fmt::Display for ExceptionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExceptionCategory::ThreadDeath => write!(f, "ThreadDeath"),
            ExceptionCategory::ConnectException => write!(f, "ConnectException"),
            ExceptionCategory::ClosedException => write!(f, "ClosedException"),
            ExceptionCategory::JavaHelpPrint => write!(f, "JavaHelpPrint"),
            ExceptionCategory::JavaHelpTheme => write!(f, "JavaHelpTheme"),
            ExceptionCategory::OutOfMemory => write!(f, "OutOfMemory"),
            ExceptionCategory::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// UncaughtError
// ---------------------------------------------------------------------------

/// Represents an uncaught error that has been classified by the handler.
#[derive(Debug, Clone)]
pub struct UncaughtError {
    /// The error message.
    pub message: String,
    /// The error category.
    pub category: ExceptionCategory,
    /// Optional stack trace as a string.
    pub stack_trace: Option<String>,
    /// Memory statistics if the error is an OOM.
    pub memory_info: Option<MemoryInfo>,
}

/// Memory statistics captured at the time of an out-of-memory error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryInfo {
    /// Free memory in bytes.
    pub free: u64,
    /// Maximum memory in bytes.
    pub max: u64,
    /// Total memory in bytes.
    pub total: u64,
}

impl fmt::Display for UncaughtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.category, self.message)?;
        if let Some(ref mem) = self.memory_info {
            write!(
                f,
                " (memory: free={}, max={}, total={})",
                mem.free, mem.max, mem.total
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SwingExceptionHandler
// ---------------------------------------------------------------------------

/// Handler for uncaught exceptions in the event-dispatch context.
///
/// In the Java version this is installed as `Thread.setDefaultUncaughtExceptionHandler`.
/// In Rust the caller explicitly invokes [`handle`] or [`classify`] when
/// an error occurs.
pub struct SwingExceptionHandler {
    /// Set of stack-trace substrings that identify known Java Help bugs.
    known_help_patterns: HashSet<String>,
}

impl SwingExceptionHandler {
    /// Create a new handler with the default set of known-bad patterns.
    pub fn new() -> Self {
        let mut known_help_patterns = HashSet::new();
        known_help_patterns.insert(
            "com.sun.java.help.impl.JHelpPrintHandler$JHFrame.validate".to_string(),
        );
        known_help_patterns
            .insert("javax.help.plaf.basic.BasicTOCNavigatorUI".to_string());
        known_help_patterns.insert(
            "javax.swing.text.html.BlockView".to_string(),
        );
        Self { known_help_patterns }
    }

    /// Classify a raw error message and optional stack trace into a
    /// structured [`UncaughtError`].
    ///
    /// This is the Rust equivalent of Java's `handleUncaughtException`.
    pub fn classify(
        &self,
        message: &str,
        stack_trace: Option<&str>,
        memory_info: Option<MemoryInfo>,
    ) -> UncaughtError {
        let category = self.categorize(message, stack_trace);

        UncaughtError {
            message: message.to_string(),
            category,
            stack_trace: stack_trace.map(|s| s.to_string()),
            memory_info,
        }
    }

    /// Classify and decide whether the error should be reported.
    ///
    /// Returns `Some(error)` if the error is non-ignorable (should be
    /// surfaced to the user), `None` if it is a known-benign exception.
    pub fn handle(
        &self,
        message: &str,
        stack_trace: Option<&str>,
        memory_info: Option<MemoryInfo>,
    ) -> Option<UncaughtError> {
        let error = self.classify(message, stack_trace, memory_info);
        if error.category.should_ignore() {
            None
        } else {
            Some(error)
        }
    }

    /// Determine the [`ExceptionCategory`] for the given error.
    fn categorize(&self, message: &str, stack_trace: Option<&str>) -> ExceptionCategory {
        let lower_msg = message.to_lowercase();

        // Check for known benign exceptions by message keywords
        if lower_msg.contains("threaddeath") {
            return ExceptionCategory::ThreadDeath;
        }
        if lower_msg.contains("connectexception") || lower_msg.contains("connection refused") {
            return ExceptionCategory::ConnectException;
        }
        if lower_msg.contains("closedexception") || lower_msg.contains("stream closed") {
            return ExceptionCategory::ClosedException;
        }
        if lower_msg.contains("outofmemoryerror") || lower_msg.contains("out of memory") {
            return ExceptionCategory::OutOfMemory;
        }

        // Check stack trace for known help-system patterns
        if let Some(trace) = stack_trace {
            if self.is_known_java_help_exception(trace) {
                return ExceptionCategory::JavaHelpPrint;
            }
            if self.is_java_help_theme_exception(trace) {
                return ExceptionCategory::JavaHelpTheme;
            }
        }

        ExceptionCategory::Unknown
    }

    /// Check if the stack trace matches known Java Help printing bugs.
    fn is_known_java_help_exception(&self, stack_trace: &str) -> bool {
        stack_trace.contains("com.sun.java.help.impl.JHelpPrintHandler$JHFrame.validate")
    }

    /// Check if the stack trace matches known Java Help theme-switching bugs.
    fn is_java_help_theme_exception(&self, stack_trace: &str) -> bool {
        if stack_trace.contains("javax.help.plaf.basic.BasicTOCNavigatorUI") {
            return true;
        }
        if stack_trace.contains("javax.swing.text.html.BlockView")
            && stack_trace.contains("javax.swing.text.html.HTMLDocument.fireChangedUpdate")
        {
            return true;
        }
        false
    }
}

impl Default for SwingExceptionHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_death_ignored() {
        let handler = SwingExceptionHandler::new();
        let result = handler.handle("ThreadDeath", None, None);
        assert!(result.is_none(), "ThreadDeath should be ignored");
    }

    #[test]
    fn test_connect_exception_ignored() {
        let handler = SwingExceptionHandler::new();
        let result = handler.handle("ConnectException", None, None);
        assert!(result.is_none(), "ConnectException should be ignored");
    }

    #[test]
    fn test_closed_exception_ignored() {
        let handler = SwingExceptionHandler::new();
        let result = handler.handle("ClosedException", None, None);
        assert!(result.is_none(), "ClosedException should be ignored");
    }

    #[test]
    fn test_connection_refused_ignored() {
        let handler = SwingExceptionHandler::new();
        let result = handler.handle("Connection refused", None, None);
        assert!(result.is_none(), "Connection refused should be ignored");
    }

    #[test]
    fn test_stream_closed_ignored() {
        let handler = SwingExceptionHandler::new();
        let result = handler.handle("Stream closed", None, None);
        assert!(result.is_none(), "Stream closed should be ignored");
    }

    #[test]
    fn test_out_of_memory_surfaced() {
        let handler = SwingExceptionHandler::new();
        let mem = MemoryInfo {
            free: 1024,
            max: 65536,
            total: 32768,
        };
        let result = handler.handle("OutOfMemoryError", None, Some(mem));
        assert!(result.is_some(), "OOM should be surfaced");
        let error = result.unwrap();
        assert_eq!(error.category, ExceptionCategory::OutOfMemory);
        assert!(error.memory_info.is_some());
    }

    #[test]
    fn test_out_of_memory_message_variant() {
        let handler = SwingExceptionHandler::new();
        let result = handler.handle("java.lang.OutOfMemoryError: Java heap space", None, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().category, ExceptionCategory::OutOfMemory);
    }

    #[test]
    fn test_unknown_error_surfaced() {
        let handler = SwingExceptionHandler::new();
        let result = handler.handle("NullPointerException", None, None);
        assert!(result.is_some(), "Unknown error should be surfaced");
        let error = result.unwrap();
        assert_eq!(error.category, ExceptionCategory::Unknown);
        assert_eq!(error.severity(), ErrorSeverity::Error);
    }

    #[test]
    fn test_java_help_print_ignored() {
        let handler = SwingExceptionHandler::new();
        let stack = "at com.sun.java.help.impl.JHelpPrintHandler$JHFrame.validate(JHelpPrintHandler.java:123)\n\tat java.base/java.awt.EventDispatchThread.run";
        let result = handler.handle("some error", Some(stack), None);
        assert!(result.is_none(), "Java Help print exception should be ignored");
    }

    #[test]
    fn test_java_help_theme_ignored() {
        let handler = SwingExceptionHandler::new();
        let stack = "at javax.help.plaf.basic.BasicTOCNavigatorUI.someMethod(BasicTOCNavigatorUI.java:45)";
        let result = handler.handle("theme error", Some(stack), None);
        assert!(
            result.is_none(),
            "Java Help theme exception should be ignored"
        );
    }

    #[test]
    fn test_java_help_block_view_ignored() {
        let handler = SwingExceptionHandler::new();
        let stack = "at javax.swing.text.html.BlockView.layout(BlockView.java:100)\n\tat javax.swing.text.html.HTMLDocument.fireChangedUpdate(HTMLDocument.java:200)";
        let result = handler.handle("block error", Some(stack), None);
        assert!(
            result.is_none(),
            "Java Help BlockView exception should be ignored"
        );
    }

    #[test]
    fn test_classify_returns_always() {
        let handler = SwingExceptionHandler::new();
        let error = handler.classify("ThreadDeath", None, None);
        assert_eq!(error.category, ExceptionCategory::ThreadDeath);
        assert!(error.category.should_ignore());
    }

    #[test]
    fn test_display_error() {
        let handler = SwingExceptionHandler::new();
        let error = handler.classify("test error", None, None);
        let display = format!("{}", error);
        assert!(display.contains("[Unknown]"));
        assert!(display.contains("test error"));
    }

    #[test]
    fn test_display_error_with_memory() {
        let handler = SwingExceptionHandler::new();
        let mem = MemoryInfo {
            free: 100,
            max: 200,
            total: 300,
        };
        let error = handler.classify("OutOfMemoryError", None, Some(mem));
        let display = format!("{}", error);
        assert!(display.contains("memory: free=100"));
    }

    #[test]
    fn test_display_severity() {
        assert_eq!(format!("{}", ErrorSeverity::Info), "INFO");
        assert_eq!(format!("{}", ErrorSeverity::Warning), "WARN");
        assert_eq!(format!("{}", ErrorSeverity::Error), "ERROR");
    }

    #[test]
    fn test_display_category() {
        assert_eq!(format!("{}", ExceptionCategory::ThreadDeath), "ThreadDeath");
        assert_eq!(format!("{}", ExceptionCategory::OutOfMemory), "OutOfMemory");
        assert_eq!(format!("{}", ExceptionCategory::Unknown), "Unknown");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(ErrorSeverity::Info < ErrorSeverity::Warning);
        assert!(ErrorSeverity::Warning < ErrorSeverity::Error);
    }

    #[test]
    fn test_memory_info_equality() {
        let a = MemoryInfo {
            free: 1,
            max: 2,
            total: 3,
        };
        let b = MemoryInfo {
            free: 1,
            max: 2,
            total: 3,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_stack_trace_preserved() {
        let handler = SwingExceptionHandler::new();
        let error = handler.classify("test", Some("line1\nline2"), None);
        assert_eq!(error.stack_trace, Some("line1\nline2".to_string()));
    }

    #[test]
    fn test_default_handler() {
        let handler = SwingExceptionHandler::default();
        assert!(handler.known_help_patterns.len() > 0);
    }
}
