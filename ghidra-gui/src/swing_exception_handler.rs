//! Global exception handler for GUI event dispatch threads.
//!
//! Ports `ghidra.SwingExceptionHandler`.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

/// Kinds of exceptions that should be silently ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgnorableExceptionKind {
    /// Thread death is expected during shutdown.
    ThreadDeath,
    /// Connection was refused or broken.
    ConnectionRefused,
    /// A resource was already closed.
    ClosedResource,
    /// A Java Help API exception (internal rendering error).
    JavaHelpApi,
}

/// Central handler for uncaught exceptions in the UI thread.
///
/// Analogous to Java's `UncaughtExceptionHandler`.
#[derive(Debug)]
pub struct SwingExceptionHandler {
    ignored_kinds: Mutex<HashSet<IgnorableExceptionKind>>,
    suppressed_patterns: Mutex<Vec<String>>,
}

static HANDLER: OnceLock<SwingExceptionHandler> = OnceLock::new();

impl SwingExceptionHandler {
    /// Obtain the global singleton.
    pub fn global() -> &'static Self {
        HANDLER.get_or_init(|| Self {
            ignored_kinds: Mutex::new(HashSet::new()),
            suppressed_patterns: Mutex::new(Vec::new()),
        })
    }

    /// Register this handler as the process-wide default.
    ///
    /// In a Rust GUI application this would hook into whatever
    /// event-loop error handler is appropriate (e.g., eframe's
    /// `on_fatal_event` or a custom panic hook).
    pub fn register_handler() {
        let _handler = Self::global();
        log::info!("SwingExceptionHandler registered");
    }

    /// Handle an uncaught exception, logging or reporting as appropriate.
    pub fn handle_uncaught_exception(error_msg: &str) {
        let handler = Self::global();

        // Check suppressed patterns
        {
            let patterns = handler.suppressed_patterns.lock().unwrap();
            for pat in patterns.iter() {
                if error_msg.contains(pat.as_str()) {
                    log::debug!("Suppressed known exception: {}", error_msg);
                    return;
                }
            }
        }

        // Check OOM
        let details = if error_msg.contains("OutOfMemory") {
            format!("Uncaught OOM: {}", error_msg)
        } else {
            format!("Uncaught Exception: {}", error_msg)
        };

        log::error!("{}", details);
    }

    /// Add an exception kind to the ignore list.
    pub fn ignore_kind(kind: IgnorableExceptionKind) {
        let handler = Self::global();
        handler.ignored_kinds.lock().unwrap().insert(kind);
    }

    /// Add a stack-trace pattern that should be silently ignored.
    pub fn add_suppressed_pattern(pattern: &str) {
        let handler = Self::global();
        handler
            .suppressed_patterns
            .lock()
            .unwrap()
            .push(pattern.to_string());
    }

    /// Returns true if the given kind should be ignored.
    pub fn should_ignore(kind: IgnorableExceptionKind) -> bool {
        let handler = Self::global();
        handler.ignored_kinds.lock().unwrap().contains(&kind)
    }
}

impl Default for SwingExceptionHandler {
    fn default() -> Self {
        Self {
            ignored_kinds: Mutex::new(HashSet::new()),
            suppressed_patterns: Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_is_singleton() {
        let a = SwingExceptionHandler::global() as *const _;
        let b = SwingExceptionHandler::global() as *const _;
        assert_eq!(a, b);
    }

    #[test]
    fn test_ignore_kind() {
        SwingExceptionHandler::ignore_kind(IgnorableExceptionKind::ThreadDeath);
        assert!(SwingExceptionHandler::should_ignore(
            IgnorableExceptionKind::ThreadDeath
        ));
    }

    #[test]
    fn test_suppressed_pattern() {
        SwingExceptionHandler::add_suppressed_pattern("JHelpPrintHandler");
        let handler = SwingExceptionHandler::global();
        let patterns = handler.suppressed_patterns.lock().unwrap();
        assert!(patterns.iter().any(|p| p.contains("JHelpPrintHandler")));
    }

    #[test]
    fn test_handle_uncaught_logs() {
        // Should not panic
        SwingExceptionHandler::handle_uncaught_exception("test error message");
    }

    #[test]
    fn test_handle_oom() {
        // Should not panic on OOM message
        SwingExceptionHandler::handle_uncaught_exception("OutOfMemoryError: heap space");
    }
}
