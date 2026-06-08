//! Analysis listener infrastructure.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener`.
//!
//! Provides the callback interface for notifications when analysis
//! starts, ends, or encounters errors. Listeners are registered with
//! the [`AutoAnalysisManager`] and invoked at key lifecycle points.

use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// AutoAnalysisManagerListener trait
// ---------------------------------------------------------------------------

/// Callback interface for auto-analysis lifecycle events.
///
/// Ported from `AutoAnalysisManagerListener.java`. Implementors receive
/// notifications when analysis starts, ends, or is cancelled.
///
/// # Usage
///
/// ```ignore
/// struct MyListener;
/// impl AutoAnalysisManagerListener for MyListener {
///     fn analysis_ended(&self, is_cancelled: bool) {
///         if is_cancelled {
///             println!("Analysis was cancelled");
///         } else {
///             println!("Analysis completed");
///         }
///     }
/// }
/// ```
pub trait AutoAnalysisManagerListener: Send + Sync {
    /// Called when the analysis run has ended.
    ///
    /// # Arguments
    /// * `is_cancelled` - `true` if the analysis was cancelled before completion.
    fn analysis_ended(&self, is_cancelled: bool);

    /// Called when a new analysis iteration begins.
    ///
    /// Default implementation does nothing.
    fn analysis_started(&self) {}

    /// Called when an analyzer reports a warning or error.
    ///
    /// Default implementation does nothing.
    fn analysis_message(&self, _analyzer_name: &str, _message: &str) {}

    /// Called when analysis progress changes.
    ///
    /// Default implementation does nothing.
    fn analysis_progress(&self, _completed: usize, _total: usize) {}
}

// ---------------------------------------------------------------------------
// ListenerRegistry
// ---------------------------------------------------------------------------

/// Thread-safe registry for analysis listeners.
///
/// Manages a list of [`AutoAnalysisManagerListener`] instances and
/// dispatches events to all registered listeners.
#[derive(Clone)]
pub struct ListenerRegistry {
    listeners: Arc<Mutex<Vec<Box<dyn AutoAnalysisManagerListener>>>>,
}

impl std::fmt::Debug for ListenerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.listeners.lock().unwrap().len();
        write!(f, "ListenerRegistry({} listeners)", count)
    }
}

impl ListenerRegistry {
    /// Create a new empty listener registry.
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a listener. Duplicates are not checked.
    pub fn add_listener(&self, listener: Box<dyn AutoAnalysisManagerListener>) {
        self.listeners.lock().unwrap().push(listener);
    }

    /// Remove all registered listeners.
    pub fn clear(&self) {
        self.listeners.lock().unwrap().clear();
    }

    /// Get the number of registered listeners.
    pub fn len(&self) -> usize {
        self.listeners.lock().unwrap().len()
    }

    /// Whether no listeners are registered.
    pub fn is_empty(&self) -> bool {
        self.listeners.lock().unwrap().is_empty()
    }

    /// Notify all listeners that analysis has ended.
    pub fn notify_analysis_ended(&self, is_cancelled: bool) {
        let listeners = self.listeners.lock().unwrap();
        for listener in listeners.iter() {
            listener.analysis_ended(is_cancelled);
        }
    }

    /// Notify all listeners that analysis has started.
    pub fn notify_analysis_started(&self) {
        let listeners = self.listeners.lock().unwrap();
        for listener in listeners.iter() {
            listener.analysis_started();
        }
    }

    /// Notify all listeners of an analysis message.
    pub fn notify_analysis_message(&self, analyzer_name: &str, message: &str) {
        let listeners = self.listeners.lock().unwrap();
        for listener in listeners.iter() {
            listener.analysis_message(analyzer_name, message);
        }
    }

    /// Notify all listeners of analysis progress.
    pub fn notify_analysis_progress(&self, completed: usize, total: usize) {
        let listeners = self.listeners.lock().unwrap();
        for listener in listeners.iter() {
            listener.analysis_progress(completed, total);
        }
    }
}

impl Default for ListenerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LoggingListener -- built-in listener that collects messages
// ---------------------------------------------------------------------------

/// A listener that collects analysis messages for later inspection.
///
/// Useful for testing and headless operation where messages need to be
/// captured rather than displayed.
#[derive(Debug, Clone)]
pub struct LoggingListener {
    messages: Arc<Mutex<Vec<AnalysisLogEntry>>>,
}

/// A single log entry captured by [`LoggingListener`].
#[derive(Debug, Clone)]
pub struct AnalysisLogEntry {
    /// The analyzer that generated the message, if any.
    pub analyzer_name: Option<String>,
    /// The log message text.
    pub message: String,
    /// Whether this was a cancellation event.
    pub is_cancellation: bool,
}

impl LoggingListener {
    /// Create a new logging listener.
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get all captured log entries.
    pub fn entries(&self) -> Vec<AnalysisLogEntry> {
        self.messages.lock().unwrap().clone()
    }

    /// Get the number of captured entries.
    pub fn entry_count(&self) -> usize {
        self.messages.lock().unwrap().len()
    }

    /// Clear all captured entries.
    pub fn clear(&self) {
        self.messages.lock().unwrap().clear();
    }

    /// Check if any cancellation events were recorded.
    pub fn has_cancellation(&self) -> bool {
        self.messages
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.is_cancellation)
    }

    /// Get all non-cancellation messages as a single string.
    pub fn messages_as_string(&self) -> String {
        self.messages
            .lock()
            .unwrap()
            .iter()
            .filter(|e| !e.is_cancellation)
            .map(|e| {
                if let Some(ref name) = e.analyzer_name {
                    format!("[{}] {}", name, e.message)
                } else {
                    e.message.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for LoggingListener {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoAnalysisManagerListener for LoggingListener {
    fn analysis_ended(&self, is_cancelled: bool) {
        self.messages.lock().unwrap().push(AnalysisLogEntry {
            analyzer_name: None,
            message: if is_cancelled {
                "Analysis cancelled".to_string()
            } else {
                "Analysis completed".to_string()
            },
            is_cancellation: is_cancelled,
        });
    }

    fn analysis_started(&self) {
        self.messages.lock().unwrap().push(AnalysisLogEntry {
            analyzer_name: None,
            message: "Analysis started".to_string(),
            is_cancellation: false,
        });
    }

    fn analysis_message(&self, analyzer_name: &str, message: &str) {
        self.messages.lock().unwrap().push(AnalysisLogEntry {
            analyzer_name: Some(analyzer_name.to_string()),
            message: message.to_string(),
            is_cancellation: false,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct TestListener {
        ended_called: Arc<AtomicBool>,
        last_cancelled: Arc<AtomicBool>,
        started_count: Arc<AtomicUsize>,
    }

    impl TestListener {
        fn new() -> (Self, Arc<AtomicBool>, Arc<AtomicBool>, Arc<AtomicUsize>) {
            let ended = Arc::new(AtomicBool::new(false));
            let cancelled = Arc::new(AtomicBool::new(false));
            let started = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    ended_called: ended.clone(),
                    last_cancelled: cancelled.clone(),
                    started_count: started.clone(),
                },
                ended,
                cancelled,
                started,
            )
        }
    }

    impl AutoAnalysisManagerListener for TestListener {
        fn analysis_ended(&self, is_cancelled: bool) {
            self.ended_called.store(true, Ordering::SeqCst);
            self.last_cancelled.store(is_cancelled, Ordering::SeqCst);
        }

        fn analysis_started(&self) {
            self.started_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_listener_registry_add_and_notify() {
        let registry = ListenerRegistry::new();
        assert!(registry.is_empty());

        let (listener, ended, cancelled, _) = TestListener::new();
        registry.add_listener(Box::new(listener));
        assert_eq!(registry.len(), 1);

        registry.notify_analysis_ended(true);
        assert!(ended.load(Ordering::SeqCst));
        assert!(cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn test_listener_registry_multiple() {
        let registry = ListenerRegistry::new();
        let (l1, ended1, _, started1) = TestListener::new();
        let (l2, ended2, _, started2) = TestListener::new();

        registry.add_listener(Box::new(l1));
        registry.add_listener(Box::new(l2));

        registry.notify_analysis_started();
        assert_eq!(started1.load(Ordering::SeqCst), 1);
        assert_eq!(started2.load(Ordering::SeqCst), 1);

        registry.notify_analysis_ended(false);
        assert!(ended1.load(Ordering::SeqCst));
        assert!(ended2.load(Ordering::SeqCst));
    }

    #[test]
    fn test_listener_registry_clear() {
        let registry = ListenerRegistry::new();
        let (listener, _, _, _) = TestListener::new();
        registry.add_listener(Box::new(listener));
        assert_eq!(registry.len(), 1);

        registry.clear();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_logging_listener() {
        let listener = LoggingListener::new();
        listener.analysis_started();
        listener.analysis_message("TestAnalyzer", "Found something");
        listener.analysis_ended(false);

        assert_eq!(listener.entry_count(), 3);
        assert!(!listener.has_cancellation());

        let entries = listener.entries();
        assert_eq!(entries[0].message, "Analysis started");
        assert_eq!(entries[1].analyzer_name.as_deref(), Some("TestAnalyzer"));
        assert_eq!(entries[2].message, "Analysis completed");
    }

    #[test]
    fn test_logging_listener_cancellation() {
        let listener = LoggingListener::new();
        listener.analysis_ended(true);
        assert!(listener.has_cancellation());
    }

    #[test]
    fn test_logging_listener_messages_as_string() {
        let listener = LoggingListener::new();
        listener.analysis_message("Analyzer1", "msg1");
        listener.analysis_message("Analyzer2", "msg2");
        listener.analysis_ended(true); // cancelled -> filtered out

        let s = listener.messages_as_string();
        assert!(s.contains("[Analyzer1] msg1"));
        assert!(s.contains("[Analyzer2] msg2"));
        // The cancellation entry is filtered out
        assert!(!s.contains("Analysis cancelled"));
    }
}
