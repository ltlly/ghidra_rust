//! Trace event and log types for the debug target model.
//!
//! Ported from Ghidra's `ghidra.trace.model.time` package.
//! Provides event markers, log entries, and event-type metadata for
//! recording debug session events (breakpoint hits, signals, process
//! creation/destruction, thread start/stop, etc.).

use serde::{Deserialize, Serialize};

use crate::target::KeyPath;

/// An event marker within a trace.
///
/// Ported from Ghidra's `TraceEvent`. Represents a discrete event that
/// occurred during a debug session, such as a breakpoint hit, a signal
/// being received, or a thread being created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// The database key for this event.
    pub key: i64,
    /// The snap (snapshot time) at which this event occurred.
    pub snap: i64,
    /// The event type (e.g., "breakpoint-hit", "signal-received").
    pub event_type: TraceEventType,
    /// The thread in which the event occurred, if applicable.
    pub thread_key: Option<i64>,
    /// The process in which the event occurred, if applicable.
    pub process_key: Option<i64>,
    /// A human-readable description.
    pub description: String,
    /// The path in the target tree where this event is recorded.
    pub path: KeyPath,
    /// Additional metadata (key-value pairs).
    pub metadata: std::collections::BTreeMap<String, String>,
}

impl TraceEvent {
    /// Create a new trace event.
    pub fn new(
        key: i64,
        snap: i64,
        event_type: TraceEventType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            key,
            snap,
            event_type,
            thread_key: None,
            process_key: None,
            description: description.into(),
            path: KeyPath::ROOT,
            metadata: std::collections::BTreeMap::new(),
        }
    }

    /// Set the thread key.
    pub fn with_thread_key(mut self, key: i64) -> Self {
        self.thread_key = Some(key);
        self
    }

    /// Set the process key.
    pub fn with_process_key(mut self, key: i64) -> Self {
        self.process_key = Some(key);
        self
    }

    /// Add a metadata entry.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set the path.
    pub fn with_path(mut self, path: KeyPath) -> Self {
        self.path = path;
        self
    }

    /// Whether this event is associated with a specific thread.
    pub fn has_thread(&self) -> bool {
        self.thread_key.is_some()
    }

    /// Whether this event is associated with a specific process.
    pub fn has_process(&self) -> bool {
        self.process_key.is_some()
    }
}

/// Well-known event types for debug sessions.
///
/// Ported from Ghidra's trace event type enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceEventType {
    /// A breakpoint was hit.
    BreakpointHit,
    /// A watchpoint was hit.
    WatchpointHit,
    /// A signal was received (e.g., SIGSEGV, SIGINT).
    Signal,
    /// A thread was created.
    ThreadCreated,
    /// A thread was destroyed.
    ThreadDestroyed,
    /// A process was created / attached.
    ProcessCreated,
    /// A process was destroyed / detached.
    ProcessDestroyed,
    /// A step (single-step) was completed.
    StepCompleted,
    /// A library/module was loaded.
    ModuleLoaded,
    /// A library/module was unloaded.
    ModuleUnloaded,
    /// Memory was modified.
    MemoryChanged,
    /// A custom/extension event.
    Custom(String),
}

impl TraceEventType {
    /// Get a human-readable label for the event type.
    pub fn label(&self) -> String {
        match self {
            Self::BreakpointHit => "Breakpoint Hit".into(),
            Self::WatchpointHit => "Watchpoint Hit".into(),
            Self::Signal => "Signal".into(),
            Self::ThreadCreated => "Thread Created".into(),
            Self::ThreadDestroyed => "Thread Destroyed".into(),
            Self::ProcessCreated => "Process Created".into(),
            Self::ProcessDestroyed => "Process Destroyed".into(),
            Self::StepCompleted => "Step Completed".into(),
            Self::ModuleLoaded => "Module Loaded".into(),
            Self::ModuleUnloaded => "Module Unloaded".into(),
            Self::MemoryChanged => "Memory Changed".into(),
            Self::Custom(name) => name.clone(),
        }
    }

    /// Whether this event is a "stop" event (debugger should pause).
    pub fn is_stop_event(&self) -> bool {
        matches!(
            self,
            Self::BreakpointHit | Self::WatchpointHit | Self::Signal | Self::StepCompleted
        )
    }

    /// Whether this event is a lifecycle event.
    pub fn is_lifecycle(&self) -> bool {
        matches!(
            self,
            Self::ThreadCreated
                | Self::ThreadDestroyed
                | Self::ProcessCreated
                | Self::ProcessDestroyed
                | Self::ModuleLoaded
                | Self::ModuleUnloaded
        )
    }
}

impl std::fmt::Display for TraceEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// A log entry for recording messages during a debug session.
///
/// Ported from Ghidra's trace log/console output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceLogEntry {
    /// The snap at which this entry was logged.
    pub snap: i64,
    /// The log level.
    pub level: LogLevel,
    /// The message text.
    pub message: String,
    /// The category (e.g., "gdb", "lldb", "plugin").
    pub category: String,
    /// Timestamp in milliseconds since epoch.
    pub timestamp_ms: Option<i64>,
}

impl TraceLogEntry {
    /// Create a new log entry.
    pub fn new(snap: i64, level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            snap,
            level,
            message: message.into(),
            category: String::new(),
            timestamp_ms: None,
        }
    }

    /// Set the category.
    pub fn with_category(mut self, cat: impl Into<String>) -> Self {
        self.category = cat.into();
        self
    }

    /// Set the timestamp.
    pub fn with_timestamp(mut self, ms: i64) -> Self {
        self.timestamp_ms = Some(ms);
        self
    }
}

/// Log severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    /// Detailed trace information.
    Trace,
    /// Debug-level messages.
    Debug,
    /// Informational messages.
    Info,
    /// Warning messages.
    Warn,
    /// Error messages.
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trace => write!(f, "TRACE"),
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// Manager for trace events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceEventManager {
    events: Vec<TraceEvent>,
    next_key: i64,
}

impl TraceEventManager {
    /// Create a new event manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new event, auto-assigning a key.
    pub fn record_event(&mut self, snap: i64, event_type: TraceEventType, desc: impl Into<String>) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        self.events
            .push(TraceEvent::new(key, snap, event_type, desc));
        key
    }

    /// Get all events.
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Get events at a given snap.
    pub fn events_at_snap(&self, snap: i64) -> Vec<&TraceEvent> {
        self.events.iter().filter(|e| e.snap == snap).collect()
    }

    /// Get events of a given type.
    pub fn events_of_type(&self, event_type: &TraceEventType) -> Vec<&TraceEvent> {
        self.events.iter().filter(|e| &e.event_type == event_type).collect()
    }

    /// Get the number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether there are no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Delete an event by key.
    pub fn delete_event(&mut self, key: i64) -> bool {
        let before = self.events.len();
        self.events.retain(|e| e.key != key);
        self.events.len() < before
    }
}

/// Manager for trace log entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceLogManager {
    entries: Vec<TraceLogEntry>,
}

impl TraceLogManager {
    /// Create a new log manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a log entry.
    pub fn log(&mut self, entry: TraceLogEntry) {
        self.entries.push(entry);
    }

    /// Log an info message.
    pub fn info(&mut self, snap: i64, message: impl Into<String>) {
        self.log(TraceLogEntry::new(snap, LogLevel::Info, message));
    }

    /// Log a warning message.
    pub fn warn(&mut self, snap: i64, message: impl Into<String>) {
        self.log(TraceLogEntry::new(snap, LogLevel::Warn, message));
    }

    /// Log an error message.
    pub fn error(&mut self, snap: i64, message: impl Into<String>) {
        self.log(TraceLogEntry::new(snap, LogLevel::Error, message));
    }

    /// Get all entries.
    pub fn entries(&self) -> &[TraceLogEntry] {
        &self.entries
    }

    /// Get entries at a given snap.
    pub fn entries_at_snap(&self, snap: i64) -> Vec<&TraceLogEntry> {
        self.entries.iter().filter(|e| e.snap == snap).collect()
    }

    /// Get entries of a given level or higher severity.
    pub fn entries_at_level(&self, min_level: LogLevel) -> Vec<&TraceLogEntry> {
        self.entries.iter().filter(|e| e.level >= min_level).collect()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_labels() {
        assert_eq!(TraceEventType::BreakpointHit.label(), "Breakpoint Hit");
        assert_eq!(TraceEventType::Signal.label(), "Signal");
    }

    #[test]
    fn test_event_type_stop() {
        assert!(TraceEventType::BreakpointHit.is_stop_event());
        assert!(TraceEventType::Signal.is_stop_event());
        assert!(!TraceEventType::ThreadCreated.is_stop_event());
    }

    #[test]
    fn test_event_type_lifecycle() {
        assert!(TraceEventType::ProcessCreated.is_lifecycle());
        assert!(TraceEventType::ModuleLoaded.is_lifecycle());
        assert!(!TraceEventType::StepCompleted.is_lifecycle());
    }

    #[test]
    fn test_trace_event_creation() {
        let event = TraceEvent::new(1, 5, TraceEventType::BreakpointHit, "hit at main")
            .with_thread_key(10)
            .with_process_key(100)
            .with_metadata("address", "0x400000");
        assert_eq!(event.key, 1);
        assert_eq!(event.snap, 5);
        assert_eq!(event.description, "hit at main");
        assert!(event.has_thread());
        assert!(event.has_process());
        assert_eq!(event.metadata.get("address").unwrap(), "0x400000");
    }

    #[test]
    fn test_trace_event_type_display() {
        assert_eq!(TraceEventType::BreakpointHit.to_string(), "Breakpoint Hit");
        assert_eq!(
            TraceEventType::Custom("my-event".into()).to_string(),
            "my-event"
        );
    }

    #[test]
    fn test_trace_event_manager() {
        let mut mgr = TraceEventManager::new();
        mgr.record_event(0, TraceEventType::ProcessCreated, "attached");
        mgr.record_event(1, TraceEventType::BreakpointHit, "bp hit");
        mgr.record_event(1, TraceEventType::ThreadCreated, "new thread");

        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.events_at_snap(1).len(), 2);
        assert_eq!(mgr.events_of_type(&TraceEventType::BreakpointHit).len(), 1);
    }

    #[test]
    fn test_trace_event_manager_delete() {
        let mut mgr = TraceEventManager::new();
        let key = mgr.record_event(0, TraceEventType::StepCompleted, "step");
        assert_eq!(mgr.len(), 1);
        assert!(mgr.delete_event(key));
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_log_entry() {
        let entry = TraceLogEntry::new(0, LogLevel::Info, "Hello")
            .with_category("gdb")
            .with_timestamp(1000);
        assert_eq!(entry.message, "Hello");
        assert_eq!(entry.category, "gdb");
        assert_eq!(entry.timestamp_ms, Some(1000));
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Error.to_string(), "ERROR");
        assert_eq!(LogLevel::Info.to_string(), "INFO");
    }

    #[test]
    fn test_log_manager() {
        let mut mgr = TraceLogManager::new();
        mgr.info(0, "connected");
        mgr.warn(0, "slow response");
        mgr.error(1, "connection lost");

        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.entries_at_snap(0).len(), 2);
        assert_eq!(mgr.entries_at_level(LogLevel::Warn).len(), 2);
    }

    #[test]
    fn test_event_serde() {
        let event = TraceEvent::new(1, 0, TraceEventType::Signal, "SIGSEGV");
        let json = serde_json::to_string(&event).unwrap();
        let back: TraceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, TraceEventType::Signal);
    }

    #[test]
    fn test_log_entry_serde() {
        let entry = TraceLogEntry::new(0, LogLevel::Error, "oops");
        let json = serde_json::to_string(&entry).unwrap();
        let back: TraceLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message, "oops");
    }

    #[test]
    fn test_log_manager_empty() {
        let mgr = TraceLogManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
    }
}
