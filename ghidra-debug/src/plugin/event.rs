//! Debugger plugin events.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.event` package.

use serde::{Deserialize, Serialize};

use crate::util::DebugCoordinates;

/// Event fired when a trace is activated in the debugger.
///
/// Ported from Ghidra's `TraceActivatedPluginEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceActivatedEvent {
    /// The trace ID that was activated.
    pub trace_id: String,
    /// The current coordinates after activation.
    pub coordinates: Option<DebugCoordinates>,
}

impl TraceActivatedEvent {
    /// Create a new event.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            coordinates: None,
        }
    }

    /// Set the coordinates.
    pub fn with_coordinates(mut self, coords: DebugCoordinates) -> Self {
        self.coordinates = Some(coords);
        self
    }
}

/// Event fired when a trace is closed.
///
/// Ported from Ghidra's `TraceClosedPluginEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceClosedEvent {
    /// The trace ID that was closed.
    pub trace_id: String,
}

impl TraceClosedEvent {
    /// Create a new event.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
        }
    }
}

/// Event fired when the trace highlight changes.
///
/// Ported from Ghidra's `TraceHighlightPluginEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHighlightEvent {
    /// The trace ID.
    pub trace_id: String,
    /// The highlighted address offset, if any.
    pub offset: Option<u64>,
}

impl TraceHighlightEvent {
    /// Create a new event.
    pub fn new(trace_id: impl Into<String>, offset: Option<u64>) -> Self {
        Self {
            trace_id: trace_id.into(),
            offset,
        }
    }
}

/// Event fired when coordinates become inactive (e.g., a trace is deactivated).
///
/// Ported from Ghidra's `TraceInactiveCoordinatesPluginEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceInactiveCoordinatesEvent {
    /// The trace ID that became inactive.
    pub trace_id: String,
}

impl TraceInactiveCoordinatesEvent {
    /// Create a new event.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
        }
    }
}

/// Event fired when the debugger platform changes.
///
/// Ported from Ghidra's `DebuggerPlatformPluginEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerPlatformEvent {
    /// The new platform name.
    pub platform_name: String,
    /// The new language ID.
    pub language_id: String,
    /// The new compiler spec ID.
    pub compiler_spec_id: String,
}

impl DebuggerPlatformEvent {
    /// Create a new event.
    pub fn new(
        platform_name: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            platform_name: platform_name.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
        }
    }
}

/// Event fired when a trace is opened.
///
/// Ported from Ghidra's `TraceOpenedPluginEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceOpenedEvent {
    /// The trace ID that was opened.
    pub trace_id: String,
}

impl TraceOpenedEvent {
    /// Create a new event.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
        }
    }
}

/// Event fired when the location in a trace changes.
///
/// Ported from Ghidra's `TraceLocationPluginEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceLocationEvent {
    /// The trace ID.
    pub trace_id: String,
    /// The new address offset.
    pub offset: u64,
    /// The address space name.
    pub space: Option<String>,
}

impl TraceLocationEvent {
    /// Create a new event.
    pub fn new(trace_id: impl Into<String>, offset: u64) -> Self {
        Self {
            trace_id: trace_id.into(),
            offset,
            space: None,
        }
    }

    /// Set the address space.
    pub fn with_space(mut self, space: impl Into<String>) -> Self {
        self.space = Some(space.into());
        self
    }
}

/// Event fired when the selection in a trace listing changes.
///
/// Ported from Ghidra's `TraceSelectionPluginEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSelectionEvent {
    /// The trace ID.
    pub trace_id: String,
    /// The selected address ranges as (start, end) pairs.
    pub ranges: Vec<(u64, u64)>,
}

impl TraceSelectionEvent {
    /// Create a new event.
    pub fn new(trace_id: impl Into<String>, ranges: Vec<(u64, u64)>) -> Self {
        Self {
            trace_id: trace_id.into(),
            ranges,
        }
    }

    /// Whether the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The total number of selected addresses.
    pub fn selected_size(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s + 1).sum()
    }
}

/// Activation cause for trace manager events.
///
/// Ported from Ghidra's `DebuggerTraceManagerService.ActivationCause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActivationCause {
    /// User navigated to a trace.
    Navigate,
    /// A new trace was opened.
    Opened,
    /// A trace was selected programmatically.
    Programmatic,
    /// A trace was activated by a target event.
    TargetEvent,
}

/// A unified enum of all debugger plugin events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebuggerPluginEvent {
    /// A trace was activated.
    TraceActivated(TraceActivatedEvent),
    /// A trace was closed.
    TraceClosed(TraceClosedEvent),
    /// A trace was opened.
    TraceOpened(TraceOpenedEvent),
    /// The trace highlight changed.
    TraceHighlight(TraceHighlightEvent),
    /// The location in a trace changed.
    TraceLocation(TraceLocationEvent),
    /// The selection in a trace listing changed.
    TraceSelection(TraceSelectionEvent),
    /// Coordinates became inactive.
    TraceInactiveCoordinates(TraceInactiveCoordinatesEvent),
    /// The debugger platform changed.
    PlatformChanged(DebuggerPlatformEvent),
}

/// Transaction coalescer for batching trace writes.
///
/// Ported from Ghidra's `TransactionCoalescer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCoalescer {
    /// The trace ID.
    pub trace_id: String,
    /// The pending operations (description fragments).
    pub pending_operations: Vec<String>,
    /// Whether a transaction is currently open.
    pub open: bool,
    /// The coalescence interval in milliseconds.
    pub interval_ms: u64,
}

impl TransactionCoalescer {
    /// Create a new coalescer.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            pending_operations: Vec::new(),
            open: false,
            interval_ms: 100,
        }
    }

    /// Record an operation.
    pub fn record(&mut self, description: impl Into<String>) {
        self.pending_operations.push(description.into());
    }

    /// Start a transaction.
    pub fn begin(&mut self) {
        self.open = true;
    }

    /// End the transaction.
    pub fn end(&mut self) -> Vec<String> {
        self.open = false;
        std::mem::take(&mut self.pending_operations)
    }

    /// Whether a transaction is open.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// The number of pending operations.
    pub fn pending_count(&self) -> usize {
        self.pending_operations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_activated_event() {
        let event = TraceActivatedEvent::new("trace1");
        assert_eq!(event.trace_id, "trace1");
        assert!(event.coordinates.is_none());
    }

    #[test]
    fn test_trace_closed_event() {
        let event = TraceClosedEvent::new("trace1");
        assert_eq!(event.trace_id, "trace1");
    }

    #[test]
    fn test_trace_highlight_event() {
        let event = TraceHighlightEvent::new("trace1", Some(0x400000));
        assert_eq!(event.offset, Some(0x400000));
    }

    #[test]
    fn test_debugger_platform_event() {
        let event = DebuggerPlatformEvent::new("x86", "x86:LE:64:default", "default");
        assert_eq!(event.platform_name, "x86");
        assert_eq!(event.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_plugin_event_enum() {
        let event = DebuggerPluginEvent::TraceClosed(TraceClosedEvent::new("t1"));
        match event {
            DebuggerPluginEvent::TraceClosed(e) => assert_eq!(e.trace_id, "t1"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_trace_opened_event() {
        let event = TraceOpenedEvent::new("trace1");
        assert_eq!(event.trace_id, "trace1");
    }

    #[test]
    fn test_trace_location_event() {
        let event = TraceLocationEvent::new("trace1", 0x400000)
            .with_space("ram");
        assert_eq!(event.offset, 0x400000);
        assert_eq!(event.space.as_deref(), Some("ram"));
    }

    #[test]
    fn test_trace_selection_event() {
        let event = TraceSelectionEvent::new("trace1", vec![(0x1000, 0x1fff), (0x3000, 0x30ff)]);
        assert!(!event.is_empty());
        assert_eq!(event.selected_size(), 0x1000 + 0x100);

        let empty = TraceSelectionEvent::new("trace1", vec![]);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_activation_cause() {
        assert_ne!(ActivationCause::Navigate, ActivationCause::Opened);
        assert_ne!(ActivationCause::Programmatic, ActivationCause::TargetEvent);
    }

    #[test]
    fn test_trace_opened_serde() {
        let event = TraceOpenedEvent::new("t1");
        let json = serde_json::to_string(&event).unwrap();
        let back: TraceOpenedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_id, "t1");
    }

    #[test]
    fn test_trace_location_serde() {
        let event = TraceLocationEvent::new("t1", 0x400000);
        let json = serde_json::to_string(&event).unwrap();
        let back: TraceLocationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.offset, 0x400000);
    }

    #[test]
    fn test_trace_selection_serde() {
        let event = TraceSelectionEvent::new("t1", vec![(0, 10)]);
        let json = serde_json::to_string(&event).unwrap();
        let back: TraceSelectionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ranges, vec![(0, 10)]);
    }

    #[test]
    fn test_plugin_event_variants() {
        let events = vec![
            DebuggerPluginEvent::TraceOpened(TraceOpenedEvent::new("t1")),
            DebuggerPluginEvent::TraceLocation(TraceLocationEvent::new("t1", 0)),
            DebuggerPluginEvent::TraceSelection(TraceSelectionEvent::new("t1", vec![])),
        ];
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_transaction_coalescer() {
        let mut coalescer = TransactionCoalescer::new("trace1");
        assert!(!coalescer.is_open());

        coalescer.begin();
        assert!(coalescer.is_open());

        coalescer.record("write memory");
        coalescer.record("write register");
        assert_eq!(coalescer.pending_count(), 2);

        let ops = coalescer.end();
        assert_eq!(ops.len(), 2);
        assert!(!coalescer.is_open());
        assert_eq!(coalescer.pending_count(), 0);
    }

    #[test]
    fn test_event_serde() {
        let event = TraceActivatedEvent::new("trace1");
        let json = serde_json::to_string(&event).unwrap();
        let back: TraceActivatedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_id, "trace1");
    }
}
