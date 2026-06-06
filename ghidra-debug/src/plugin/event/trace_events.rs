//! Debugger plugin events ported from Ghidra's Debugger event package.
//!
//! Each event type represents a notification emitted by the debugger
//! framework when the trace state changes. These events are dispatched
//! through the plugin event system to interested listeners.

use crate::api::tracemgr::DebuggerCoordinates;

/// Cause for a trace becoming active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivationCause {
    /// User explicitly selected this trace.
    UserSelect,
    /// Trace was opened programmatically.
    Opened,
    /// Trace coordinates changed (e.g., snap or thread changed).
    CoordinatesChanged,
    /// Trace was activated due to external event.
    External,
}

/// Event emitted when a trace is activated (brought to focus).
///
/// Ported from Ghidra's `TraceActivatedPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceActivatedEvent {
    /// The source that produced this event.
    pub source: String,
    /// The active coordinates at the time of activation.
    pub coordinates: DebuggerCoordinates,
    /// What caused the activation.
    pub cause: ActivationCause,
}

impl TraceActivatedEvent {
    /// Create a new trace activated event.
    pub fn new(
        source: impl Into<String>,
        coordinates: DebuggerCoordinates,
        cause: ActivationCause,
    ) -> Self {
        Self {
            source: source.into(),
            coordinates,
            cause,
        }
    }

    /// Get the event name (for serialization/dispatch).
    pub fn event_name(&self) -> &'static str {
        "TraceActivated"
    }
}

/// Event emitted when a trace is closed.
///
/// Ported from Ghidra's `TraceClosedPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceClosedEvent {
    /// The source that produced this event.
    pub source: String,
    /// The key of the trace that was closed.
    pub trace_key: i64,
}

impl TraceClosedEvent {
    /// Create a new trace closed event.
    pub fn new(source: impl Into<String>, trace_key: i64) -> Self {
        Self {
            source: source.into(),
            trace_key,
        }
    }

    /// Get the event name.
    pub fn event_name(&self) -> &'static str {
        "TraceClosed"
    }
}

/// Event emitted when a new trace is opened.
///
/// Ported from Ghidra's `TraceOpenedPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceOpenedEvent {
    /// The source that produced this event.
    pub source: String,
    /// The key of the newly opened trace.
    pub trace_key: i64,
}

impl TraceOpenedEvent {
    /// Create a new trace opened event.
    pub fn new(source: impl Into<String>, trace_key: i64) -> Self {
        Self {
            source: source.into(),
            trace_key,
        }
    }

    /// Get the event name.
    pub fn event_name(&self) -> &'static str {
        "TraceOpened"
    }
}

/// Event emitted when the trace location (address) changes.
///
/// Ported from Ghidra's `TraceLocationPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceLocationEvent {
    /// The source that produced this event.
    pub source: String,
    /// The current coordinates.
    pub coordinates: DebuggerCoordinates,
}

impl TraceLocationEvent {
    /// Create a new trace location event.
    pub fn new(source: impl Into<String>, coordinates: DebuggerCoordinates) -> Self {
        Self {
            source: source.into(),
            coordinates,
        }
    }

    /// Get the event name.
    pub fn event_name(&self) -> &'static str {
        "TraceLocation"
    }
}

/// Event emitted when the trace selection (highlighted range) changes.
///
/// Ported from Ghidra's `TraceSelectionPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceSelectionEvent {
    /// The source that produced this event.
    pub source: String,
    /// The current coordinates.
    pub coordinates: DebuggerCoordinates,
    /// Optional start of selection range.
    pub selection_start: Option<u64>,
    /// Optional end of selection range.
    pub selection_end: Option<u64>,
}

impl TraceSelectionEvent {
    /// Create a new trace selection event.
    pub fn new(
        source: impl Into<String>,
        coordinates: DebuggerCoordinates,
    ) -> Self {
        Self {
            source: source.into(),
            coordinates,
            selection_start: None,
            selection_end: None,
        }
    }

    /// Create a new trace selection event with a range.
    pub fn with_range(
        source: impl Into<String>,
        coordinates: DebuggerCoordinates,
        start: u64,
        end: u64,
    ) -> Self {
        Self {
            source: source.into(),
            coordinates,
            selection_start: Some(start),
            selection_end: Some(end),
        }
    }

    /// Get the event name.
    pub fn event_name(&self) -> &'static str {
        "TraceSelection"
    }
}

/// Event emitted when a trace highlight changes.
///
/// Ported from Ghidra's `TraceHighlightPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceHighlightEvent {
    /// The source that produced this event.
    pub source: String,
    /// The current coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The highlight color as an ARGB integer.
    pub color: Option<u32>,
}

impl TraceHighlightEvent {
    /// Create a new trace highlight event.
    pub fn new(
        source: impl Into<String>,
        coordinates: DebuggerCoordinates,
        color: Option<u32>,
    ) -> Self {
        Self {
            source: source.into(),
            coordinates,
            color,
        }
    }

    /// Get the event name.
    pub fn event_name(&self) -> &'static str {
        "TraceHighlight"
    }
}

/// Event emitted when inactive coordinates change.
///
/// Ported from Ghidra's `TraceInactiveCoordinatesPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceInactiveCoordinatesEvent {
    /// The source that produced this event.
    pub source: String,
    /// The inactive coordinates.
    pub coordinates: DebuggerCoordinates,
}

impl TraceInactiveCoordinatesEvent {
    /// Create a new trace inactive coordinates event.
    pub fn new(source: impl Into<String>, coordinates: DebuggerCoordinates) -> Self {
        Self {
            source: source.into(),
            coordinates,
        }
    }

    /// Get the event name.
    pub fn event_name(&self) -> &'static str {
        "TraceInactiveCoordinates"
    }
}

/// Event emitted when the debugger platform changes.
///
/// Ported from Ghidra's `DebuggerPlatformPluginEvent`.
#[derive(Debug, Clone)]
pub struct DebuggerPlatformEvent {
    /// The source that produced this event.
    pub source: String,
    /// The trace key.
    pub trace_key: i64,
}

impl DebuggerPlatformEvent {
    /// Create a new debugger platform event.
    pub fn new(source: impl Into<String>, trace_key: i64) -> Self {
        Self {
            source: source.into(),
            trace_key,
        }
    }

    /// Get the event name.
    pub fn event_name(&self) -> &'static str {
        "DebuggerPlatform"
    }
}

/// Event emitted when tracking changes.
///
/// Ported from Ghidra's `TrackingChangedPluginEvent`.
#[derive(Debug, Clone)]
pub struct TrackingChangedEvent {
    /// The source that produced this event.
    pub source: String,
    /// Whether tracking is now enabled.
    pub tracking_enabled: bool,
}

impl TrackingChangedEvent {
    /// Create a new tracking changed event.
    pub fn new(source: impl Into<String>, tracking_enabled: bool) -> Self {
        Self {
            source: source.into(),
            tracking_enabled,
        }
    }

    /// Get the event name.
    pub fn event_name(&self) -> &'static str {
        "TrackingChanged"
    }
}

/// A union of all debugger plugin events.
#[derive(Debug, Clone)]
pub enum DebuggerPluginEvent {
    /// A trace was activated.
    TraceActivated(TraceActivatedEvent),
    /// A trace was closed.
    TraceClosed(TraceClosedEvent),
    /// A trace was opened.
    TraceOpened(TraceOpenedEvent),
    /// A trace location changed.
    TraceLocation(TraceLocationEvent),
    /// A trace selection changed.
    TraceSelection(TraceSelectionEvent),
    /// A trace highlight changed.
    TraceHighlight(TraceHighlightEvent),
    /// Inactive coordinates changed.
    TraceInactiveCoordinates(TraceInactiveCoordinatesEvent),
    /// Debugger platform changed.
    DebuggerPlatform(DebuggerPlatformEvent),
    /// Tracking state changed.
    TrackingChanged(TrackingChangedEvent),
}

impl DebuggerPluginEvent {
    /// Get the source of this event.
    pub fn source(&self) -> &str {
        match self {
            Self::TraceActivated(e) => &e.source,
            Self::TraceClosed(e) => &e.source,
            Self::TraceOpened(e) => &e.source,
            Self::TraceLocation(e) => &e.source,
            Self::TraceSelection(e) => &e.source,
            Self::TraceHighlight(e) => &e.source,
            Self::TraceInactiveCoordinates(e) => &e.source,
            Self::DebuggerPlatform(e) => &e.source,
            Self::TrackingChanged(e) => &e.source,
        }
    }

    /// Get the event name for dispatch/logging.
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::TraceActivated(e) => e.event_name(),
            Self::TraceClosed(e) => e.event_name(),
            Self::TraceOpened(e) => e.event_name(),
            Self::TraceLocation(e) => e.event_name(),
            Self::TraceSelection(e) => e.event_name(),
            Self::TraceHighlight(e) => e.event_name(),
            Self::TraceInactiveCoordinates(e) => e.event_name(),
            Self::DebuggerPlatform(e) => e.event_name(),
            Self::TrackingChanged(e) => e.event_name(),
        }
    }
}

/// Trait for receiving debugger plugin events.
pub trait DebuggerPluginEventListener: Send + Sync {
    /// Called when a plugin event is dispatched.
    fn on_event(&self, event: &DebuggerPluginEvent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tracemgr::DebuggerCoordinates;

    fn test_coordinates() -> DebuggerCoordinates {
        DebuggerCoordinates::default()
    }

    #[test]
    fn test_trace_activated_event() {
        let coords = test_coordinates();
        let event = TraceActivatedEvent::new("test", coords, ActivationCause::UserSelect);
        assert_eq!(event.event_name(), "TraceActivated");
        assert_eq!(event.source, "test");
        assert_eq!(event.cause, ActivationCause::UserSelect);
    }

    #[test]
    fn test_trace_closed_event() {
        let event = TraceClosedEvent::new("test", 42);
        assert_eq!(event.event_name(), "TraceClosed");
        assert_eq!(event.trace_key, 42);
    }

    #[test]
    fn test_trace_opened_event() {
        let event = TraceOpenedEvent::new("test", 1);
        assert_eq!(event.event_name(), "TraceOpened");
        assert_eq!(event.trace_key, 1);
    }

    #[test]
    fn test_trace_location_event() {
        let coords = test_coordinates();
        let event = TraceLocationEvent::new("test", coords);
        assert_eq!(event.event_name(), "TraceLocation");
    }

    #[test]
    fn test_trace_selection_event_no_range() {
        let coords = test_coordinates();
        let event = TraceSelectionEvent::new("test", coords);
        assert_eq!(event.event_name(), "TraceSelection");
        assert!(event.selection_start.is_none());
        assert!(event.selection_end.is_none());
    }

    #[test]
    fn test_trace_selection_event_with_range() {
        let coords = test_coordinates();
        let event = TraceSelectionEvent::with_range("test", coords, 0x1000, 0x2000);
        assert_eq!(event.selection_start, Some(0x1000));
        assert_eq!(event.selection_end, Some(0x2000));
    }

    #[test]
    fn test_trace_highlight_event() {
        let coords = test_coordinates();
        let event = TraceHighlightEvent::new("test", coords, Some(0xFF00FF00));
        assert_eq!(event.event_name(), "TraceHighlight");
        assert_eq!(event.color, Some(0xFF00FF00));
    }

    #[test]
    fn test_trace_inactive_coordinates_event() {
        let coords = test_coordinates();
        let event = TraceInactiveCoordinatesEvent::new("test", coords);
        assert_eq!(event.event_name(), "TraceInactiveCoordinates");
    }

    #[test]
    fn test_debugger_platform_event() {
        let event = DebuggerPlatformEvent::new("test", 7);
        assert_eq!(event.event_name(), "DebuggerPlatform");
        assert_eq!(event.trace_key, 7);
    }

    #[test]
    fn test_tracking_changed_event() {
        let event = TrackingChangedEvent::new("test", true);
        assert_eq!(event.event_name(), "TrackingChanged");
        assert!(event.tracking_enabled);
    }

    #[test]
    fn test_debugger_plugin_event_union() {
        let coords = test_coordinates();
        let event = DebuggerPluginEvent::TraceOpened(TraceOpenedEvent::new("src", 1));
        assert_eq!(event.source(), "src");
        assert_eq!(event.event_name(), "TraceOpened");

        let event = DebuggerPluginEvent::TraceActivated(TraceActivatedEvent::new(
            "src2",
            coords,
            ActivationCause::Opened,
        ));
        assert_eq!(event.source(), "src2");
        assert_eq!(event.event_name(), "TraceActivated");
    }

    #[test]
    fn test_activation_cause_variants() {
        assert_ne!(ActivationCause::UserSelect, ActivationCause::Opened);
        assert_ne!(ActivationCause::CoordinatesChanged, ActivationCause::External);
    }
}
