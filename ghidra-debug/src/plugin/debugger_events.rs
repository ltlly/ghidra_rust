//! Debugger plugin event types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.event` package:
//! - `TraceActivatedPluginEvent`
//! - `TraceClosedPluginEvent`
//! - `TraceOpenedPluginEvent`
//! - `TraceHighlightPluginEvent`
//! - `TraceLocationPluginEvent`
//! - `TraceSelectionPluginEvent`
//! - `TraceInactiveCoordinatesPluginEvent`
//! - `TrackingChangedPluginEvent`
//! - `DebuggerPlatformPluginEvent`
//!
//! Plugin events are used for inter-component communication within the
//! Ghidra plugin framework. These events carry trace-related state
//! changes to interested listeners.


use crate::api::tracemgr::DebuggerCoordinates;

/// A plugin event indicating a trace was activated.
///
/// Ported from Ghidra's `TraceActivatedPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceActivatedEvent {
    /// The coordinates of the activated trace.
    pub coordinates: DebuggerCoordinates,
    /// The source component that caused the activation.
    pub source: String,
}

impl TraceActivatedEvent {
    /// Create a new trace activated event.
    pub fn new(coordinates: DebuggerCoordinates, source: impl Into<String>) -> Self {
        Self {
            coordinates,
            source: source.into(),
        }
    }

    /// Get the trace key from the coordinates.
    pub fn trace_key(&self) -> Option<i64> {
        self.coordinates.trace_key
    }
}

/// A plugin event indicating a trace was opened.
///
/// Ported from Ghidra's `TraceOpenedPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceOpenedEvent {
    /// The trace key.
    pub trace_key: i64,
    /// The source component.
    pub source: String,
}

impl TraceOpenedEvent {
    /// Create a new trace opened event.
    pub fn new(trace_key: i64, source: impl Into<String>) -> Self {
        Self {
            trace_key,
            source: source.into(),
        }
    }
}

/// A plugin event indicating a trace was closed.
///
/// Ported from Ghidra's `TraceClosedPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceClosedEvent {
    /// The trace key.
    pub trace_key: i64,
    /// The source component.
    pub source: String,
}

impl TraceClosedEvent {
    /// Create a new trace closed event.
    pub fn new(trace_key: i64, source: impl Into<String>) -> Self {
        Self {
            trace_key,
            source: source.into(),
        }
    }
}

/// A plugin event indicating a trace location changed.
///
/// Ported from Ghidra's `TraceLocationPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceLocationEvent {
    /// The coordinates of the location.
    pub coordinates: DebuggerCoordinates,
    /// The source component.
    pub source: String,
}

impl TraceLocationEvent {
    /// Create a new trace location event.
    pub fn new(coordinates: DebuggerCoordinates, source: impl Into<String>) -> Self {
        Self {
            coordinates,
            source: source.into(),
        }
    }

    /// Get the address from the coordinates.
    pub fn address(&self) -> Option<u64> {
        self.coordinates.snap.map(|s| s as u64)
    }
}

/// A plugin event indicating a trace selection changed.
///
/// Ported from Ghidra's `TraceSelectionPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceSelectionEvent {
    /// The coordinates of the selection start.
    pub start: DebuggerCoordinates,
    /// The coordinates of the selection end.
    pub end: DebuggerCoordinates,
    /// The source component.
    pub source: String,
}

impl TraceSelectionEvent {
    /// Create a new selection event.
    pub fn new(
        start: DebuggerCoordinates,
        end: DebuggerCoordinates,
        source: impl Into<String>,
    ) -> Self {
        Self {
            start,
            end,
            source: source.into(),
        }
    }

    /// Whether the selection is a single point (start == end).
    pub fn is_point(&self) -> bool {
        self.start.trace_key == self.end.trace_key
            && self.start.snap == self.end.snap
            && self.start.thread_key == self.end.thread_key
    }
}

/// A plugin event indicating a trace highlight changed.
///
/// Ported from Ghidra's `TraceHighlightPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceHighlightEvent {
    /// The highlighted address range (start, end).
    pub range: Option<(u64, u64)>,
    /// The source component.
    pub source: String,
}

impl TraceHighlightEvent {
    /// Create a new highlight event with a range.
    pub fn with_range(start: u64, end: u64, source: impl Into<String>) -> Self {
        Self {
            range: Some((start, end)),
            source: source.into(),
        }
    }

    /// Create a highlight clear event.
    pub fn clear(source: impl Into<String>) -> Self {
        Self {
            range: None,
            source: source.into(),
        }
    }

    /// Whether the highlight was cleared.
    pub fn is_cleared(&self) -> bool {
        self.range.is_none()
    }
}

/// A plugin event for inactive trace coordinates.
///
/// Ported from Ghidra's `TraceInactiveCoordinatesPluginEvent`.
#[derive(Debug, Clone)]
pub struct TraceInactiveCoordinatesEvent {
    /// The coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The source component.
    pub source: String,
}

impl TraceInactiveCoordinatesEvent {
    /// Create a new inactive coordinates event.
    pub fn new(coordinates: DebuggerCoordinates, source: impl Into<String>) -> Self {
        Self {
            coordinates,
            source: source.into(),
        }
    }
}

/// A plugin event indicating tracking mode changed.
///
/// Ported from Ghidra's `TrackingChangedPluginEvent`.
#[derive(Debug, Clone)]
pub struct TrackingChangedEvent {
    /// Whether tracking is now enabled.
    pub tracking_enabled: bool,
    /// The tracking spec name.
    pub tracking_spec: Option<String>,
    /// The source component.
    pub source: String,
}

impl TrackingChangedEvent {
    /// Create a new tracking changed event.
    pub fn new(tracking_enabled: bool, source: impl Into<String>) -> Self {
        Self {
            tracking_enabled,
            tracking_spec: None,
            source: source.into(),
        }
    }

    /// Set the tracking spec name.
    pub fn with_spec(mut self, spec: impl Into<String>) -> Self {
        self.tracking_spec = Some(spec.into());
        self
    }
}

/// A plugin event indicating the debugger platform changed.
///
/// Ported from Ghidra's `DebuggerPlatformPluginEvent`.
#[derive(Debug, Clone)]
pub struct DebuggerPlatformEvent {
    /// The new language ID.
    pub language_id: Option<String>,
    /// The new compiler spec ID.
    pub compiler_spec_id: Option<String>,
    /// The source component.
    pub source: String,
}

impl DebuggerPlatformEvent {
    /// Create a new platform event.
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            language_id: None,
            compiler_spec_id: None,
            source: source.into(),
        }
    }

    /// Set the language ID.
    pub fn with_language(mut self, language_id: impl Into<String>) -> Self {
        self.language_id = Some(language_id.into());
        self
    }

    /// Set the compiler spec ID.
    pub fn with_compiler_spec(mut self, compiler_spec_id: impl Into<String>) -> Self {
        self.compiler_spec_id = Some(compiler_spec_id.into());
        self
    }
}

/// Union type for all debugger plugin events.
#[derive(Debug, Clone)]
pub enum DebuggerPluginEvent {
    /// A trace was activated.
    Activated(TraceActivatedEvent),
    /// A trace was opened.
    Opened(TraceOpenedEvent),
    /// A trace was closed.
    Closed(TraceClosedEvent),
    /// A trace location changed.
    Location(TraceLocationEvent),
    /// A trace selection changed.
    Selection(TraceSelectionEvent),
    /// A trace highlight changed.
    Highlight(TraceHighlightEvent),
    /// Inactive coordinates changed.
    InactiveCoordinates(TraceInactiveCoordinatesEvent),
    /// Tracking mode changed.
    TrackingChanged(TrackingChangedEvent),
    /// Platform changed.
    Platform(DebuggerPlatformEvent),
}

impl DebuggerPluginEvent {
    /// Get the source component name.
    pub fn source(&self) -> &str {
        match self {
            DebuggerPluginEvent::Activated(e) => &e.source,
            DebuggerPluginEvent::Opened(e) => &e.source,
            DebuggerPluginEvent::Closed(e) => &e.source,
            DebuggerPluginEvent::Location(e) => &e.source,
            DebuggerPluginEvent::Selection(e) => &e.source,
            DebuggerPluginEvent::Highlight(e) => &e.source,
            DebuggerPluginEvent::InactiveCoordinates(e) => &e.source,
            DebuggerPluginEvent::TrackingChanged(e) => &e.source,
            DebuggerPluginEvent::Platform(e) => &e.source,
        }
    }

    /// Whether this event is a trace lifecycle event (open/close/activate).
    pub fn is_lifecycle(&self) -> bool {
        matches!(
            self,
            DebuggerPluginEvent::Opened(_)
                | DebuggerPluginEvent::Closed(_)
                | DebuggerPluginEvent::Activated(_)
        )
    }

    /// Whether this event is a coordinate change event.
    pub fn is_coordinate_change(&self) -> bool {
        matches!(
            self,
            DebuggerPluginEvent::Location(_)
                | DebuggerPluginEvent::Selection(_)
                | DebuggerPluginEvent::InactiveCoordinates(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_activated_event() {
        let coords = DebuggerCoordinates::default();
        let event = TraceActivatedEvent::new(coords, "test");
        assert_eq!(event.source, "test");
    }

    #[test]
    fn test_trace_opened_closed() {
        let opened = TraceOpenedEvent::new(1, "opener");
        assert_eq!(opened.trace_key, 1);

        let closed = TraceClosedEvent::new(1, "closer");
        assert_eq!(closed.trace_key, 1);
    }

    #[test]
    fn test_trace_location_event() {
        let coords = DebuggerCoordinates::default();
        let event = TraceLocationEvent::new(coords, "listing");
        assert_eq!(event.source, "listing");
    }

    #[test]
    fn test_trace_selection_event() {
        let start = DebuggerCoordinates::default();
        let end = DebuggerCoordinates::default();
        let event = TraceSelectionEvent::new(start, end, "listing");
        assert!(event.is_point());
    }

    #[test]
    fn test_trace_highlight_event() {
        let event = TraceHighlightEvent::with_range(0x401000, 0x401100, "test");
        assert!(!event.is_cleared());
        assert_eq!(event.range, Some((0x401000, 0x401100)));

        let cleared = TraceHighlightEvent::clear("test");
        assert!(cleared.is_cleared());
    }

    #[test]
    fn test_tracking_changed_event() {
        let event = TrackingChangedEvent::new(true, "test").with_spec("PCLocation");
        assert!(event.tracking_enabled);
        assert_eq!(event.tracking_spec, Some("PCLocation".into()));
    }

    #[test]
    fn test_debugger_platform_event() {
        let event = DebuggerPlatformEvent::new("test")
            .with_language("x86:LE:64:default")
            .with_compiler_spec("default");
        assert_eq!(event.language_id, Some("x86:LE:64:default".into()));
        assert_eq!(event.compiler_spec_id, Some("default".into()));
    }

    #[test]
    fn test_plugin_event_union() {
        let event = DebuggerPluginEvent::Opened(TraceOpenedEvent::new(1, "test"));
        assert!(event.is_lifecycle());
        assert!(!event.is_coordinate_change());
        assert_eq!(event.source(), "test");

        let event = DebuggerPluginEvent::Location(TraceLocationEvent::new(
            DebuggerCoordinates::default(),
            "test",
        ));
        assert!(!event.is_lifecycle());
        assert!(event.is_coordinate_change());
    }

    #[test]
    fn test_inactive_coordinates_event() {
        let coords = DebuggerCoordinates::default();
        let event = TraceInactiveCoordinatesEvent::new(coords, "test");
        assert_eq!(event.source, "test");
    }
}
