//! Additional plugin event types for the debugger.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.event` package.
//! These events are fired by debugger plugins to notify listeners of
//! trace lifecycle changes: activation, opening, closing, highlighting,
//! platform changes, and coordinate changes.

use serde::{Deserialize, Serialize};

use crate::api::DebuggerCoordinates;

/// The cause of a trace activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActivationCause {
    /// The user explicitly selected this trace.
    UserAction,
    /// A trace was activated programmatically.
    Programmatic,
    /// Activation occurred because another trace was closed.
    Cascade,
}

impl Default for ActivationCause {
    fn default() -> Self {
        Self::UserAction
    }
}

/// Event fired when a trace is activated (brought to focus).
#[derive(Debug, Clone)]
pub struct TraceActivatedPluginEvent {
    /// The source plugin name.
    pub source: String,
    /// The coordinates of the activated trace.
    pub coordinates: DebuggerCoordinates,
    /// Why this trace was activated.
    pub cause: ActivationCause,
}

impl TraceActivatedPluginEvent {
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

    /// Get the active coordinates.
    pub fn active_coordinates(&self) -> &DebuggerCoordinates {
        &self.coordinates
    }
}

/// Event fired when a trace is opened.
#[derive(Debug, Clone)]
pub struct TraceOpenedPluginEvent {
    /// The source plugin name.
    pub source: String,
    /// The trace key.
    pub trace_key: i64,
    /// The trace name.
    pub trace_name: String,
}

impl TraceOpenedPluginEvent {
    /// Create a new trace opened event.
    pub fn new(source: impl Into<String>, trace_key: i64, trace_name: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            trace_key,
            trace_name: trace_name.into(),
        }
    }
}

/// Event fired when a trace is closed.
#[derive(Debug, Clone)]
pub struct TraceClosedPluginEvent {
    /// The source plugin name.
    pub source: String,
    /// The trace key.
    pub trace_key: i64,
}

impl TraceClosedPluginEvent {
    /// Create a new trace closed event.
    pub fn new(source: impl Into<String>, trace_key: i64) -> Self {
        Self {
            source: source.into(),
            trace_key,
        }
    }
}

/// Event fired when the trace selection changes.
#[derive(Debug, Clone)]
pub struct TraceSelectionPluginEvent {
    /// The source plugin name.
    pub source: String,
    /// The newly selected coordinates.
    pub coordinates: DebuggerCoordinates,
}

impl TraceSelectionPluginEvent {
    /// Create a new selection event.
    pub fn new(source: impl Into<String>, coordinates: DebuggerCoordinates) -> Self {
        Self {
            source: source.into(),
            coordinates,
        }
    }
}

/// Event fired when the trace location (cursor) changes.
#[derive(Debug, Clone)]
pub struct TraceLocationPluginEvent {
    /// The source plugin name.
    pub source: String,
    /// The new coordinates.
    pub coordinates: DebuggerCoordinates,
}

impl TraceLocationPluginEvent {
    /// Create a new location event.
    pub fn new(source: impl Into<String>, coordinates: DebuggerCoordinates) -> Self {
        Self {
            source: source.into(),
            coordinates,
        }
    }
}

/// Event fired when the trace highlight changes.
#[derive(Debug, Clone)]
pub struct TraceHighlightPluginEvent {
    /// The source plugin name.
    pub source: String,
    /// The highlighted coordinates.
    pub coordinates: DebuggerCoordinates,
}

impl TraceHighlightPluginEvent {
    /// Create a new highlight event.
    pub fn new(source: impl Into<String>, coordinates: DebuggerCoordinates) -> Self {
        Self {
            source: source.into(),
            coordinates,
        }
    }
}

/// Event fired when inactive coordinates change (e.g., non-active trace).
#[derive(Debug, Clone)]
pub struct TraceInactiveCoordinatesPluginEvent {
    /// The source plugin name.
    pub source: String,
    /// The inactive coordinates.
    pub coordinates: DebuggerCoordinates,
}

impl TraceInactiveCoordinatesPluginEvent {
    /// Create a new inactive coordinates event.
    pub fn new(source: impl Into<String>, coordinates: DebuggerCoordinates) -> Self {
        Self {
            source: source.into(),
            coordinates,
        }
    }
}

/// Event fired when the debugger platform changes.
#[derive(Debug, Clone)]
pub struct DebuggerPlatformPluginEvent {
    /// The source plugin name.
    pub source: String,
    /// The new platform name.
    pub platform_name: String,
    /// The language ID.
    pub language_id: String,
}

impl DebuggerPlatformPluginEvent {
    /// Create a new platform event.
    pub fn new(
        source: impl Into<String>,
        platform_name: impl Into<String>,
        language_id: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            platform_name: platform_name.into(),
            language_id: language_id.into(),
        }
    }
}

/// Event fired when tracking changes (e.g., position tracking toggle).
#[derive(Debug, Clone)]
pub struct TrackingChangedPluginEvent {
    /// The source plugin name.
    pub source: String,
    /// Whether tracking is now enabled.
    pub tracking_enabled: bool,
}

impl TrackingChangedPluginEvent {
    /// Create a new tracking changed event.
    pub fn new(source: impl Into<String>, tracking_enabled: bool) -> Self {
        Self {
            source: source.into(),
            tracking_enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_activated_event() {
        let coords = DebuggerCoordinates::trace(1).with_snap(0);
        let event = TraceActivatedPluginEvent::new("test", coords, ActivationCause::UserAction);
        assert_eq!(event.source, "test");
        assert_eq!(event.cause, ActivationCause::UserAction);
        assert_eq!(event.active_coordinates().trace_key, Some(1));
    }

    #[test]
    fn test_trace_opened_event() {
        let event = TraceOpenedPluginEvent::new("plugin", 42, "my_trace");
        assert_eq!(event.trace_key, 42);
        assert_eq!(event.trace_name, "my_trace");
    }

    #[test]
    fn test_trace_closed_event() {
        let event = TraceClosedPluginEvent::new("plugin", 42);
        assert_eq!(event.trace_key, 42);
    }

    #[test]
    fn test_trace_selection_event() {
        let coords = DebuggerCoordinates::trace(1).with_snap(5);
        let event = TraceSelectionPluginEvent::new("test", coords);
        assert_eq!(event.coordinates.snap, Some(5));
    }

    #[test]
    fn test_trace_location_event() {
        let coords = DebuggerCoordinates::trace(1);
        let event = TraceLocationPluginEvent::new("test", coords);
        assert_eq!(event.coordinates.trace_key, Some(1));
    }

    #[test]
    fn test_trace_highlight_event() {
        let coords = DebuggerCoordinates::trace(1);
        let event = TraceHighlightPluginEvent::new("test", coords);
        assert_eq!(event.source, "test");
    }

    #[test]
    fn test_trace_inactive_coordinates_event() {
        let coords = DebuggerCoordinates::trace(2);
        let event = TraceInactiveCoordinatesPluginEvent::new("test", coords);
        assert_eq!(event.coordinates.trace_key, Some(2));
    }

    #[test]
    fn test_platform_event() {
        let event = DebuggerPlatformPluginEvent::new("test", "x86_64", "x86:LE:64:default");
        assert_eq!(event.platform_name, "x86_64");
        assert_eq!(event.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_tracking_changed_event() {
        let event = TrackingChangedPluginEvent::new("test", true);
        assert!(event.tracking_enabled);
    }

    #[test]
    fn test_activation_cause_default() {
        assert_eq!(ActivationCause::default(), ActivationCause::UserAction);
    }
}
