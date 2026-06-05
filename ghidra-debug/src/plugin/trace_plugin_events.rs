//! Trace plugin events for the debugger framework.
//!
//! Ported from Ghidra's debugger plugin event types:
//! `TraceLocationPluginEvent`, `TraceOpenedPluginEvent`, `TraceClosedPluginEvent`,
//! `TraceActivatedPluginEvent`, `TraceInactiveCoordinatesPluginEvent`,
//! `DebuggerPlatformPluginEvent`.

use serde::{Deserialize, Serialize};

/// Plugin event types specific to the debugger.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TracePluginEventKind {
    /// A trace was opened.
    TraceOpened,
    /// A trace was closed.
    TraceClosed,
    /// A trace was activated (focused in the UI).
    TraceActivated,
    /// A trace was deactivated.
    TraceDeactivated,
    /// The current location in the trace changed.
    TraceLocationChanged,
    /// The coordinates became inactive (e.g., navigation target lost).
    TraceInactiveCoordinates,
    /// The debugger platform changed.
    DebuggerPlatformChanged,
    /// A breakpoint was hit.
    BreakpointHit,
    /// Execution stopped.
    ExecutionStopped,
    /// Execution resumed.
    ExecutionResumed,
}

/// A location within a trace (thread + snap + address).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceLocation {
    /// The trace ID.
    pub trace_id: String,
    /// The thread key (if applicable).
    pub thread_key: Option<i64>,
    /// The snapshot.
    pub snap: i64,
    /// The address offset.
    pub address: Option<u64>,
    /// The address space name.
    pub space: Option<String>,
}

impl TraceLocation {
    /// Create a new trace location.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            thread_key: None,
            snap,
            address: None,
            space: None,
        }
    }

    /// Set the thread.
    pub fn with_thread(mut self, key: i64) -> Self {
        self.thread_key = Some(key);
        self
    }

    /// Set the address.
    pub fn with_address(mut self, space: impl Into<String>, addr: u64) -> Self {
        self.space = Some(space.into());
        self.address = Some(addr);
        self
    }
}

/// Coordinates for a trace position including time and space.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceCoordinates {
    /// The trace location.
    pub location: TraceLocation,
    /// Whether these coordinates are valid.
    pub valid: bool,
    /// The view type (e.g., "listing", "memory").
    pub view_type: Option<String>,
}

impl TraceCoordinates {
    /// Create new coordinates from a location.
    pub fn new(location: TraceLocation) -> Self {
        Self {
            location,
            valid: true,
            view_type: None,
        }
    }

    /// Mark as invalid.
    pub fn with_invalid(mut self) -> Self {
        self.valid = false;
        self
    }
}

/// A platform offer for a debugger target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerPlatformOffer {
    /// The language ID.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// The platform name.
    pub name: String,
    /// Confidence level (0.0 to 1.0).
    pub confidence: f64,
    /// Whether this is a manual selection.
    pub is_manual: bool,
}

impl DebuggerPlatformOffer {
    /// Create a new platform offer.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        name: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            name: name.into(),
            confidence,
            is_manual: false,
        }
    }
}

/// A plugin event carrying a trace location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePluginEvent {
    /// The kind of event.
    pub kind: TracePluginEventKind,
    /// The source (plugin name or ID).
    pub source: String,
    /// The trace location (if applicable).
    pub location: Option<TraceLocation>,
    /// Timestamp when the event occurred.
    pub timestamp: u64,
}

impl TracePluginEvent {
    /// Create a new plugin event.
    pub fn new(kind: TracePluginEventKind, source: impl Into<String>) -> Self {
        Self {
            kind,
            source: source.into(),
            location: None,
            timestamp: 0,
        }
    }

    /// Set the trace location.
    pub fn with_location(mut self, loc: TraceLocation) -> Self {
        self.location = Some(loc);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_location() {
        let loc = TraceLocation::new("trace1", 5)
            .with_thread(1)
            .with_address("ram", 0x400000);
        assert_eq!(loc.trace_id, "trace1");
        assert_eq!(loc.thread_key, Some(1));
        assert_eq!(loc.address, Some(0x400000));
    }

    #[test]
    fn test_trace_plugin_event() {
        let event = TracePluginEvent::new(
            TracePluginEventKind::TraceOpened,
            "TraceManagerPlugin",
        )
        .with_location(TraceLocation::new("trace1", 0));
        assert_eq!(event.kind, TracePluginEventKind::TraceOpened);
        assert!(event.location.is_some());
    }

    #[test]
    fn test_platform_offer() {
        let offer = DebuggerPlatformOffer::new("x86:LE:64:default", "default", "x86-64", 0.9);
        assert_eq!(offer.language_id, "x86:LE:64:default");
        assert_eq!(offer.confidence, 0.9);
    }
}
