//! Breakpoint GUI provider data model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.breakpoint` package.
//! Provides data model types for the breakpoint panel, including logical
//! breakpoint rows, location rows, state management, and breakpoint marker
//! support.

use serde::{Deserialize, Serialize};

use crate::api::breakpoint::{BreakpointMode, BreakpointState, LogicalBreakpoint};
use crate::model::breakpoint::TraceBreakpointKind;

// ---------------------------------------------------------------------------
// Breakpoint state cell rendering / editing
// ---------------------------------------------------------------------------

/// State representation for display in the breakpoint table.
///
/// Ported from Ghidra's `DebuggerBreakpointStateTableCellRenderer`/`Editor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointDisplayState {
    /// Breakpoint is fully enabled (logical + all locations).
    Enabled,
    /// Breakpoint is partially enabled (some locations enabled).
    PartiallyEnabled,
    /// Breakpoint is disabled.
    Disabled,
    /// Breakpoint has no locations mapped.
    Unmapped,
}

impl BreakpointDisplayState {
    /// Compute from a logical breakpoint.
    pub fn from_logical(bp: &LogicalBreakpoint) -> Self {
        match bp.state.mode {
            Some(BreakpointMode::Enabled) => BreakpointDisplayState::Enabled,
            Some(BreakpointMode::Disabled) => BreakpointDisplayState::Disabled,
            None => BreakpointDisplayState::Unmapped,
        }
    }

    /// Get the toggled state (for click-to-toggle).
    pub fn toggled(&self, mapped: bool) -> Self {
        match self {
            BreakpointDisplayState::Enabled => BreakpointDisplayState::Disabled,
            BreakpointDisplayState::Disabled => {
                if mapped {
                    BreakpointDisplayState::Enabled
                } else {
                    BreakpointDisplayState::Disabled
                }
            }
            BreakpointDisplayState::PartiallyEnabled => BreakpointDisplayState::Disabled,
            BreakpointDisplayState::Unmapped => BreakpointDisplayState::Unmapped,
        }
    }
}

// ---------------------------------------------------------------------------
// Logical breakpoint row
// ---------------------------------------------------------------------------

/// A row in the logical breakpoints table.
///
/// Ported from Ghidra's `LogicalBreakpointRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalBreakpointRow {
    /// The display state (enabled/disabled/partially/unmapped).
    pub state: BreakpointDisplayState,
    /// The breakpoint expression (e.g., hex address or Sleigh expression).
    pub expression: String,
    /// Whether the breakpoint is mapped to any locations.
    pub is_mapped: bool,
    /// Number of trace breakpoint locations.
    pub location_count: usize,
    /// The program URL (if statically mapped).
    pub program_url: Option<String>,
    /// The offset within the program (if statically mapped).
    pub program_offset: Option<u64>,
    /// The breakpoint kinds.
    pub kinds: BreakpointKindSet,
    /// The logical breakpoint reference.
    pub logical: LogicalBreakpoint,
}

impl LogicalBreakpointRow {
    /// Create from a `LogicalBreakpoint`.
    pub fn from_logical(bp: LogicalBreakpoint) -> Self {
        let state = BreakpointDisplayState::from_logical(&bp);
        let expression = bp.expression.clone();
        let kinds = BreakpointKindSet::from_string_vec(bp.kinds.clone());
        Self {
            state,
            expression,
            is_mapped: false,
            location_count: 0,
            program_url: None,
            program_offset: None,
            kinds,
            logical: bp,
        }
    }

    /// Get the breakpoint state.
    pub fn get_state(&self) -> BreakpointDisplayState {
        self.state
    }

    /// Set the breakpoint state.
    pub fn set_state(&mut self, state: BreakpointDisplayState) {
        self.state = state;
    }

    /// Whether the breakpoint is mapped.
    pub fn is_mapped(&self) -> bool {
        self.is_mapped
    }
}

// ---------------------------------------------------------------------------
// Breakpoint kind set
// ---------------------------------------------------------------------------

/// A set of breakpoint kinds for a logical breakpoint.
///
/// Ported from Ghidra's `TraceBreakpointKind` usage in breakpoint rows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BreakpointKindSet {
    /// The kinds of breakpoints.
    pub kinds: Vec<TraceBreakpointKind>,
}

impl BreakpointKindSet {
    /// Create an empty set.
    pub fn new() -> Self {
        Self { kinds: Vec::new() }
    }

    /// Create from a single kind.
    pub fn with_kind(kind: TraceBreakpointKind) -> Self {
        Self {
            kinds: vec![kind],
        }
    }

    /// Create from a string vector of kinds.
    pub fn from_string_vec(strings: Vec<String>) -> Self {
        let kinds = strings
            .iter()
            .filter_map(|s| match s.as_str() {
                "Read" => Some(TraceBreakpointKind::Read),
                "Write" => Some(TraceBreakpointKind::Write),
                "HwExecute" => Some(TraceBreakpointKind::HwExecute),
                "SwExecute" => Some(TraceBreakpointKind::SwExecute),
                _ => None,
            })
            .collect();
        Self { kinds }
    }

    /// Check if the set contains a kind.
    pub fn contains(&self, kind: &TraceBreakpointKind) -> bool {
        self.kinds.contains(kind)
    }

    /// Add a kind.
    pub fn insert(&mut self, kind: TraceBreakpointKind) {
        if !self.kinds.contains(&kind) {
            self.kinds.push(kind);
        }
    }

    /// The display label (comma-separated).
    pub fn display_label(&self) -> String {
        self.kinds
            .iter()
            .map(|k| format!("{:?}", k))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// ---------------------------------------------------------------------------
// Breakpoint location row
// ---------------------------------------------------------------------------

/// A row in the breakpoint locations table.
///
/// Ported from Ghidra's `BreakpointLocationRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointLocationRow {
    /// The display state.
    pub state: BreakpointDisplayState,
    /// The trace object key.
    pub object_key: Option<i64>,
    /// The trace ID.
    pub trace_id: Option<String>,
    /// The trace address offset.
    pub offset: u64,
    /// The length of the breakpoint region.
    pub length: u64,
    /// The breakpoint kinds for this specific location.
    pub kinds: BreakpointKindSet,
    /// Thread key (if thread-specific).
    pub thread_key: Option<i64>,
    /// The expression (Sleigh).
    pub expression: Option<String>,
}

impl BreakpointLocationRow {
    /// Get the display state.
    pub fn get_state(&self) -> BreakpointDisplayState {
        self.state
    }

    /// Set the display state.
    pub fn set_state(&mut self, state: BreakpointDisplayState) {
        self.state = state;
    }

    /// Get the toggled state.
    pub fn get_toggled_state(&self) -> BreakpointDisplayState {
        self.state.toggled(false)
    }
}

// ---------------------------------------------------------------------------
// Debugger breakpoint marker data
// ---------------------------------------------------------------------------

/// Marker data for a breakpoint in the listing margin.
///
/// Ported from Ghidra's `DebuggerBreakpointMarkerPlugin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointMarkerData {
    /// The breakpoint offset.
    pub offset: u64,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// The kinds.
    pub kinds: BreakpointKindSet,
    /// The tooltip text.
    pub tooltip: String,
}

// ---------------------------------------------------------------------------
// Breakpoint action context
// ---------------------------------------------------------------------------

/// Action context for breakpoint-specific operations.
///
/// Ported from Ghidra's `DebuggerBreakpointLocationsActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointActionContext {
    /// The selected breakpoint location rows.
    pub locations: Vec<BreakpointLocationRow>,
    /// The trace ID.
    pub trace_id: Option<String>,
}

/// Action context for logical breakpoint operations.
///
/// Ported from Ghidra's `DebuggerLogicalBreakpointsActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalBreakpointActionContext {
    /// The selected logical breakpoint rows.
    pub rows: Vec<LogicalBreakpointRow>,
}

/// Action context for making breakpoints effective.
///
/// Ported from Ghidra's `DebuggerMakeBreakpointsEffectiveActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeBreakpointsEffectiveContext {
    /// The rows to make effective.
    pub rows: Vec<LogicalBreakpointRow>,
}

// ---------------------------------------------------------------------------
// Sleigh input dialog data
// ---------------------------------------------------------------------------

/// Data model for the Sleigh expression/semantic input dialog.
///
/// Ported from Ghidra's `DebuggerSleighExpressionInputDialog` and
/// `DebuggerSleighSemanticInputDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleighBreakpointInput {
    /// The expression text.
    pub expression: String,
    /// The breakpoint kinds.
    pub kinds: BreakpointKindSet,
    /// Whether this is a semantic (Sleigh) breakpoint.
    pub is_semantic: bool,
    /// The length (if applicable).
    pub length: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_display_state() {
        let mut bp = LogicalBreakpoint::new(0x400000, "0x400000");
        bp.state.mode = Some(BreakpointMode::Enabled);
        let state = BreakpointDisplayState::from_logical(&bp);
        assert_eq!(state, BreakpointDisplayState::Enabled);

        bp.state.mode = Some(BreakpointMode::Disabled);
        let state = BreakpointDisplayState::from_logical(&bp);
        assert_eq!(state, BreakpointDisplayState::Disabled);

        bp.state.mode = None;
        let state = BreakpointDisplayState::from_logical(&bp);
        assert_eq!(state, BreakpointDisplayState::Unmapped);
    }

    #[test]
    fn test_display_state_toggle() {
        assert_eq!(
            BreakpointDisplayState::Enabled.toggled(true),
            BreakpointDisplayState::Disabled
        );
        assert_eq!(
            BreakpointDisplayState::Disabled.toggled(true),
            BreakpointDisplayState::Enabled
        );
        assert_eq!(
            BreakpointDisplayState::Disabled.toggled(false),
            BreakpointDisplayState::Disabled
        );
        assert_eq!(
            BreakpointDisplayState::Unmapped.toggled(true),
            BreakpointDisplayState::Unmapped
        );
    }

    #[test]
    fn test_logical_breakpoint_row() {
        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        let row = LogicalBreakpointRow::from_logical(bp);
        assert_eq!(row.expression, "0x400000");
        assert!(!row.is_mapped);
        assert_eq!(row.location_count, 0);
        // LogicalBreakpoint::new sets state to ENABLED by default
        assert_eq!(row.state, BreakpointDisplayState::Enabled);
    }

    #[test]
    fn test_breakpoint_kind_set() {
        let mut set = BreakpointKindSet::new();
        set.insert(TraceBreakpointKind::SwExecute);
        assert!(set.contains(&TraceBreakpointKind::SwExecute));
        assert!(!set.contains(&TraceBreakpointKind::HwExecute));
        set.insert(TraceBreakpointKind::HwExecute);
        assert_eq!(set.kinds.len(), 2);
    }

    #[test]
    fn test_breakpoint_location_row_toggle() {
        let row = BreakpointLocationRow {
            state: BreakpointDisplayState::Enabled,
            object_key: Some(1),
            trace_id: Some("trace1".into()),
            offset: 0x400000,
            length: 1,
            kinds: BreakpointKindSet::with_kind(TraceBreakpointKind::SwExecute),
            thread_key: None,
            expression: None,
        };
        assert_eq!(
            row.get_toggled_state(),
            BreakpointDisplayState::Disabled
        );
    }

    #[test]
    fn test_sleigh_breakpoint_input() {
        let input = SleighBreakpointInput {
            expression: "RAX".into(),
            kinds: BreakpointKindSet::with_kind(TraceBreakpointKind::Read),
            is_semantic: false,
            length: 8,
        };
        assert_eq!(input.expression, "RAX");
        assert!(!input.is_semantic);
    }
}
