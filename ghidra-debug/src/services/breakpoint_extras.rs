//! Additional breakpoint service types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.breakpoint` package.
//! Provides concrete implementations for logical breakpoint internals:
//! - `MappedLogicalBreakpoint`: A breakpoint that maps between program and trace.
//! - `ProgramBreakpoint`: A program-bookmark-based breakpoint.
//! - `LoneLogicalBreakpoint`: A breakpoint not mappable to any program.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

use crate::model::Lifespan;

/// A mapped logical breakpoint that maps between a program bookmark and
/// trace breakpoint locations.
///
/// Ported from `MappedLogicalBreakpoint`. This is the ideal case where
/// the breakpoint has both a program bookmark and trace locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedLogicalBreakpoint {
    /// The program URL.
    pub program_url: String,
    /// The static address in the program.
    pub program_address: u64,
    /// The breakpoint kinds.
    pub kinds: HashSet<BreakpointKindEntry>,
    /// The length of the breakpoint.
    pub length: u64,
    /// The name.
    pub name: String,
    /// Trace breakpoints (trace_key -> trace_breakpoint_ids).
    pub trace_breakpoints: BTreeMap<String, Vec<i64>>,
    /// Whether the program bookmark is enabled.
    pub bookmark_enabled: bool,
    /// The program bookmark ID, if bookmarked.
    pub bookmark_id: Option<i64>,
}

/// A breakpoint kind entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointKindEntry {
    /// Software breakpoint.
    Software,
    /// Hardware breakpoint.
    Hardware,
    /// Write watchpoint.
    WriteWatch,
    /// Read watchpoint.
    ReadWatch,
    /// Read/write watchpoint.
    AccessWatch,
    /// Sleigh injection breakpoint.
    SleighInjection,
}

impl MappedLogicalBreakpoint {
    /// Create a new mapped logical breakpoint.
    pub fn new(
        program_url: impl Into<String>,
        program_address: u64,
        kinds: HashSet<BreakpointKindEntry>,
    ) -> Self {
        Self {
            program_url: program_url.into(),
            program_address,
            kinds,
            length: 1,
            name: String::new(),
            trace_breakpoints: BTreeMap::new(),
            bookmark_enabled: true,
            bookmark_id: None,
        }
    }

    /// Add a trace breakpoint.
    pub fn add_trace_breakpoint(&mut self, trace_key: impl Into<String>, bp_id: i64) {
        self.trace_breakpoints
            .entry(trace_key.into())
            .or_default()
            .push(bp_id);
    }

    /// Remove a trace breakpoint.
    pub fn remove_trace_breakpoint(&mut self, trace_key: &str, bp_id: i64) -> bool {
        let key = trace_key.to_string();
        let Some(bps) = self.trace_breakpoints.get_mut(&key) else {
            return false;
        };
        let before = bps.len();
        bps.retain(|&id| id != bp_id);
        let removed = bps.len() < before;
        let empty = bps.is_empty();
        drop(bps);
        if empty {
            self.trace_breakpoints.remove(&key);
        }
        removed
    }

    /// Get the traces that have breakpoints.
    pub fn participating_traces(&self) -> Vec<&str> {
        self.trace_breakpoints.keys().map(|s| s.as_str()).collect()
    }

    /// Whether this breakpoint has any trace breakpoints.
    pub fn has_trace_breakpoints(&self) -> bool {
        !self.trace_breakpoints.is_empty()
    }

    /// Get the total number of trace breakpoints.
    pub fn trace_breakpoint_count(&self) -> usize {
        self.trace_breakpoints.values().map(|v| v.len()).sum()
    }

    /// Compute the mode across all trace breakpoints.
    pub fn compute_trace_mode(&self) -> TraceBreakpointMode {
        if self.trace_breakpoints.is_empty() {
            return TraceBreakpointMode::None;
        }
        // Simplified: in real Ghidra, each trace breakpoint has its own enabled state
        if self.bookmark_enabled {
            TraceBreakpointMode::Enabled
        } else {
            TraceBreakpointMode::Disabled
        }
    }
}

/// A program-based breakpoint (stored as a bookmark).
///
/// Ported from `ProgramBreakpoint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramBreakpoint {
    /// The bookmark ID.
    pub bookmark_id: i64,
    /// The address.
    pub address: u64,
    /// The bookmark type (enabled/disabled).
    pub bookmark_type: String,
    /// The breakpoint name.
    pub name: String,
    /// The sleigh injection text.
    pub emu_sleigh: Option<String>,
}

impl ProgramBreakpoint {
    /// Create an enabled program breakpoint.
    pub fn enabled(address: u64) -> Self {
        Self {
            bookmark_id: 0,
            address,
            bookmark_type: "BreakpointEnabled".into(),
            name: String::new(),
            emu_sleigh: None,
        }
    }

    /// Create a disabled program breakpoint.
    pub fn disabled(address: u64) -> Self {
        Self {
            bookmark_id: 0,
            address,
            bookmark_type: "BreakpointDisabled".into(),
            name: String::new(),
            emu_sleigh: None,
        }
    }

    /// Whether this breakpoint is enabled.
    pub fn is_enabled(&self) -> bool {
        self.bookmark_type == "BreakpointEnabled"
    }

    /// Toggle the enabled state.
    pub fn toggle(&mut self) {
        if self.is_enabled() {
            self.bookmark_type = "BreakpointDisabled".into();
        } else {
            self.bookmark_type = "BreakpointEnabled".into();
        }
    }
}

/// A lone logical breakpoint that is not mappable to any program.
///
/// Ported from `LoneLogicalBreakpoint`. These breakpoints exist only in
/// traces and have no corresponding program bookmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoneLogicalBreakpoint {
    /// The trace address.
    pub trace_address: u64,
    /// The trace key.
    pub trace_key: String,
    /// The breakpoint kinds.
    pub kinds: HashSet<BreakpointKindEntry>,
    /// Trace breakpoint IDs.
    pub trace_breakpoint_ids: Vec<i64>,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
}

impl LoneLogicalBreakpoint {
    /// Create a new lone logical breakpoint.
    pub fn new(
        trace_address: u64,
        trace_key: impl Into<String>,
        kinds: HashSet<BreakpointKindEntry>,
    ) -> Self {
        Self {
            trace_address,
            trace_key: trace_key.into(),
            kinds,
            trace_breakpoint_ids: Vec::new(),
            enabled: true,
        }
    }

    /// Add a trace breakpoint ID.
    pub fn add_breakpoint_id(&mut self, id: i64) {
        self.trace_breakpoint_ids.push(id);
    }

    /// Whether this is a lone (unmapped) breakpoint.
    pub fn is_lone(&self) -> bool {
        true // Always lone by definition
    }
}

/// The mode of a trace breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceBreakpointMode {
    /// No breakpoints.
    None,
    /// All breakpoints enabled.
    Enabled,
    /// All breakpoints disabled.
    Disabled,
    /// Mixed (some enabled, some disabled).
    Mixed,
}

impl TraceBreakpointMode {
    /// Combine two trace modes.
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::None, x) | (x, Self::None) => x,
            (Self::Enabled, Self::Enabled) => Self::Enabled,
            (Self::Disabled, Self::Disabled) => Self::Disabled,
            _ => Self::Mixed,
        }
    }
}

/// A breakpoint action set for batch operations.
///
/// Ported from `BreakpointActionSet`.
#[derive(Debug, Clone, Default)]
pub struct BreakpointActionSet {
    /// Actions to perform.
    actions: Vec<BreakpointActionEntry>,
}

/// An entry in a breakpoint action set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointActionEntry {
    /// The action kind.
    pub kind: BreakpointActionKind,
    /// The breakpoint ID.
    pub breakpoint_id: i64,
    /// The trace key.
    pub trace_key: String,
    /// The address.
    pub address: u64,
}

/// The kind of breakpoint action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointActionKind {
    /// Place a new breakpoint.
    Place,
    /// Delete an existing breakpoint.
    Delete,
    /// Enable a breakpoint.
    Enable,
    /// Disable a breakpoint.
    Disable,
}

impl BreakpointActionSet {
    /// Create a new action set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an action.
    pub fn push(&mut self, entry: BreakpointActionEntry) {
        self.actions.push(entry);
    }

    /// Get all actions.
    pub fn actions(&self) -> &[BreakpointActionEntry] {
        &self.actions
    }

    /// Get the number of actions.
    pub fn count(&self) -> usize {
        self.actions.len()
    }

    /// Whether the action set is empty.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Clear all actions.
    pub fn clear(&mut self) {
        self.actions.clear();
    }
}

/// Exception for breakpoints that were tracked too soon.
///
/// Ported from `TrackedTooSoonException`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedTooSoonException {
    /// The address that was tracked.
    pub address: u64,
    /// The elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// The minimum required time in milliseconds.
    pub required_ms: u64,
}

impl std::fmt::Display for TrackedTooSoonException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Breakpoint at 0x{:x} tracked too soon: {}ms elapsed, {}ms required",
            self.address, self.elapsed_ms, self.required_ms
        )
    }
}

impl std::error::Error for TrackedTooSoonException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapped_logical_breakpoint() {
        let mut bp = MappedLogicalBreakpoint::new(
            "file:///test.gzf",
            0x401000,
            HashSet::from([BreakpointKindEntry::Software]),
        );
        assert_eq!(bp.program_address, 0x401000);
        assert!(!bp.has_trace_breakpoints());

        bp.add_trace_breakpoint("trace1", 100);
        bp.add_trace_breakpoint("trace1", 101);
        bp.add_trace_breakpoint("trace2", 200);
        assert!(bp.has_trace_breakpoints());
        assert_eq!(bp.trace_breakpoint_count(), 3);
        assert_eq!(bp.participating_traces().len(), 2);

        assert!(bp.remove_trace_breakpoint("trace1", 100));
        assert_eq!(bp.trace_breakpoint_count(), 2);
    }

    #[test]
    fn test_program_breakpoint() {
        let mut bp = ProgramBreakpoint::enabled(0x401000);
        assert!(bp.is_enabled());

        bp.toggle();
        assert!(!bp.is_enabled());
        assert_eq!(bp.bookmark_type, "BreakpointDisabled");

        bp.toggle();
        assert!(bp.is_enabled());
    }

    #[test]
    fn test_lone_logical_breakpoint() {
        let mut bp = LoneLogicalBreakpoint::new(
            0x7FFE0000,
            "trace1",
            HashSet::from([BreakpointKindEntry::Hardware]),
        );
        assert!(bp.is_lone());
        assert!(bp.enabled);

        bp.add_breakpoint_id(42);
        assert_eq!(bp.trace_breakpoint_ids.len(), 1);
    }

    #[test]
    fn test_trace_breakpoint_mode_combine() {
        assert_eq!(
            TraceBreakpointMode::None.combine(TraceBreakpointMode::Enabled),
            TraceBreakpointMode::Enabled
        );
        assert_eq!(
            TraceBreakpointMode::Enabled.combine(TraceBreakpointMode::Enabled),
            TraceBreakpointMode::Enabled
        );
        assert_eq!(
            TraceBreakpointMode::Enabled.combine(TraceBreakpointMode::Disabled),
            TraceBreakpointMode::Mixed
        );
        assert_eq!(
            TraceBreakpointMode::Disabled.combine(TraceBreakpointMode::Disabled),
            TraceBreakpointMode::Disabled
        );
    }

    #[test]
    fn test_breakpoint_action_set() {
        let mut set = BreakpointActionSet::new();
        assert!(set.is_empty());

        set.push(BreakpointActionEntry {
            kind: BreakpointActionKind::Place,
            breakpoint_id: 1,
            trace_key: "trace1".into(),
            address: 0x401000,
        });
        set.push(BreakpointActionEntry {
            kind: BreakpointActionKind::Enable,
            breakpoint_id: 2,
            trace_key: "trace1".into(),
            address: 0x402000,
        });

        assert_eq!(set.count(), 2);
        assert_eq!(set.actions()[0].kind, BreakpointActionKind::Place);

        set.clear();
        assert!(set.is_empty());
    }

    #[test]
    fn test_tracked_too_soon() {
        let exc = TrackedTooSoonException {
            address: 0x401000,
            elapsed_ms: 50,
            required_ms: 100,
        };
        let msg = format!("{}", exc);
        assert!(msg.contains("0x401000"));
        assert!(msg.contains("50ms"));
    }

    #[test]
    fn test_breakpoint_kind_entry() {
        assert_ne!(
            BreakpointKindEntry::Software,
            BreakpointKindEntry::Hardware
        );
        assert_eq!(
            BreakpointKindEntry::WriteWatch,
            BreakpointKindEntry::WriteWatch
        );
    }
}
