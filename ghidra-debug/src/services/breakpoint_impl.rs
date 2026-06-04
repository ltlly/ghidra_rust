//! Breakpoint service implementation types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.breakpoint` package.
//! Provides types for managing logical breakpoints across programs, traces, and emulators.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::api::breakpoint::{BreakpointMode, BreakpointState, LogicalBreakpoint};
use crate::model::Lifespan;

// ── Action Items ──────────────────────────────────────────────────────────

/// An action item to perform on a breakpoint (enable, disable, delete, place).
///
/// Ported from Ghidra's `BreakpointActionItem`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointActionKind {
    /// Enable the breakpoint on the target.
    EnableTarget,
    /// Disable the breakpoint on the target.
    DisableTarget,
    /// Delete the breakpoint from the target.
    DeleteTarget,
    /// Place the breakpoint on the target.
    PlaceTarget,
    /// Enable the breakpoint in the emulator.
    EnableEmu,
    /// Disable the breakpoint in the emulator.
    DisableEmu,
    /// Delete the breakpoint from the emulator.
    DeleteEmu,
    /// Place the breakpoint in the emulator.
    PlaceEmu,
}

/// An action item describing a specific operation to perform on a breakpoint.
///
/// Ported from Ghidra's `BreakpointActionItem`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointActionItem {
    /// The kind of action.
    pub kind: BreakpointActionKind,
    /// The breakpoint address.
    pub address: u64,
    /// The trace ID (if applicable).
    pub trace_id: Option<String>,
    /// The program URL (if applicable).
    pub program_url: Option<String>,
    /// Whether this action is pending.
    pub pending: bool,
}

impl BreakpointActionItem {
    /// Create a new action item.
    pub fn new(kind: BreakpointActionKind, address: u64) -> Self {
        Self {
            kind,
            address,
            trace_id: None,
            program_url: None,
            pending: true,
        }
    }

    /// Set the trace ID.
    pub fn with_trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Set the program URL.
    pub fn with_program(mut self, program_url: impl Into<String>) -> Self {
        self.program_url = Some(program_url.into());
        self
    }

    /// Mark as completed.
    pub fn complete(&mut self) {
        self.pending = false;
    }
}

// ── Breakpoint Action Set ─────────────────────────────────────────────────

/// A set of breakpoint action items to be executed atomically.
///
/// Ported from Ghidra's `BreakpointActionSet`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BreakpointActionSet {
    /// The actions in this set.
    pub actions: Vec<BreakpointActionItem>,
    /// The description of this action set.
    pub description: String,
}

impl BreakpointActionSet {
    /// Create a new empty action set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Add an action.
    pub fn add(&mut self, action: BreakpointActionItem) {
        self.actions.push(action);
    }

    /// Number of actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Get all pending actions.
    pub fn pending(&self) -> Vec<&BreakpointActionItem> {
        self.actions.iter().filter(|a| a.pending).collect()
    }
}

// ── Logical Breakpoint Internal ───────────────────────────────────────────

/// Internal representation of a logical breakpoint with full tracking state.
///
/// Ported from Ghidra's `LogicalBreakpointInternal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalBreakpointInternal {
    /// The base logical breakpoint.
    pub base: LogicalBreakpoint,
    /// The set of program breakpoints that correspond to this logical breakpoint.
    pub program_breakpoints: Vec<ProgramBreakpoint>,
    /// The set of trace breakpoints that correspond to this logical breakpoint.
    pub trace_breakpoints: Vec<TraceBreakpointEntry>,
    /// Whether the breakpoint is being tracked.
    pub tracked: bool,
    /// Error message if placement failed.
    pub error: Option<String>,
}

impl LogicalBreakpointInternal {
    /// Create a new internal breakpoint from a base.
    pub fn new(base: LogicalBreakpoint) -> Self {
        Self {
            base,
            program_breakpoints: Vec::new(),
            trace_breakpoints: Vec::new(),
            tracked: false,
            error: None,
        }
    }

    /// Add a program breakpoint.
    pub fn add_program_breakpoint(&mut self, bp: ProgramBreakpoint) {
        self.program_breakpoints.push(bp);
    }

    /// Add a trace breakpoint.
    pub fn add_trace_breakpoint(&mut self, bp: TraceBreakpointEntry) {
        self.trace_breakpoints.push(bp);
    }

    /// Whether this breakpoint is effective (placed on target).
    pub fn is_effective(&self) -> bool {
        self.base.is_enabled() && !self.trace_breakpoints.is_empty()
    }

    /// Set an error message.
    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
    }

    /// Clear the error.
    pub fn clear_error(&mut self) {
        self.error = None;
    }
}

// ── Program Breakpoint ────────────────────────────────────────────────────

/// A breakpoint in a static program.
///
/// Ported from Ghidra's `ProgramBreakpoint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramBreakpoint {
    /// The program URL.
    pub program_url: String,
    /// The address in the program.
    pub address: u64,
    /// The breakpoint expression (Sleigh or address).
    pub expression: String,
    /// The kind of breakpoint.
    pub kind: ProgramBreakpointKind,
}

/// The kind of program breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProgramBreakpointKind {
    /// Software breakpoint (INT3, etc.).
    Software,
    /// Hardware breakpoint.
    Hardware,
    /// Read watchpoint.
    ReadWatch,
    /// Write watchpoint.
    WriteWatch,
    /// Access watchpoint (read/write).
    AccessWatch,
}

impl ProgramBreakpoint {
    /// Create a new software breakpoint.
    pub fn software(program_url: impl Into<String>, address: u64) -> Self {
        Self {
            program_url: program_url.into(),
            address,
            expression: format!("0x{:x}", address),
            kind: ProgramBreakpointKind::Software,
        }
    }

    /// Create a new hardware breakpoint.
    pub fn hardware(program_url: impl Into<String>, address: u64) -> Self {
        Self {
            program_url: program_url.into(),
            address,
            expression: format!("0x{:x}", address),
            kind: ProgramBreakpointKind::Hardware,
        }
    }
}

// ── Trace Breakpoint Entry ────────────────────────────────────────────────

/// An entry representing a breakpoint in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBreakpointEntry {
    /// The trace ID.
    pub trace_id: String,
    /// The trace breakpoint key.
    pub breakpoint_key: i64,
    /// The address.
    pub address: u64,
    /// The kind.
    pub kind: ProgramBreakpointKind,
    /// The lifespan.
    pub lifespan: Lifespan,
}

impl TraceBreakpointEntry {
    /// Create a new trace breakpoint entry.
    pub fn new(
        trace_id: impl Into<String>,
        breakpoint_key: i64,
        address: u64,
        kind: ProgramBreakpointKind,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            breakpoint_key,
            address,
            kind,
            lifespan,
        }
    }
}

// ── Trace Breakpoint Set ──────────────────────────────────────────────────

/// A set of breakpoints belonging to a single trace.
///
/// Ported from Ghidra's `TraceBreakpointSet`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceBreakpointSet {
    /// The trace ID.
    pub trace_id: String,
    /// Breakpoint entries keyed by breakpoint key.
    pub entries: BTreeMap<i64, TraceBreakpointEntry>,
}

impl TraceBreakpointSet {
    /// Create a new set for a trace.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Add a breakpoint entry.
    pub fn add(&mut self, entry: TraceBreakpointEntry) {
        self.entries.insert(entry.breakpoint_key, entry);
    }

    /// Remove a breakpoint by key.
    pub fn remove(&mut self, key: i64) -> Option<TraceBreakpointEntry> {
        self.entries.remove(&key)
    }

    /// Get the number of breakpoints.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Mapped Logical Breakpoint ─────────────────────────────────────────────

/// A logical breakpoint that is mapped from a program to a trace.
///
/// Ported from Ghidra's `MappedLogicalBreakpoint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedLogicalBreakpoint {
    /// The program URL.
    pub program_url: String,
    /// The program address.
    pub program_address: u64,
    /// The trace address it maps to.
    pub trace_address: u64,
    /// The logical breakpoint.
    pub logical: LogicalBreakpointInternal,
}

impl MappedLogicalBreakpoint {
    /// Create a new mapped logical breakpoint.
    pub fn new(
        program_url: impl Into<String>,
        program_address: u64,
        trace_address: u64,
        logical: LogicalBreakpointInternal,
    ) -> Self {
        Self {
            program_url: program_url.into(),
            program_address,
            trace_address,
            logical,
        }
    }
}

// ── Lone Logical Breakpoint ───────────────────────────────────────────────

/// A logical breakpoint that exists only in a program (not mapped to a trace).
///
/// Ported from Ghidra's `LoneLogicalBreakpoint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoneLogicalBreakpoint {
    /// The program URL.
    pub program_url: String,
    /// The address.
    pub address: u64,
    /// The logical breakpoint.
    pub logical: LogicalBreakpointInternal,
}

impl LoneLogicalBreakpoint {
    /// Create a new lone logical breakpoint.
    pub fn new(
        program_url: impl Into<String>,
        address: u64,
        logical: LogicalBreakpointInternal,
    ) -> Self {
        Self {
            program_url: program_url.into(),
            address,
            logical,
        }
    }
}

/// Exception thrown when a breakpoint is tracked too soon (before target is ready).
///
/// Ported from Ghidra's `TrackedTooSoonException`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Breakpoint at 0x{address:x} tracked too soon: {message}")]
pub struct TrackedTooSoonException {
    /// The breakpoint address.
    pub address: u64,
    /// The message.
    pub message: String,
}

impl TrackedTooSoonException {
    /// Create a new exception.
    pub fn new(address: u64, message: impl Into<String>) -> Self {
        Self {
            address,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_action_item() {
        let item = BreakpointActionItem::new(BreakpointActionKind::PlaceTarget, 0x400000)
            .with_trace("trace1")
            .with_program("file:///prog");
        assert_eq!(item.address, 0x400000);
        assert!(item.pending);
        assert_eq!(item.trace_id.as_deref(), Some("trace1"));

        let mut item = item;
        item.complete();
        assert!(!item.pending);
    }

    #[test]
    fn test_breakpoint_action_set() {
        let mut set = BreakpointActionSet::new()
            .with_description("Enable all breakpoints");
        set.add(BreakpointActionItem::new(BreakpointActionKind::EnableTarget, 0x400000));
        set.add(BreakpointActionItem::new(BreakpointActionKind::EnableEmu, 0x400000));
        assert_eq!(set.len(), 2);
        assert_eq!(set.pending().len(), 2);
    }

    #[test]
    fn test_logical_breakpoint_internal() {
        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        let mut internal = LogicalBreakpointInternal::new(bp);
        assert!(!internal.is_effective());

        internal.add_trace_breakpoint(TraceBreakpointEntry::new(
            "trace1",
            1,
            0x400000,
            ProgramBreakpointKind::Software,
            Lifespan::now_on(0),
        ));
        assert!(internal.is_effective());

        internal.set_error("placement failed");
        assert!(internal.error.is_some());
        internal.clear_error();
        assert!(internal.error.is_none());
    }

    #[test]
    fn test_program_breakpoint() {
        let bp = ProgramBreakpoint::software("prog", 0x400000);
        assert_eq!(bp.kind, ProgramBreakpointKind::Software);
        assert_eq!(bp.address, 0x400000);

        let bp = ProgramBreakpoint::hardware("prog", 0x401000);
        assert_eq!(bp.kind, ProgramBreakpointKind::Hardware);
    }

    #[test]
    fn test_trace_breakpoint_set() {
        let mut set = TraceBreakpointSet::new("trace1");
        assert!(set.is_empty());

        set.add(TraceBreakpointEntry::new(
            "trace1",
            1,
            0x400000,
            ProgramBreakpointKind::Software,
            Lifespan::now_on(0),
        ));
        assert_eq!(set.len(), 1);

        let removed = set.remove(1);
        assert!(removed.is_some());
        assert!(set.is_empty());
    }

    #[test]
    fn test_mapped_logical_breakpoint() {
        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        let internal = LogicalBreakpointInternal::new(bp);
        let mapped = MappedLogicalBreakpoint::new("prog", 0x400000, 0x7fff0000, internal);
        assert_eq!(mapped.program_address, 0x400000);
        assert_eq!(mapped.trace_address, 0x7fff0000);
    }

    #[test]
    fn test_lone_logical_breakpoint() {
        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        let internal = LogicalBreakpointInternal::new(bp);
        let lone = LoneLogicalBreakpoint::new("prog", 0x400000, internal);
        assert_eq!(lone.address, 0x400000);
    }

    #[test]
    fn test_tracked_too_soon() {
        let err = TrackedTooSoonException::new(0x400000, "Target not ready");
        assert_eq!(err.address, 0x400000);
        assert!(err.to_string().contains("400000"));
    }

    #[test]
    fn test_breakpoint_action_set_serde() {
        let mut set = BreakpointActionSet::new();
        set.add(BreakpointActionItem::new(BreakpointActionKind::PlaceTarget, 0x400000));
        let json = serde_json::to_string(&set).unwrap();
        let back: BreakpointActionSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }
}
