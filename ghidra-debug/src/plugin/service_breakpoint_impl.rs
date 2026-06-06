//! Breakpoint service implementation types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.breakpoint` package.
//! Provides the logical breakpoint service plugin data model including
//! breakpoint action items, tracked breakpoints, and program breakpoints.

use std::collections::BTreeMap;

use crate::api::breakpoint::LogicalBreakpoint;

/// Kind of action to perform on a breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointActionKind {
    /// Place a breakpoint on the emulator.
    PlaceEmu,
    /// Delete a breakpoint from the emulator.
    DeleteEmu,
    /// Enable a breakpoint on the emulator.
    EnableEmu,
    /// Disable a breakpoint on the emulator.
    DisableEmu,
    /// Place a breakpoint on the target.
    PlaceTarget,
    /// Delete a breakpoint from the target.
    DeleteTarget,
    /// Enable a breakpoint on the target.
    EnableTarget,
    /// Disable a breakpoint on the target.
    DisableTarget,
}

/// An action item describing a single breakpoint action to perform.
///
/// Corresponds to Java's `BreakpointActionItem` and its subclasses.
#[derive(Debug, Clone)]
pub struct BreakpointActionItem {
    /// The kind of action.
    pub action: BreakpointActionKind,
    /// The logical breakpoint this action targets.
    pub breakpoint_key: u64,
    /// The trace key associated with this action.
    pub trace_key: Option<i64>,
    /// The program URL for program-level breakpoints.
    pub program_url: Option<String>,
    /// Whether this action has been completed.
    pub completed: bool,
}

impl BreakpointActionItem {
    /// Create a new action item.
    pub fn new(action: BreakpointActionKind, breakpoint_key: u64) -> Self {
        Self {
            action,
            breakpoint_key,
            trace_key: None,
            program_url: None,
            completed: false,
        }
    }

    /// Set the trace key.
    pub fn with_trace_key(mut self, key: i64) -> Self {
        self.trace_key = Some(key);
        self
    }

    /// Set the program URL.
    pub fn with_program_url(mut self, url: impl Into<String>) -> Self {
        self.program_url = Some(url.into());
        self
    }

    /// Mark this action as completed.
    pub fn mark_completed(&mut self) {
        self.completed = true;
    }

    /// Whether this is an emulator action.
    pub fn is_emu_action(&self) -> bool {
        matches!(
            self.action,
            BreakpointActionKind::PlaceEmu
                | BreakpointActionKind::DeleteEmu
                | BreakpointActionKind::EnableEmu
                | BreakpointActionKind::DisableEmu
        )
    }

    /// Whether this is a target action.
    pub fn is_target_action(&self) -> bool {
        !self.is_emu_action()
    }
}

/// A set of breakpoint action items to be executed together.
#[derive(Debug, Clone)]
pub struct BreakpointActionSet {
    /// The action items in this set.
    pub items: Vec<BreakpointActionItem>,
    /// Unique identifier for this action set.
    pub set_id: u64,
}

impl BreakpointActionSet {
    /// Create a new action set.
    pub fn new(set_id: u64) -> Self {
        Self {
            items: Vec::new(),
            set_id,
        }
    }

    /// Add an action item to the set.
    pub fn push(&mut self, item: BreakpointActionItem) {
        self.items.push(item);
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get the number of actions in the set.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Get the number of completed actions.
    pub fn completed_count(&self) -> usize {
        self.items.iter().filter(|i| i.completed).count()
    }

    /// Check if all actions are completed.
    pub fn all_completed(&self) -> bool {
        !self.items.is_empty() && self.items.iter().all(|i| i.completed)
    }
}

/// A trace-level breakpoint reference within a logical breakpoint.
#[derive(Debug, Clone)]
pub struct TraceBreakpointEntry {
    /// Trace key.
    pub trace_key: i64,
    /// Breakpoint specification key in the trace.
    pub spec_key: u64,
    /// Whether the trace breakpoint is enabled.
    pub enabled: bool,
    /// Address offset.
    pub offset: u64,
}

/// A set of trace breakpoints associated with a logical breakpoint.
///
/// Corresponds to Java's `TraceBreakpointSet`.
#[derive(Debug, Clone)]
pub struct TraceBreakpointSet {
    /// The entries in this set.
    entries: BTreeMap<i64, TraceBreakpointEntry>,
}

impl TraceBreakpointSet {
    /// Create a new trace breakpoint set.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Add a trace breakpoint entry.
    pub fn insert(&mut self, entry: TraceBreakpointEntry) {
        self.entries.insert(entry.trace_key, entry);
    }

    /// Remove a trace breakpoint by trace key.
    pub fn remove(&mut self, trace_key: i64) -> Option<TraceBreakpointEntry> {
        self.entries.remove(&trace_key)
    }

    /// Get a trace breakpoint by trace key.
    pub fn get(&self, trace_key: i64) -> Option<&TraceBreakpointEntry> {
        self.entries.get(&trace_key)
    }

    /// Get all entries.
    pub fn entries(&self) -> Vec<&TraceBreakpointEntry> {
        self.entries.values().collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the trace keys in this set.
    pub fn trace_keys(&self) -> Vec<i64> {
        self.entries.keys().copied().collect()
    }
}

impl Default for TraceBreakpointSet {
    fn default() -> Self {
        Self::new()
    }
}

/// A program-level breakpoint entry.
///
/// Corresponds to Java's `ProgramBreakpoint`. Represents a breakpoint
/// defined in a static program that has been mapped to the trace.
#[derive(Debug, Clone)]
pub struct ProgramBreakpoint {
    /// Program URL.
    pub program_url: String,
    /// Address in the program.
    pub program_address: u64,
    /// Associated logical breakpoint key.
    pub logical_bp_key: Option<u64>,
    /// Whether this program breakpoint is enabled.
    pub enabled: bool,
}

impl ProgramBreakpoint {
    /// Create a new program breakpoint.
    pub fn new(program_url: impl Into<String>, program_address: u64) -> Self {
        Self {
            program_url: program_url.into(),
            program_address,
            logical_bp_key: None,
            enabled: true,
        }
    }

    /// Associate with a logical breakpoint.
    pub fn set_logical_bp(&mut self, key: u64) {
        self.logical_bp_key = Some(key);
    }

    /// Check if this is associated with a logical breakpoint.
    pub fn has_logical_bp(&self) -> bool {
        self.logical_bp_key.is_some()
    }
}

/// Exception thrown when a breakpoint is tracked too soon.
///
/// Corresponds to Java's `TrackedTooSoonException`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Breakpoint tracked too soon: {message}")]
pub struct TrackedTooSoonException {
    /// Error message.
    pub message: String,
    /// The breakpoint key that was tracked too early.
    pub breakpoint_key: u64,
    /// Minimum delay required (in milliseconds).
    pub min_delay_ms: u64,
}

impl TrackedTooSoonException {
    /// Create a new exception.
    pub fn new(message: impl Into<String>, breakpoint_key: u64, min_delay_ms: u64) -> Self {
        Self {
            message: message.into(),
            breakpoint_key,
            min_delay_ms,
        }
    }
}

/// Internal state of a logical breakpoint for the service implementation.
///
/// Corresponds to Java's `LogicalBreakpointInternal`.
#[derive(Debug, Clone)]
pub struct LogicalBreakpointInternal {
    /// The public logical breakpoint.
    pub breakpoint: LogicalBreakpoint,
    /// Trace breakpoints associated with this logical breakpoint.
    pub trace_bps: TraceBreakpointSet,
    /// Program breakpoints associated with this logical breakpoint.
    pub program_bps: Vec<ProgramBreakpoint>,
    /// Pending action items.
    pub pending_actions: Vec<BreakpointActionItem>,
    /// Whether the breakpoint is currently being tracked.
    pub is_tracking: bool,
}

impl LogicalBreakpointInternal {
    /// Create from a logical breakpoint.
    pub fn new(breakpoint: LogicalBreakpoint) -> Self {
        Self {
            breakpoint,
            trace_bps: TraceBreakpointSet::new(),
            program_bps: Vec::new(),
            pending_actions: Vec::new(),
            is_tracking: false,
        }
    }

    /// Get the breakpoint key (offset).
    pub fn key(&self) -> u64 {
        self.breakpoint.offset
    }

    /// Check if the breakpoint has any trace associations.
    pub fn has_trace_bps(&self) -> bool {
        !self.trace_bps.is_empty()
    }

    /// Check if the breakpoint has any program associations.
    pub fn has_program_bps(&self) -> bool {
        !self.program_bps.is_empty()
    }

    /// Add a pending action.
    pub fn add_pending_action(&mut self, action: BreakpointActionItem) {
        self.pending_actions.push(action);
    }

    /// Clear pending actions.
    pub fn clear_pending_actions(&mut self) {
        self.pending_actions.clear();
    }
}

/// A "lone" logical breakpoint that has no mapped trace or program association.
///
/// Corresponds to Java's `LoneLogicalBreakpoint`.
#[derive(Debug, Clone)]
pub struct LoneLogicalBreakpoint {
    /// The logical breakpoint data.
    pub bp: LogicalBreakpoint,
    /// When this breakpoint was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl LoneLogicalBreakpoint {
    /// Create a new lone logical breakpoint.
    pub fn new(bp: LogicalBreakpoint) -> Self {
        Self {
            bp,
            created_at: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_action_item() {
        let item = BreakpointActionItem::new(BreakpointActionKind::PlaceEmu, 42)
            .with_trace_key(1)
            .with_program_url("file:///test");
        assert!(item.is_emu_action());
        assert!(!item.is_target_action());
        assert!(!item.completed);
        assert_eq!(item.trace_key, Some(1));
    }

    #[test]
    fn test_breakpoint_action_target() {
        let mut item = BreakpointActionItem::new(BreakpointActionKind::PlaceTarget, 10);
        assert!(item.is_target_action());
        item.mark_completed();
        assert!(item.completed);
    }

    #[test]
    fn test_breakpoint_action_set() {
        let mut set = BreakpointActionSet::new(1);
        assert!(set.is_empty());

        set.push(BreakpointActionItem::new(BreakpointActionKind::PlaceEmu, 1));
        set.push(BreakpointActionItem::new(BreakpointActionKind::PlaceTarget, 2));
        assert_eq!(set.len(), 2);
        assert_eq!(set.completed_count(), 0);
        assert!(!set.all_completed());
    }

    #[test]
    fn test_breakpoint_action_set_all_completed() {
        let mut set = BreakpointActionSet::new(1);
        let mut item1 = BreakpointActionItem::new(BreakpointActionKind::PlaceEmu, 1);
        let mut item2 = BreakpointActionItem::new(BreakpointActionKind::PlaceTarget, 2);
        item1.mark_completed();
        item2.mark_completed();
        set.push(item1);
        set.push(item2);
        assert!(set.all_completed());
    }

    #[test]
    fn test_trace_breakpoint_set() {
        let mut tbs = TraceBreakpointSet::new();
        assert!(tbs.is_empty());

        tbs.insert(TraceBreakpointEntry {
            trace_key: 1,
            spec_key: 100,
            enabled: true,
            offset: 0x400000,
        });
        tbs.insert(TraceBreakpointEntry {
            trace_key: 2,
            spec_key: 200,
            enabled: false,
            offset: 0x400100,
        });

        assert_eq!(tbs.len(), 2);
        assert!(tbs.get(1).is_some());
        assert!(tbs.get(3).is_none());
        assert_eq!(tbs.trace_keys(), vec![1, 2]);
    }

    #[test]
    fn test_trace_breakpoint_set_remove() {
        let mut tbs = TraceBreakpointSet::new();
        tbs.insert(TraceBreakpointEntry {
            trace_key: 1,
            spec_key: 100,
            enabled: true,
            offset: 0x400000,
        });
        tbs.remove(1);
        assert!(tbs.is_empty());
    }

    #[test]
    fn test_program_breakpoint() {
        let mut pb = ProgramBreakpoint::new("file:///test", 0x400000);
        assert!(!pb.has_logical_bp());
        pb.set_logical_bp(42);
        assert!(pb.has_logical_bp());
        assert!(pb.enabled);
    }

    #[test]
    fn test_tracked_too_soon_exception() {
        let err = TrackedTooSoonException::new("too soon", 100, 500);
        assert_eq!(err.breakpoint_key, 100);
        assert_eq!(err.min_delay_ms, 500);
        assert!(err.to_string().contains("too soon"));
    }

    #[test]
    fn test_logical_breakpoint_internal() {
        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        let mut internal = LogicalBreakpointInternal::new(bp);
        assert_eq!(internal.key(), 0x400000);
        assert!(!internal.has_trace_bps());
        assert!(!internal.has_program_bps());

        internal.add_pending_action(BreakpointActionItem::new(
            BreakpointActionKind::PlaceEmu,
            1,
        ));
        assert_eq!(internal.pending_actions.len(), 1);

        internal.clear_pending_actions();
        assert!(internal.pending_actions.is_empty());
    }

    #[test]
    fn test_lone_logical_breakpoint() {
        let bp = LogicalBreakpoint::new(0x500000, "0x500000");
        let lone = LoneLogicalBreakpoint::new(bp);
        assert_eq!(lone.bp.offset, 0x500000);
    }
}
