//! Breakpoint lifecycle manager - comprehensive breakpoint management.
//!
//! Ported from Ghidra's `DebuggerLogicalBreakpointServicePlugin` (1427 lines)
//! and `MappedLogicalBreakpoint` (583 lines). This module manages the complete
//! lifecycle of logical breakpoints: creation, enabling/disabling, placement
//! on targets, synchronization with emulators, and deletion.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::api::breakpoint::{
    BreakpointState, LogicalBreakpoint,
};
use crate::model::breakpoint::TraceBreakpointKind;

/// Action items that can be applied to breakpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointActionItem {
    /// Place a breakpoint on the target.
    PlaceTarget,
    /// Place a breakpoint on the emulator.
    PlaceEmu,
    /// Delete a breakpoint from the target.
    DeleteTarget,
    /// Delete a breakpoint from the emulator.
    DeleteEmu,
    /// Enable a breakpoint on the target.
    EnableTarget,
    /// Enable a breakpoint on the emulator.
    EnableEmu,
    /// Disable a breakpoint on the target.
    DisableTarget,
    /// Disable a breakpoint on the emulator.
    DisableEmu,
}

/// A set of action items to apply to a breakpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BreakpointActionSet {
    /// The action items in this set.
    items: Vec<BreakpointActionItem>,
}

impl BreakpointActionSet {
    /// Create an empty action set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an action item.
    pub fn push(&mut self, item: BreakpointActionItem) {
        if !self.items.contains(&item) {
            self.items.push(item);
        }
    }

    /// Check if the set contains a given action.
    pub fn contains(&self, item: &BreakpointActionItem) -> bool {
        self.items.contains(item)
    }

    /// Get the action items.
    pub fn items(&self) -> &[BreakpointActionItem] {
        &self.items
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Merge another action set into this one.
    pub fn merge(&mut self, other: &BreakpointActionSet) {
        for item in &other.items {
            self.push(item.clone());
        }
    }
}

/// A program breakpoint ties a logical breakpoint to a specific program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramBreakpoint {
    /// The logical breakpoint.
    pub logical: LogicalBreakpoint,
    /// The program key.
    pub program_key: String,
    /// The address in the program.
    pub address: u64,
}

/// A trace breakpoint set tracks breakpoints in a single trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBreakpointSet {
    /// The trace key.
    pub trace_key: String,
    /// Breakpoints indexed by their expression string.
    breakpoints: BTreeMap<String, LogicalBreakpoint>,
}

impl TraceBreakpointSet {
    /// Create an empty breakpoint set for a trace.
    pub fn new(trace_key: impl Into<String>) -> Self {
        Self {
            trace_key: trace_key.into(),
            breakpoints: BTreeMap::new(),
        }
    }

    /// Add a breakpoint.
    pub fn insert(&mut self, bp: LogicalBreakpoint) {
        self.breakpoints.insert(bp.expression.clone(), bp);
    }

    /// Remove a breakpoint by expression.
    pub fn remove(&mut self, expression: &str) -> Option<LogicalBreakpoint> {
        self.breakpoints.remove(expression)
    }

    /// Get a breakpoint by expression.
    pub fn get(&self, expression: &str) -> Option<&LogicalBreakpoint> {
        self.breakpoints.get(expression)
    }

    /// Get all breakpoints.
    pub fn all(&self) -> impl Iterator<Item = &LogicalBreakpoint> {
        self.breakpoints.values()
    }

    /// The number of breakpoints in the set.
    pub fn len(&self) -> usize {
        self.breakpoints.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    /// Get all enabled breakpoints.
    pub fn enabled(&self) -> Vec<&LogicalBreakpoint> {
        self.breakpoints
            .values()
            .filter(|bp| bp.is_enabled())
            .collect()
    }

    /// Get all disabled breakpoints.
    pub fn disabled(&self) -> Vec<&LogicalBreakpoint> {
        self.breakpoints
            .values()
            .filter(|bp| !bp.is_enabled())
            .collect()
    }

    /// Enable all breakpoints.
    pub fn enable_all(&mut self) {
        for bp in self.breakpoints.values_mut() {
            bp.state = BreakpointState::ENABLED;
        }
    }

    /// Disable all breakpoints.
    pub fn disable_all(&mut self) {
        for bp in self.breakpoints.values_mut() {
            bp.state = BreakpointState::DISABLED;
        }
    }

    /// Delete all breakpoints.
    pub fn clear(&mut self) {
        self.breakpoints.clear();
    }

    /// Compute actions needed to synchronize this set with a target state.
    pub fn compute_sync_actions(&self, has_target: bool) -> Vec<(String, BreakpointActionSet)> {
        let mut actions = Vec::new();
        for (expr, bp) in &self.breakpoints {
            let mut set = BreakpointActionSet::new();
            if bp.is_enabled() && has_target {
                set.push(BreakpointActionItem::PlaceTarget);
            } else if !bp.is_enabled() {
                set.push(BreakpointActionItem::DisableTarget);
            }
            if !set.is_empty() {
                actions.push((expr.clone(), set));
            }
        }
        actions
    }
}

/// The main breakpoint manager that coordinates breakpoints across
/// programs, traces, and emulators.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogicalBreakpointManager {
    /// Program breakpoints indexed by (program_key, address).
    program_breakpoints: BTreeMap<(String, u64), LogicalBreakpoint>,
    /// Trace breakpoint sets indexed by trace key.
    trace_sets: BTreeMap<String, TraceBreakpointSet>,
    /// Whether the manager is currently synchronizing.
    synchronizing: bool,
}

impl LogicalBreakpointManager {
    /// Create a new breakpoint manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a breakpoint at the given address in a program.
    pub fn add_program_breakpoint(
        &mut self,
        program_key: &str,
        address: u64,
        expression: impl Into<String>,
        kinds: Vec<TraceBreakpointKind>,
    ) -> &LogicalBreakpoint {
        let bp = LogicalBreakpoint::new(address, expression)
            .with_kinds(kinds.iter().map(|k| format!("{:?}", k)).collect());
        self.program_breakpoints
            .insert((program_key.to_string(), address), bp);
        self.program_breakpoints
            .get(&(program_key.to_string(), address))
            .unwrap()
    }

    /// Remove a program breakpoint.
    pub fn remove_program_breakpoint(
        &mut self,
        program_key: &str,
        address: u64,
    ) -> Option<LogicalBreakpoint> {
        self.program_breakpoints
            .remove(&(program_key.to_string(), address))
    }

    /// Get all program breakpoints.
    pub fn program_breakpoints(&self) -> &BTreeMap<(String, u64), LogicalBreakpoint> {
        &self.program_breakpoints
    }

    /// Get or create a trace breakpoint set.
    pub fn trace_set_mut(&mut self, trace_key: &str) -> &mut TraceBreakpointSet {
        self.trace_sets
            .entry(trace_key.to_string())
            .or_insert_with(|| TraceBreakpointSet::new(trace_key))
    }

    /// Get a trace breakpoint set.
    pub fn trace_set(&self, trace_key: &str) -> Option<&TraceBreakpointSet> {
        self.trace_sets.get(trace_key)
    }

    /// Remove a trace breakpoint set.
    pub fn remove_trace_set(&mut self, trace_key: &str) -> Option<TraceBreakpointSet> {
        self.trace_sets.remove(trace_key)
    }

    /// Get all trace keys that have breakpoint sets.
    pub fn trace_keys(&self) -> Vec<&String> {
        self.trace_sets.keys().collect()
    }

    /// Toggle a breakpoint's enabled state.
    pub fn toggle_breakpoint(&mut self, program_key: &str, address: u64) {
        if let Some(bp) = self
            .program_breakpoints
            .get_mut(&(program_key.to_string(), address))
        {
            if bp.is_enabled() {
                bp.state = BreakpointState::DISABLED;
            } else {
                bp.state = BreakpointState::ENABLED;
            }
        }
    }

    /// The total number of program breakpoints.
    pub fn total_program_breakpoints(&self) -> usize {
        self.program_breakpoints.len()
    }

    /// Begin a synchronization pass.
    pub fn begin_synchronize(&mut self) {
        self.synchronizing = true;
    }

    /// End a synchronization pass.
    pub fn end_synchronize(&mut self) {
        self.synchronizing = false;
    }

    /// Whether a synchronization pass is in progress.
    pub fn is_synchronizing(&self) -> bool {
        self.synchronizing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_action_set() {
        let mut set = BreakpointActionSet::new();
        assert!(set.is_empty());

        set.push(BreakpointActionItem::PlaceTarget);
        set.push(BreakpointActionItem::PlaceTarget); // duplicate
        assert_eq!(set.items().len(), 1);
        assert!(set.contains(&BreakpointActionItem::PlaceTarget));

        set.push(BreakpointActionItem::EnableTarget);
        assert_eq!(set.items().len(), 2);
    }

    #[test]
    fn test_breakpoint_action_set_merge() {
        let mut a = BreakpointActionSet::new();
        a.push(BreakpointActionItem::PlaceTarget);

        let mut b = BreakpointActionSet::new();
        b.push(BreakpointActionItem::PlaceEmu);
        b.push(BreakpointActionItem::PlaceTarget); // duplicate with a

        a.merge(&b);
        assert_eq!(a.items().len(), 2);
    }

    #[test]
    fn test_trace_breakpoint_set() {
        let mut set = TraceBreakpointSet::new("trace1");
        assert!(set.is_empty());

        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        set.insert(bp);
        assert_eq!(set.len(), 1);

        let bp = set.get("0x400000").unwrap();
        assert!(bp.is_enabled());

        let enabled = set.enabled();
        assert_eq!(enabled.len(), 1);

        let removed = set.remove("0x400000");
        assert!(removed.is_some());
        assert!(set.is_empty());
    }

    #[test]
    fn test_trace_breakpoint_set_enable_disable_all() {
        let mut set = TraceBreakpointSet::new("trace1");
        set.insert(LogicalBreakpoint::new(0x1000, "0x1000"));
        set.insert(LogicalBreakpoint::new(0x2000, "0x2000"));

        assert_eq!(set.enabled().len(), 2);

        set.disable_all();
        assert_eq!(set.enabled().len(), 0);
        assert_eq!(set.disabled().len(), 2);

        set.enable_all();
        assert_eq!(set.enabled().len(), 2);
    }

    #[test]
    fn test_trace_breakpoint_set_clear() {
        let mut set = TraceBreakpointSet::new("trace1");
        set.insert(LogicalBreakpoint::new(0x1000, "0x1000"));
        set.insert(LogicalBreakpoint::new(0x2000, "0x2000"));
        set.clear();
        assert!(set.is_empty());
    }

    #[test]
    fn test_trace_breakpoint_set_sync_actions() {
        let mut set = TraceBreakpointSet::new("trace1");
        set.insert(LogicalBreakpoint::new(0x1000, "0x1000"));

        let actions = set.compute_sync_actions(true);
        assert_eq!(actions.len(), 1);
        assert!(actions[0].1.contains(&BreakpointActionItem::PlaceTarget));

        let actions = set.compute_sync_actions(false);
        assert_eq!(actions.len(), 0);
    }

    #[test]
    fn test_trace_breakpoint_set_all_iter() {
        let mut set = TraceBreakpointSet::new("trace1");
        set.insert(LogicalBreakpoint::new(0x1000, "0x1000"));
        set.insert(LogicalBreakpoint::new(0x2000, "0x2000"));

        let all: Vec<_> = set.all().collect();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_breakpoint_manager_add_remove() {
        let mut mgr = LogicalBreakpointManager::new();
        mgr.add_program_breakpoint(
            "prog1",
            0x400000,
            "0x400000",
            vec![TraceBreakpointKind::HwExecute],
        );

        assert_eq!(mgr.total_program_breakpoints(), 1);

        let removed = mgr.remove_program_breakpoint("prog1", 0x400000);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().offset, 0x400000);
        assert_eq!(mgr.total_program_breakpoints(), 0);
    }

    #[test]
    fn test_breakpoint_manager_toggle() {
        let mut mgr = LogicalBreakpointManager::new();
        mgr.add_program_breakpoint("prog1", 0x400000, "0x400000", vec![]);

        let bp = mgr.program_breakpoints().get(&("prog1".into(), 0x400000)).unwrap();
        assert!(bp.is_enabled());

        mgr.toggle_breakpoint("prog1", 0x400000);
        let bp = mgr.program_breakpoints().get(&("prog1".into(), 0x400000)).unwrap();
        assert!(!bp.is_enabled());

        mgr.toggle_breakpoint("prog1", 0x400000);
        let bp = mgr.program_breakpoints().get(&("prog1".into(), 0x400000)).unwrap();
        assert!(bp.is_enabled());
    }

    #[test]
    fn test_breakpoint_manager_trace_sets() {
        let mut mgr = LogicalBreakpointManager::new();
        let set = mgr.trace_set_mut("trace1");
        set.insert(LogicalBreakpoint::new(0x1000, "0x1000"));

        let set = mgr.trace_set("trace1").unwrap();
        assert_eq!(set.len(), 1);

        let removed = mgr.remove_trace_set("trace1");
        assert!(removed.is_some());
        assert!(mgr.trace_set("trace1").is_none());
    }

    #[test]
    fn test_breakpoint_manager_trace_keys() {
        let mut mgr = LogicalBreakpointManager::new();
        mgr.trace_set_mut("t1");
        mgr.trace_set_mut("t2");
        mgr.trace_set_mut("t3");

        let keys = mgr.trace_keys();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&&"t1".to_string()));
        assert!(keys.contains(&&"t2".to_string()));
    }

    #[test]
    fn test_breakpoint_manager_synchronize() {
        let mut mgr = LogicalBreakpointManager::new();
        assert!(!mgr.is_synchronizing());
        mgr.begin_synchronize();
        assert!(mgr.is_synchronizing());
        mgr.end_synchronize();
        assert!(!mgr.is_synchronizing());
    }

    #[test]
    fn test_program_breakpoint_serialization() {
        let bp = ProgramBreakpoint {
            logical: LogicalBreakpoint::new(0x400000, "0x400000"),
            program_key: "prog1".into(),
            address: 0x400000,
        };
        let json = serde_json::to_string(&bp).unwrap();
        let back: ProgramBreakpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back.address, 0x400000);
        assert_eq!(back.program_key, "prog1");
    }

    #[test]
    fn test_breakpoint_action_item_serialization() {
        let item = BreakpointActionItem::PlaceTarget;
        let json = serde_json::to_string(&item).unwrap();
        let back: BreakpointActionItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back, BreakpointActionItem::PlaceTarget);
    }

    #[test]
    fn test_multiple_programs() {
        let mut mgr = LogicalBreakpointManager::new();
        mgr.add_program_breakpoint("prog1", 0x1000, "0x1000", vec![]);
        mgr.add_program_breakpoint("prog1", 0x2000, "0x2000", vec![]);
        mgr.add_program_breakpoint("prog2", 0x1000, "0x1000", vec![]);

        assert_eq!(mgr.total_program_breakpoints(), 3);

        mgr.remove_program_breakpoint("prog1", 0x1000);
        assert_eq!(mgr.total_program_breakpoints(), 2);
    }
}
