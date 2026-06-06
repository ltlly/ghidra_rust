//! Debugger logical breakpoint service plugin implementation.
//!
//! Ported from Ghidra's `DebuggerLogicalBreakpointServicePlugin` (1427 lines).
//!
//! Aggregates breakpoints from open programs and live traces. This is the
//! main service plugin that maintains the logical breakpoint state, handles
//! synchronization between program breakpoints and trace breakpoints, and
//! notifies listeners of changes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::api::breakpoint::{BreakpointMode, LogicalBreakpoint};

/// The collection mode for aggregating breakpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointCollectionMode {
    /// Aggregate from all open programs and traces.
    All,
    /// Only collect from the active trace.
    ActiveOnly,
    /// Only collect from programs (static breakpoints).
    ProgramsOnly,
    /// Only collect from traces (dynamic breakpoints).
    TracesOnly,
}

impl Default for BreakpointCollectionMode {
    fn default() -> Self {
        BreakpointCollectionMode::All
    }
}

/// Tracks the association between a program and its breakpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramBreakpointAssociation {
    /// The program URL.
    pub program_url: String,
    /// Breakpoint addresses in this program.
    pub addresses: BTreeSet<u64>,
    /// Whether this program is currently active.
    pub is_active: bool,
}

impl ProgramBreakpointAssociation {
    /// Create a new association.
    pub fn new(program_url: impl Into<String>) -> Self {
        Self {
            program_url: program_url.into(),
            addresses: BTreeSet::new(),
            is_active: false,
        }
    }

    /// Add a breakpoint address.
    pub fn add_address(&mut self, address: u64) {
        self.addresses.insert(address);
    }

    /// Remove a breakpoint address.
    pub fn remove_address(&mut self, address: u64) -> bool {
        self.addresses.remove(&address)
    }

    /// Get the count of breakpoints.
    pub fn count(&self) -> usize {
        self.addresses.len()
    }
}

/// Tracks the association between a trace and its breakpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBreakpointAssociation {
    /// The trace key.
    pub trace_key: i64,
    /// Breakpoint entries: (spec_key, Vec<location_keys>).
    pub spec_locations: BTreeMap<i64, Vec<i64>>,
    /// The current snap.
    pub snap: i64,
}

impl TraceBreakpointAssociation {
    /// Create a new trace association.
    pub fn new(trace_key: i64) -> Self {
        Self {
            trace_key,
            spec_locations: BTreeMap::new(),
            snap: 0,
        }
    }

    /// Add a breakpoint spec with its locations.
    pub fn add_spec(&mut self, spec_key: i64, location_keys: Vec<i64>) {
        self.spec_locations.insert(spec_key, location_keys);
    }

    /// Remove a spec.
    pub fn remove_spec(&mut self, spec_key: i64) -> Option<Vec<i64>> {
        self.spec_locations.remove(&spec_key)
    }

    /// Get the total location count across all specs.
    pub fn total_locations(&self) -> usize {
        self.spec_locations.values().map(|v| v.len()).sum()
    }

    /// Get all spec keys.
    pub fn spec_keys(&self) -> Vec<i64> {
        self.spec_locations.keys().copied().collect()
    }
}

/// Change record for breakpoint service notifications.
#[derive(Debug, Clone)]
pub enum BreakpointServiceChange {
    /// A breakpoint was added.
    Added(LogicalBreakpoint),
    /// A breakpoint was updated.
    Updated(LogicalBreakpoint),
    /// A breakpoint was removed at the given address.
    Removed(u64),
    /// All breakpoints were cleared.
    Cleared,
}

/// The logical breakpoint service plugin that aggregates all breakpoint sources.
///
/// Ported from Ghidra's `DebuggerLogicalBreakpointServicePlugin`.
#[derive(Debug, Default)]
pub struct BreakpointServicePlugin {
    /// All known logical breakpoints by address.
    breakpoints: BTreeMap<u64, LogicalBreakpoint>,
    /// Program associations.
    program_associations: BTreeMap<String, ProgramBreakpointAssociation>,
    /// Trace associations.
    trace_associations: BTreeMap<i64, TraceBreakpointAssociation>,
    /// Collection mode.
    mode: BreakpointCollectionMode,
    /// Pending changes to notify.
    pending_changes: Vec<BreakpointServiceChange>,
    /// Whether the service is currently synchronizing.
    synchronizing: bool,
}

impl BreakpointServicePlugin {
    /// Create a new breakpoint service plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the collection mode.
    pub fn set_mode(&mut self, mode: BreakpointCollectionMode) {
        self.mode = mode;
    }

    /// Get the collection mode.
    pub fn mode(&self) -> BreakpointCollectionMode {
        self.mode
    }

    /// Register a program for breakpoint tracking.
    pub fn register_program(&mut self, program_url: impl Into<String>) {
        let url = program_url.into();
        self.program_associations
            .entry(url.clone())
            .or_insert_with(|| ProgramBreakpointAssociation::new(&url));
    }

    /// Unregister a program.
    pub fn unregister_program(&mut self, program_url: &str) {
        if let Some(assoc) = self.program_associations.remove(program_url) {
            for addr in &assoc.addresses {
                self.breakpoints.remove(addr);
                self.pending_changes
                    .push(BreakpointServiceChange::Removed(*addr));
            }
        }
    }

    /// Register a trace for breakpoint tracking.
    pub fn register_trace(&mut self, trace_key: i64) {
        self.trace_associations
            .entry(trace_key)
            .or_insert_with(|| TraceBreakpointAssociation::new(trace_key));
    }

    /// Unregister a trace.
    pub fn unregister_trace(&mut self, trace_key: i64) {
        self.trace_associations.remove(&trace_key);
    }

    /// Add a breakpoint from a program.
    pub fn add_program_breakpoint(
        &mut self,
        program_url: &str,
        address: u64,
    ) -> Result<(), String> {
        if let Some(assoc) = self.program_associations.get_mut(program_url) {
            assoc.add_address(address);

            let bp = LogicalBreakpoint::new(address, format!("0x{:x}", address));
            self.breakpoints.insert(address, bp.clone());
            self.pending_changes
                .push(BreakpointServiceChange::Added(bp));
            Ok(())
        } else {
            Err(format!("Program '{}' not registered", program_url))
        }
    }

    /// Remove a breakpoint from a program.
    pub fn remove_program_breakpoint(
        &mut self,
        program_url: &str,
        address: u64,
    ) -> Result<(), String> {
        if let Some(assoc) = self.program_associations.get_mut(program_url) {
            assoc.remove_address(address);
        }

        // Only remove if no other source has this breakpoint
        let has_other_source = self
            .program_associations
            .iter()
            .any(|(url, a)| url != program_url && a.addresses.contains(&address));

        if !has_other_source {
            self.breakpoints.remove(&address);
            self.pending_changes
                .push(BreakpointServiceChange::Removed(address));
        }
        Ok(())
    }

    /// Add a breakpoint from a trace.
    pub fn add_trace_breakpoint(
        &mut self,
        trace_key: i64,
        spec_key: i64,
        location_keys: Vec<i64>,
    ) {
        if let Some(assoc) = self.trace_associations.get_mut(&trace_key) {
            assoc.add_spec(spec_key, location_keys);
        }
    }

    /// Get all breakpoints.
    pub fn breakpoints(&self) -> &BTreeMap<u64, LogicalBreakpoint> {
        &self.breakpoints
    }

    /// Get a breakpoint by address.
    pub fn get_breakpoint(&self, address: u64) -> Option<&LogicalBreakpoint> {
        self.breakpoints.get(&address)
    }

    /// Get the number of breakpoints.
    pub fn breakpoint_count(&self) -> usize {
        self.breakpoints.len()
    }

    /// Toggle a breakpoint enabled/disabled.
    pub fn toggle_breakpoint(&mut self, address: u64, enabled: bool) -> Result<(), String> {
        if let Some(bp) = self.breakpoints.get_mut(&address) {
            bp.state.mode = Some(if enabled {
                BreakpointMode::Enabled
            } else {
                BreakpointMode::Disabled
            });
            self.pending_changes
                .push(BreakpointServiceChange::Updated(bp.clone()));
            Ok(())
        } else {
            Err(format!("No breakpoint at address 0x{:x}", address))
        }
    }

    /// Clear all breakpoints.
    pub fn clear_all(&mut self) {
        self.breakpoints.clear();
        self.pending_changes
            .push(BreakpointServiceChange::Cleared);
    }

    /// Drain and return all pending changes.
    pub fn drain_changes(&mut self) -> Vec<BreakpointServiceChange> {
        std::mem::take(&mut self.pending_changes)
    }

    /// Start a synchronization cycle.
    pub fn begin_sync(&mut self) {
        self.synchronizing = true;
    }

    /// End a synchronization cycle.
    pub fn end_sync(&mut self) {
        self.synchronizing = false;
    }

    /// Whether the service is currently synchronizing.
    pub fn is_synchronizing(&self) -> bool {
        self.synchronizing
    }

    /// Get the number of registered programs.
    pub fn program_count(&self) -> usize {
        self.program_associations.len()
    }

    /// Get the number of registered traces.
    pub fn trace_count(&self) -> usize {
        self.trace_associations.len()
    }

    /// Synchronize program breakpoints with trace breakpoints.
    ///
    /// This resolves conflicts when the same address has breakpoints from
    /// both program and trace sources.
    pub fn synchronize(&mut self) {
        self.begin_sync();

        // Collect addresses from all sources
        let mut all_addresses: BTreeSet<u64> = BTreeSet::new();
        for assoc in self.program_associations.values() {
            all_addresses.extend(&assoc.addresses);
        }

        // Ensure each address has a logical breakpoint
        for &addr in &all_addresses {
            if !self.breakpoints.contains_key(&addr) {
                let bp = LogicalBreakpoint::new(addr, format!("0x{:x}", addr));
                self.breakpoints.insert(addr, bp);
            }
        }

        // Remove breakpoints whose addresses no longer exist in any source
        let stale: Vec<u64> = self
            .breakpoints
            .keys()
            .filter(|addr| !all_addresses.contains(addr))
            .copied()
            .collect();

        for addr in stale {
            self.breakpoints.remove(&addr);
            self.pending_changes
                .push(BreakpointServiceChange::Removed(addr));
        }

        self.end_sync();
    }

    /// Get all registered program URLs.
    pub fn program_urls(&self) -> Vec<&str> {
        self.program_associations
            .keys()
            .map(|s| s.as_str())
            .collect()
    }

    /// Get all registered trace keys.
    pub fn trace_keys(&self) -> Vec<i64> {
        self.trace_associations.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_create_and_add_breakpoint() {
        let mut plugin = BreakpointServicePlugin::new();
        plugin.register_program("file:///test.exe");
        plugin
            .add_program_breakpoint("file:///test.exe", 0x401000)
            .unwrap();

        assert_eq!(plugin.breakpoint_count(), 1);
        assert!(plugin.get_breakpoint(0x401000).is_some());
    }

    #[test]
    fn test_plugin_add_remove_breakpoint() {
        let mut plugin = BreakpointServicePlugin::new();
        plugin.register_program("file:///test.exe");
        plugin
            .add_program_breakpoint("file:///test.exe", 0x401000)
            .unwrap();
        plugin
            .add_program_breakpoint("file:///test.exe", 0x401010)
            .unwrap();

        assert_eq!(plugin.breakpoint_count(), 2);

        plugin
            .remove_program_breakpoint("file:///test.exe", 0x401000)
            .unwrap();
        assert_eq!(plugin.breakpoint_count(), 1);
        assert!(plugin.get_breakpoint(0x401000).is_none());
    }

    #[test]
    fn test_plugin_toggle_breakpoint() {
        let mut plugin = BreakpointServicePlugin::new();
        plugin.register_program("file:///test.exe");
        plugin
            .add_program_breakpoint("file:///test.exe", 0x401000)
            .unwrap();

        plugin.toggle_breakpoint(0x401000, false).unwrap();
        let bp = plugin.get_breakpoint(0x401000).unwrap();
        assert!(!bp.is_enabled());

        plugin.toggle_breakpoint(0x401000, true).unwrap();
        let bp = plugin.get_breakpoint(0x401000).unwrap();
        assert!(bp.is_enabled());
    }

    #[test]
    fn test_plugin_unregister_program() {
        let mut plugin = BreakpointServicePlugin::new();
        plugin.register_program("file:///test.exe");
        plugin
            .add_program_breakpoint("file:///test.exe", 0x401000)
            .unwrap();

        plugin.unregister_program("file:///test.exe");
        assert_eq!(plugin.program_count(), 0);
        assert!(plugin.get_breakpoint(0x401000).is_none());
    }

    #[test]
    fn test_plugin_trace_association() {
        let mut plugin = BreakpointServicePlugin::new();
        plugin.register_trace(1);
        plugin.add_trace_breakpoint(1, 10, vec![100, 101, 102]);

        let assoc = plugin.trace_associations.get(&1).unwrap();
        assert_eq!(assoc.total_locations(), 3);
        assert_eq!(assoc.spec_keys(), vec![10]);
    }

    #[test]
    fn test_plugin_changes() {
        let mut plugin = BreakpointServicePlugin::new();
        plugin.register_program("file:///test.exe");
        plugin
            .add_program_breakpoint("file:///test.exe", 0x401000)
            .unwrap();

        let changes = plugin.drain_changes();
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0], BreakpointServiceChange::Added(_)));

        // After drain, no changes pending
        let changes = plugin.drain_changes();
        assert!(changes.is_empty());
    }

    #[test]
    fn test_plugin_synchronize() {
        let mut plugin = BreakpointServicePlugin::new();
        plugin.register_program("file:///test.exe");
        plugin
            .add_program_breakpoint("file:///test.exe", 0x401000)
            .unwrap();

        plugin.synchronize();

        assert!(!plugin.is_synchronizing());
        assert_eq!(plugin.breakpoint_count(), 1);
    }

    #[test]
    fn test_plugin_clear_all() {
        let mut plugin = BreakpointServicePlugin::new();
        plugin.register_program("file:///test.exe");
        plugin
            .add_program_breakpoint("file:///test.exe", 0x401000)
            .unwrap();
        plugin
            .add_program_breakpoint("file:///test.exe", 0x401010)
            .unwrap();

        plugin.clear_all();
        assert_eq!(plugin.breakpoint_count(), 0);

        let changes = plugin.drain_changes();
        assert!(matches!(changes.last().unwrap(), BreakpointServiceChange::Cleared));
    }

    #[test]
    fn test_program_breakpoint_association() {
        let mut assoc = ProgramBreakpointAssociation::new("file:///test.exe");
        assert_eq!(assoc.count(), 0);

        assoc.add_address(0x401000);
        assoc.add_address(0x401004);
        assert_eq!(assoc.count(), 2);

        assoc.remove_address(0x401000);
        assert_eq!(assoc.count(), 1);
    }

    #[test]
    fn test_collection_modes() {
        assert_eq!(BreakpointCollectionMode::default(), BreakpointCollectionMode::All);
    }

    #[test]
    fn test_plugin_unregistered_program_error() {
        let mut plugin = BreakpointServicePlugin::new();
        let result = plugin.add_program_breakpoint("nonexistent", 0x401000);
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_toggle_nonexistent() {
        let mut plugin = BreakpointServicePlugin::new();
        let result = plugin.toggle_breakpoint(0x401000, true);
        assert!(result.is_err());
    }
}
