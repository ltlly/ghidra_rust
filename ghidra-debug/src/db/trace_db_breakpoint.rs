//! Database-backed breakpoint location and specification management.
//!
//! Ported from Ghidra's `ghidra.trace.database.breakpoint` package in
//! Framework-TraceModeling. Provides `DBTraceBreakpointLocation`,
//! `DBTraceBreakpointSpec`, and `DBTraceBreakpointManager` backed by
//! SQLite storage.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    breakpoint::TraceBreakpointKind, BreakpointKindSet, Lifespan,
};

/// A breakpoint location in the database, representing a placed breakpoint
/// at a specific address range.
///
/// Ported from Ghidra's `DBTraceBreakpointLocation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceBreakpointLocation {
    /// Unique key for this breakpoint location.
    pub key: i64,
    /// The canonical path of this breakpoint in the target object tree.
    pub path: String,
    /// The snap range during which this location is active.
    pub lifespan: Lifespan,
    /// Start address offset.
    pub min_address: u64,
    /// End address offset.
    pub max_address: u64,
    /// The address space name (e.g., "ram", "register").
    pub space_name: String,
    /// Display name for this location.
    pub display_name: String,
    /// Whether this location is enabled.
    pub enabled: bool,
    /// Whether emulation is enabled for this location.
    pub emu_enabled: bool,
    /// Sleigh expression for emulation conditional break.
    pub emu_sleigh: String,
    /// Comment text.
    pub comment: String,
    /// Reference to the parent specification key.
    pub spec_key: Option<i64>,
}

impl DbTraceBreakpointLocation {
    /// Create a new breakpoint location.
    pub fn new(
        key: i64,
        path: impl Into<String>,
        lifespan: Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> Self {
        Self {
            key,
            path: path.into(),
            lifespan,
            min_address,
            max_address,
            space_name: String::from("ram"),
            display_name: String::new(),
            enabled: true,
            emu_enabled: true,
            emu_sleigh: String::new(),
            comment: String::new(),
            spec_key: None,
        }
    }

    /// The length of the breakpoint range in bytes.
    pub fn length(&self) -> u64 {
        if self.max_address >= self.min_address {
            self.max_address - self.min_address + 1
        } else {
            0
        }
    }

    /// Check if the breakpoint is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// Check if this breakpoint overlaps the given address at the given snap.
    pub fn contains_address(&self, snap: i64, address: u64) -> bool {
        self.is_valid_at(snap) && address >= self.min_address && address <= self.max_address
    }

    /// Check if this breakpoint intersects the given address range.
    pub fn intersects_range(&self, min_addr: u64, max_addr: u64) -> bool {
        self.min_address <= max_addr && self.max_address >= min_addr
    }

    /// Set the display name for a given lifespan.
    pub fn set_name(&mut self, lifespan: Lifespan, name: impl Into<String>) {
        self.lifespan = lifespan;
        self.display_name = name.into();
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Set the comment.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = comment.into();
    }

    /// Set the emulation Sleigh expression.
    pub fn set_emu_sleigh(&mut self, sleigh: impl Into<String>) {
        self.emu_sleigh = sleigh.into();
    }
}

/// A breakpoint specification in the database, defining the logical intent
/// of a breakpoint before it is placed at specific locations.
///
/// Ported from Ghidra's `DBTraceBreakpointSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceBreakpointSpec {
    /// Unique key for this breakpoint specification.
    pub key: i64,
    /// The canonical path in the target object tree.
    pub path: String,
    /// The snap range during which this spec is active.
    pub lifespan: Lifespan,
    /// Display name.
    pub display_name: String,
    /// The kinds of breakpoint (read, write, execute).
    pub kinds: BreakpointKindSet,
    /// Whether this spec is enabled.
    pub enabled: bool,
    /// Sleigh expression for the breakpoint condition.
    pub expression: String,
    /// Comment text.
    pub comment: String,
    /// Keys of the associated location objects.
    pub location_keys: Vec<i64>,
}

impl DbTraceBreakpointSpec {
    /// Create a new breakpoint specification.
    pub fn new(
        key: i64,
        path: impl Into<String>,
        kinds: BreakpointKindSet,
    ) -> Self {
        Self {
            key,
            path: path.into(),
            lifespan: Lifespan::ALL,
            display_name: String::new(),
            kinds,
            enabled: true,
            expression: String::new(),
            comment: String::new(),
            location_keys: Vec::new(),
        }
    }

    /// Whether this spec is a hardware execute breakpoint.
    pub fn is_hardware_execute(&self) -> bool {
        self.kinds.contains(&TraceBreakpointKind::HwExecute)
    }

    /// Whether this spec is a software execute breakpoint.
    pub fn is_software_execute(&self) -> bool {
        self.kinds.contains(&TraceBreakpointKind::SwExecute)
    }

    /// Whether this spec is a read/write watchpoint.
    pub fn is_watchpoint(&self) -> bool {
        self.kinds.contains(&TraceBreakpointKind::Read)
            || self.kinds.contains(&TraceBreakpointKind::Write)
    }

    /// Set the kinds for a given lifespan.
    pub fn set_kinds(&mut self, lifespan: Lifespan, kinds: BreakpointKindSet) {
        self.lifespan = lifespan;
        self.kinds = kinds;
    }

    /// Set the enabled state for a given lifespan.
    pub fn set_enabled(&mut self, lifespan: Lifespan, enabled: bool) {
        self.lifespan = lifespan;
        self.enabled = enabled;
    }

    /// Check if this spec is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// Get the enabled state at a given snap.
    pub fn is_enabled_at(&self, snap: i64) -> bool {
        self.is_valid_at(snap) && self.enabled
    }
}

/// The database-backed breakpoint manager.
///
/// Manages all breakpoint specifications and locations in a trace database.
/// Ported from Ghidra's `DBTraceBreakpointManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbTraceBreakpointManager {
    next_key: i64,
    /// All breakpoint specifications, keyed by spec key.
    specs: BTreeMap<i64, DbTraceBreakpointSpec>,
    /// All breakpoint locations, keyed by location key.
    locations: BTreeMap<i64, DbTraceBreakpointLocation>,
}

impl DbTraceBreakpointManager {
    /// Create a new empty breakpoint manager.
    pub fn new() -> Self {
        Self::default()
    }

    fn allocate_key(&mut self) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        key
    }

    /// Add a breakpoint location.
    pub fn add_location(
        &mut self,
        path: impl Into<String>,
        lifespan: Lifespan,
        min_address: u64,
        max_address: u64,
        kinds: &BreakpointKindSet,
        enabled: bool,
        comment: impl Into<String>,
    ) -> &DbTraceBreakpointLocation {
        let key = self.allocate_key();
        let path_str = path.into();

        // Find or create a matching spec
        let spec_key = self.find_or_create_spec(&path_str, kinds.clone());

        let mut loc = DbTraceBreakpointLocation::new(key, path_str, lifespan, min_address, max_address);
        loc.enabled = enabled;
        loc.comment = comment.into();
        loc.spec_key = Some(spec_key);

        // Link location to spec
        if let Some(spec) = self.specs.get_mut(&spec_key) {
            spec.location_keys.push(key);
        }

        self.locations.insert(key, loc);
        self.locations.get(&key).unwrap()
    }

    fn find_or_create_spec(&mut self, path: &str, kinds: BreakpointKindSet) -> i64 {
        // Look for an existing spec with the same path prefix
        for (key, spec) in &self.specs {
            if path.starts_with(&spec.path) && spec.kinds == kinds {
                return *key;
            }
        }
        // Create a new spec
        let key = self.allocate_key();
        let spec = DbTraceBreakpointSpec::new(key, path, kinds);
        self.specs.insert(key, spec);
        key
    }

    /// Get all breakpoint specifications.
    pub fn all_specs(&self) -> impl Iterator<Item = &DbTraceBreakpointSpec> {
        self.specs.values()
    }

    /// Get all breakpoint locations.
    pub fn all_locations(&self) -> impl Iterator<Item = &DbTraceBreakpointLocation> {
        self.locations.values()
    }

    /// Get a breakpoint specification by key.
    pub fn get_spec(&self, key: i64) -> Option<&DbTraceBreakpointSpec> {
        self.specs.get(&key)
    }

    /// Get a breakpoint location by key.
    pub fn get_location(&self, key: i64) -> Option<&DbTraceBreakpointLocation> {
        self.locations.get(&key)
    }

    /// Get all breakpoint specs at a given path.
    pub fn specs_by_path(&self, path: &str) -> Vec<&DbTraceBreakpointSpec> {
        self.specs.values().filter(|s| s.path == path).collect()
    }

    /// Get all breakpoint locations at a given path.
    pub fn locations_by_path(&self, path: &str) -> Vec<&DbTraceBreakpointLocation> {
        self.locations.values().filter(|l| l.path == path).collect()
    }

    /// Get all breakpoint locations containing the given address at a given snap.
    pub fn breakpoints_at(&self, snap: i64, address: u64) -> Vec<&DbTraceBreakpointLocation> {
        self.locations
            .values()
            .filter(|l| l.contains_address(snap, address))
            .collect()
    }

    /// Get all breakpoint locations intersecting the given address range.
    pub fn breakpoints_intersecting(
        &self,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<&DbTraceBreakpointLocation> {
        self.locations
            .values()
            .filter(|l| l.intersects_range(min_addr, max_addr))
            .collect()
    }

    /// Delete a breakpoint location by key.
    pub fn delete_location(&mut self, key: i64) -> bool {
        if let Some(loc) = self.locations.remove(&key) {
            // Remove from parent spec
            if let Some(spec_key) = loc.spec_key {
                if let Some(spec) = self.specs.get_mut(&spec_key) {
                    spec.location_keys.retain(|&k| k != key);
                }
            }
            true
        } else {
            false
        }
    }

    /// Delete a breakpoint specification and all its locations.
    pub fn delete_spec(&mut self, key: i64) -> bool {
        if let Some(spec) = self.specs.remove(&key) {
            for loc_key in &spec.location_keys {
                self.locations.remove(loc_key);
            }
            true
        } else {
            false
        }
    }

    /// Toggle a breakpoint location's enabled state.
    pub fn toggle_location(&mut self, key: i64, enabled: bool) -> bool {
        if let Some(loc) = self.locations.get_mut(&key) {
            loc.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// The total number of breakpoint locations.
    pub fn location_count(&self) -> usize {
        self.locations.len()
    }

    /// The total number of breakpoint specs.
    pub fn spec_count(&self) -> usize {
        self.specs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_location_creation() {
        let loc = DbTraceBreakpointLocation::new(
            1,
            "/Threads/0/Breakpoints/test",
            Lifespan::ALL,
            0x400000,
            0x400000,
        );
        assert_eq!(loc.key, 1);
        assert_eq!(loc.length(), 1);
        assert!(loc.enabled);
        assert!(loc.is_valid_at(0));
        assert!(loc.contains_address(0, 0x400000));
        assert!(!loc.contains_address(0, 0x500000));
    }

    #[test]
    fn test_breakpoint_location_range() {
        let loc = DbTraceBreakpointLocation::new(
            1,
            "/test",
            Lifespan::span(0, 100),
            0x1000,
            0x100f,
        );
        assert_eq!(loc.length(), 16);
        assert!(loc.is_valid_at(50));
        assert!(!loc.is_valid_at(200));
        assert!(loc.intersects_range(0x1005, 0x1020));
        assert!(!loc.intersects_range(0x2000, 0x3000));
    }

    #[test]
    fn test_breakpoint_spec_creation() {
        let mut kinds = BTreeSet::new();
        kinds.insert(TraceBreakpointKind::SwExecute);
        let spec = DbTraceBreakpointSpec::new(1, "/Threads/0", kinds);
        assert!(spec.is_software_execute());
        assert!(!spec.is_hardware_execute());
        assert!(!spec.is_watchpoint());
    }

    #[test]
    fn test_breakpoint_spec_watchpoint() {
        let mut kinds = BTreeSet::new();
        kinds.insert(TraceBreakpointKind::Read);
        kinds.insert(TraceBreakpointKind::Write);
        let spec = DbTraceBreakpointSpec::new(1, "/test", kinds);
        assert!(spec.is_watchpoint());
        assert!(!spec.is_software_execute());
    }

    #[test]
    fn test_breakpoint_manager_add_location() {
        let mut mgr = DbTraceBreakpointManager::new();
        let mut kinds = BTreeSet::new();
        kinds.insert(TraceBreakpointKind::SwExecute);

        mgr.add_location(
            "/test/bp1",
            Lifespan::ALL,
            0x400000,
            0x400000,
            &kinds,
            true,
            "test breakpoint",
        );

        assert_eq!(mgr.location_count(), 1);
        assert_eq!(mgr.spec_count(), 1);

        let locs = mgr.breakpoints_at(0, 0x400000);
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].comment, "test breakpoint");
    }

    #[test]
    fn test_breakpoint_manager_queries() {
        let mut mgr = DbTraceBreakpointManager::new();
        let mut kinds = BTreeSet::new();
        kinds.insert(TraceBreakpointKind::SwExecute);

        mgr.add_location("/bp1", Lifespan::ALL, 0x400000, 0x400000, &kinds, true, "");
        mgr.add_location("/bp2", Lifespan::ALL, 0x400100, 0x400100, &kinds, true, "");

        assert_eq!(mgr.breakpoints_at(0, 0x400000).len(), 1);
        assert_eq!(mgr.breakpoints_at(0, 0x400100).len(), 1);
        assert_eq!(mgr.breakpoints_at(0, 0x500000).len(), 0);

        let intersecting = mgr.breakpoints_intersecting(0x400000, 0x400050);
        assert_eq!(intersecting.len(), 1);
    }

    #[test]
    fn test_breakpoint_manager_delete() {
        let mut mgr = DbTraceBreakpointManager::new();
        let mut kinds = BTreeSet::new();
        kinds.insert(TraceBreakpointKind::SwExecute);

        mgr.add_location("/bp1", Lifespan::ALL, 0x400000, 0x400000, &kinds, true, "");
        assert_eq!(mgr.location_count(), 1);

        // Get the key of the first location
        let key = mgr.locations.values().next().unwrap().key;
        assert!(mgr.delete_location(key));
        assert_eq!(mgr.location_count(), 0);
    }

    #[test]
    fn test_breakpoint_manager_toggle() {
        let mut mgr = DbTraceBreakpointManager::new();
        let mut kinds = BTreeSet::new();
        kinds.insert(TraceBreakpointKind::SwExecute);

        mgr.add_location("/bp1", Lifespan::ALL, 0x400000, 0x400000, &kinds, true, "");
        let key = mgr.locations.values().next().unwrap().key;

        assert!(mgr.toggle_location(key, false));
        let loc = mgr.get_location(key).unwrap();
        assert!(!loc.enabled);

        assert!(mgr.toggle_location(key, true));
        let loc = mgr.get_location(key).unwrap();
        assert!(loc.enabled);
    }

    #[test]
    fn test_breakpoint_specs_by_path() {
        let mut mgr = DbTraceBreakpointManager::new();
        let mut kinds = BTreeSet::new();
        kinds.insert(TraceBreakpointKind::SwExecute);

        mgr.add_location("/Threads/0/bp", Lifespan::ALL, 0x400000, 0x400000, &kinds, true, "");
        let specs = mgr.specs_by_path("/Threads/0/bp");
        assert_eq!(specs.len(), 1);
    }
}
