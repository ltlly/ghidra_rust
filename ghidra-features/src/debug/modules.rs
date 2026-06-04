//! Module and section model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.modules` — includes [`TraceModule`]
//! and [`TraceSection`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// TraceModule
// ---------------------------------------------------------------------------

/// A binary module loaded by the target and/or debugger.
///
/// Ported from `ghidra.trace.model.modules.TraceModule`. A module also
/// serves as a namespace for its sections.
#[derive(Debug, Clone)]
pub struct TraceModule {
    /// Unique key for this module.
    key: u64,
    /// Time-varying names: (snap_from, name).
    names: BTreeMap<i64, String>,
    /// Time-varying module names (as reported by the target): (snap_from, module_name).
    module_names: BTreeMap<i64, String>,
    /// Time-varying start addresses: (snap_from, address).
    start_addresses: BTreeMap<i64, u64>,
    /// Time-varying end addresses: (snap_from, address).
    end_addresses: BTreeMap<i64, u64>,
    /// The lifespan of this module.
    pub lifespan: Lifespan,
    /// Whether the module has been deleted.
    deleted: bool,
}

impl TraceModule {
    /// Create a new module.
    pub fn new(
        key: u64,
        snap: i64,
        name: impl Into<String>,
        module_name: impl Into<String>,
        start_address: u64,
        end_address: u64,
    ) -> Self {
        let mut names = BTreeMap::new();
        names.insert(snap, name.into());
        let mut mnames = BTreeMap::new();
        mnames.insert(snap, module_name.into());
        let mut starts = BTreeMap::new();
        starts.insert(snap, start_address);
        let mut ends = BTreeMap::new();
        ends.insert(snap, end_address);
        Self {
            key,
            names,
            module_names: mnames,
            start_addresses: starts,
            end_addresses: ends,
            lifespan: Lifespan::now_on(snap),
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Get the display name at the given snapshot.
    pub fn get_name(&self, snap: i64) -> Option<&str> {
        self.names.range(..=snap).next_back().map(|(_, n)| n.as_str())
    }

    /// Set the display name effective from the given snapshot.
    pub fn set_name(&mut self, snap: i64, name: impl Into<String>) {
        self.names.insert(snap, name.into());
    }

    /// Get the module name (path) at the given snapshot.
    pub fn get_module_name(&self, snap: i64) -> Option<&str> {
        self.module_names
            .range(..=snap)
            .next_back()
            .map(|(_, n)| n.as_str())
    }

    /// Set the module name effective from the given snapshot.
    pub fn set_module_name(&mut self, snap: i64, name: impl Into<String>) {
        self.module_names.insert(snap, name.into());
    }

    /// Get the start address at the given snapshot.
    pub fn get_start_address(&self, snap: i64) -> Option<u64> {
        self.start_addresses
            .range(..=snap)
            .next_back()
            .map(|(_, a)| *a)
    }

    /// Get the end address at the given snapshot.
    pub fn get_end_address(&self, snap: i64) -> Option<u64> {
        self.end_addresses
            .range(..=snap)
            .next_back()
            .map(|(_, a)| *a)
    }

    /// Set the address range effective from the given snapshot.
    pub fn set_range(&mut self, snap: i64, start: u64, end: u64) {
        self.start_addresses.insert(snap, start);
        self.end_addresses.insert(snap, end);
    }

    /// Get the length (in bytes) at the given snapshot.
    pub fn get_length(&self, snap: i64) -> Option<u64> {
        let start = self.get_start_address(snap)?;
        let end = self.get_end_address(snap)?;
        Some(end.wrapping_sub(start).wrapping_add(1))
    }

    /// Check if the module contains the given address at the snapshot.
    pub fn contains_address(&self, address: u64, snap: i64) -> bool {
        if let (Some(start), Some(end)) =
            (self.get_start_address(snap), self.get_end_address(snap))
        {
            start <= address && address <= end
        } else {
            false
        }
    }

    /// Remove this module from the given snap onward.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap - 1);
    }

    /// Delete this module.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }
}

// ---------------------------------------------------------------------------
// TraceSection
// ---------------------------------------------------------------------------

/// A section within a module.
///
/// Ported from `ghidra.trace.model.modules.TraceSection`. Sections are
/// children of a module and represent named address ranges (e.g. `.text`,
/// `.data`, `.bss`).
#[derive(Debug, Clone)]
pub struct TraceSection {
    /// Unique key for this section.
    key: u64,
    /// The owning module key.
    pub module_key: u64,
    /// Time-varying names: (snap_from, name).
    names: BTreeMap<i64, String>,
    /// Time-varying start addresses: (snap_from, address).
    start_addresses: BTreeMap<i64, u64>,
    /// Time-varying end addresses: (snap_from, address).
    end_addresses: BTreeMap<i64, u64>,
    /// The lifespan of this section.
    pub lifespan: Lifespan,
    /// Whether the section has been deleted.
    deleted: bool,
}

impl TraceSection {
    /// Create a new section.
    pub fn new(
        key: u64,
        module_key: u64,
        snap: i64,
        name: impl Into<String>,
        start_address: u64,
        end_address: u64,
    ) -> Self {
        let mut names = BTreeMap::new();
        names.insert(snap, name.into());
        let mut starts = BTreeMap::new();
        starts.insert(snap, start_address);
        let mut ends = BTreeMap::new();
        ends.insert(snap, end_address);
        Self {
            key,
            module_key,
            names,
            start_addresses: starts,
            end_addresses: ends,
            lifespan: Lifespan::now_on(snap),
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Get the section name at the given snapshot.
    pub fn get_name(&self, snap: i64) -> Option<&str> {
        self.names.range(..=snap).next_back().map(|(_, n)| n.as_str())
    }

    /// Set the section name effective from the given snapshot.
    pub fn set_name(&mut self, snap: i64, name: impl Into<String>) {
        self.names.insert(snap, name.into());
    }

    /// Get the start address at the given snapshot.
    pub fn get_start_address(&self, snap: i64) -> Option<u64> {
        self.start_addresses
            .range(..=snap)
            .next_back()
            .map(|(_, a)| *a)
    }

    /// Get the end address at the given snapshot.
    pub fn get_end_address(&self, snap: i64) -> Option<u64> {
        self.end_addresses
            .range(..=snap)
            .next_back()
            .map(|(_, a)| *a)
    }

    /// Set the address range effective from the given snapshot.
    pub fn set_range(&mut self, snap: i64, start: u64, end: u64) {
        self.start_addresses.insert(snap, start);
        self.end_addresses.insert(snap, end);
    }

    /// Get the length at the given snapshot.
    pub fn get_length(&self, snap: i64) -> Option<u64> {
        let start = self.get_start_address(snap)?;
        let end = self.get_end_address(snap)?;
        Some(end.wrapping_sub(start).wrapping_add(1))
    }

    /// Check if the section contains the given address at the snapshot.
    pub fn contains_address(&self, address: u64, snap: i64) -> bool {
        if let (Some(start), Some(end)) =
            (self.get_start_address(snap), self.get_end_address(snap))
        {
            start <= address && address <= end
        } else {
            false
        }
    }

    /// Remove this section from the given snap onward.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap - 1);
    }

    /// Delete this section.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }
}

// ---------------------------------------------------------------------------
// ModuleManager
// ---------------------------------------------------------------------------

/// Manages modules and sections within a trace.
#[derive(Debug)]
pub struct TraceModuleManager {
    next_key: AtomicU64,
    modules: BTreeMap<u64, TraceModule>,
    sections: BTreeMap<u64, TraceSection>,
}

impl TraceModuleManager {
    /// Create a new empty module manager.
    pub fn new() -> Self {
        Self {
            next_key: AtomicU64::new(1),
            modules: BTreeMap::new(),
            sections: BTreeMap::new(),
        }
    }

    fn alloc_key(&self) -> u64 {
        self.next_key.fetch_add(1, Ordering::Relaxed)
    }

    /// Add a new module.
    pub fn add_module(
        &mut self,
        snap: i64,
        name: impl Into<String>,
        module_name: impl Into<String>,
        start_address: u64,
        end_address: u64,
    ) -> u64 {
        let key = self.alloc_key();
        self.modules.insert(
            key,
            TraceModule::new(key, snap, name, module_name, start_address, end_address),
        );
        key
    }

    /// Add a new section to a module.
    pub fn add_section(
        &mut self,
        module_key: u64,
        snap: i64,
        name: impl Into<String>,
        start_address: u64,
        end_address: u64,
    ) -> u64 {
        let key = self.alloc_key();
        self.sections.insert(
            key,
            TraceSection::new(key, module_key, snap, name, start_address, end_address),
        );
        key
    }

    /// Get a module by key.
    pub fn get_module(&self, key: u64) -> Option<&TraceModule> {
        self.modules.get(&key)
    }

    /// Get a mutable module by key.
    pub fn get_module_mut(&mut self, key: u64) -> Option<&mut TraceModule> {
        self.modules.get_mut(&key)
    }

    /// Get a section by key.
    pub fn get_section(&self, key: u64) -> Option<&TraceSection> {
        self.sections.get(&key)
    }

    /// Get a mutable section by key.
    pub fn get_section_mut(&mut self, key: u64) -> Option<&mut TraceSection> {
        self.sections.get_mut(&key)
    }

    /// Get all sections for a given module.
    pub fn get_sections_for_module(&self, module_key: u64) -> Vec<&TraceSection> {
        self.sections
            .values()
            .filter(|s| s.module_key == module_key)
            .collect()
    }

    /// Get all modules valid at the given snapshot.
    pub fn get_modules_at_snap(&self, snap: i64) -> Vec<&TraceModule> {
        self.modules.values().filter(|m| m.is_valid(snap)).collect()
    }

    /// Find the module containing the given address at the snapshot.
    pub fn find_module_for_address(&self, address: u64, snap: i64) -> Option<&TraceModule> {
        self.modules
            .values()
            .find(|m| m.is_valid(snap) && m.contains_address(address, snap))
    }

    /// Iterate over all modules.
    pub fn modules(&self) -> impl Iterator<Item = &TraceModule> {
        self.modules.values()
    }

    /// Iterate over all sections.
    pub fn sections(&self) -> impl Iterator<Item = &TraceSection> {
        self.sections.values()
    }

    /// Remove a module (and all its sections).
    pub fn remove_module(&mut self, key: u64) -> Option<TraceModule> {
        let section_keys: Vec<u64> = self
            .sections
            .values()
            .filter(|s| s.module_key == key)
            .map(|s| s.key())
            .collect();
        for sk in section_keys {
            self.sections.remove(&sk);
        }
        self.modules.remove(&key)
    }
}

impl Default for TraceModuleManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_basic() {
        let module = TraceModule::new(1, 0, "libc", "/usr/lib/libc.so", 0x7F0000, 0x7FFFFF);
        assert_eq!(module.key(), 1);
        assert_eq!(module.get_name(0), Some("libc"));
        assert_eq!(module.get_module_name(0), Some("/usr/lib/libc.so"));
        assert_eq!(module.get_start_address(0), Some(0x7F0000));
        assert_eq!(module.get_end_address(0), Some(0x7FFFFF));
        assert_eq!(module.get_length(0), Some(0x10000));
        assert!(module.contains_address(0x7F5000, 0));
        assert!(!module.contains_address(0x6FFFFF, 0));
    }

    #[test]
    fn test_module_name_history() {
        let mut module = TraceModule::new(1, 0, "libc", "/usr/lib/libc.so", 0x7F0000, 0x7FFFFF);
        module.set_name(10, "libc_renamed");

        assert_eq!(module.get_name(0), Some("libc"));
        assert_eq!(module.get_name(10), Some("libc_renamed"));
    }

    #[test]
    fn test_module_remove() {
        let mut module = TraceModule::new(1, 0, "libc", "/usr/lib/libc.so", 0x7F0000, 0x7FFFFF);
        assert!(module.is_valid(100));
        module.remove(50);
        assert!(module.is_valid(49));
        assert!(!module.is_valid(50));
    }

    #[test]
    fn test_section_basic() {
        let section = TraceSection::new(10, 1, 0, ".text", 0x400000, 0x400FFF);
        assert_eq!(section.key(), 10);
        assert_eq!(section.module_key, 1);
        assert_eq!(section.get_name(0), Some(".text"));
        assert_eq!(section.get_start_address(0), Some(0x400000));
        assert_eq!(section.get_end_address(0), Some(0x400FFF));
        assert_eq!(section.get_length(0), Some(0x1000));
    }

    #[test]
    fn test_module_manager() {
        let mut mgr = TraceModuleManager::new();
        let m1 = mgr.add_module(0, "main", "/usr/bin/main", 0x400000, 0x4FFFFF);
        let m2 = mgr.add_module(0, "libc", "/usr/lib/libc.so", 0x7F0000, 0x7FFFFF);

        let s1 = mgr.add_section(m1, 0, ".text", 0x400000, 0x400FFF);
        let s2 = mgr.add_section(m1, 0, ".data", 0x410000, 0x410FFF);

        assert_eq!(mgr.modules().count(), 2);
        assert_eq!(mgr.sections().count(), 2);

        let sections = mgr.get_sections_for_module(m1);
        assert_eq!(sections.len(), 2);

        let section = mgr.get_section(s1).unwrap();
        assert_eq!(section.get_name(0), Some(".text"));

        let found = mgr.find_module_for_address(0x7F5000, 0).unwrap();
        assert_eq!(found.key(), m2);

        let at_snap = mgr.get_modules_at_snap(0);
        assert_eq!(at_snap.len(), 2);
    }

    #[test]
    fn test_module_manager_remove_module() {
        let mut mgr = TraceModuleManager::new();
        let m = mgr.add_module(0, "temp", "/tmp/temp", 0x1000, 0x1FFF);
        mgr.add_section(m, 0, ".text", 0x1000, 0x17FF);
        mgr.add_section(m, 0, ".data", 0x1800, 0x1FFF);

        assert_eq!(mgr.sections().count(), 2);
        mgr.remove_module(m);
        assert_eq!(mgr.modules().count(), 0);
        assert_eq!(mgr.sections().count(), 0);
    }
}
