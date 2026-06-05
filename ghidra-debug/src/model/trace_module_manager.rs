//! Trace module manager - manages modules, sections, and static mappings.
//!
//! Ported from Ghidra's `TraceModuleManager`, `TraceModuleSpace`, `TraceStaticMappingManager`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::module::{TraceModule, TraceSection, TraceStaticMapping};
use super::Lifespan;

/// Manages modules, sections, and static mappings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceModuleManager {
    /// Modules by key.
    modules: BTreeMap<i64, TraceModule>,
    /// Sections by key.
    sections: BTreeMap<i64, TraceSection>,
    /// Static mappings by key.
    static_mappings: BTreeMap<i64, TraceStaticMapping>,
    /// Next available key.
    next_key: i64,
}

impl TraceModuleManager {
    /// Create a new empty module manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a module, returning its assigned key.
    pub fn add_module(&mut self, mut module: TraceModule) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        module.key = key;
        self.modules.insert(key, module);
        key
    }

    /// Get a module by key.
    pub fn get_module(&self, key: i64) -> Option<&TraceModule> {
        self.modules.get(&key)
    }

    /// Remove a module by key.
    pub fn remove_module(&mut self, key: i64) -> Option<TraceModule> {
        self.modules.remove(&key)
    }

    /// Add a section to a module.
    pub fn add_section(&mut self, mut section: TraceSection) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        section.key = key;
        self.sections.insert(key, section);
        key
    }

    /// Get a section by key.
    pub fn get_section(&self, key: i64) -> Option<&TraceSection> {
        self.sections.get(&key)
    }

    /// Get all sections for a module.
    pub fn sections_for_module(&self, module_key: i64) -> Vec<&TraceSection> {
        self.sections
            .values()
            .filter(|s| s.module_key == module_key)
            .collect()
    }

    /// Add a static mapping.
    pub fn add_static_mapping(&mut self, mut mapping: TraceStaticMapping) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        mapping.key = key;
        self.static_mappings.insert(key, mapping);
        key
    }

    /// Get a static mapping by key.
    pub fn get_static_mapping(&self, key: i64) -> Option<&TraceStaticMapping> {
        self.static_mappings.get(&key)
    }

    /// Get all modules valid at a snap.
    pub fn modules_at_snap(&self, snap: i64) -> Vec<&TraceModule> {
        self.modules.values().filter(|m| m.is_loaded_at(snap)).collect()
    }

    /// Find module by name at a snap.
    pub fn find_module_by_name(&self, snap: i64, name: &str) -> Option<&TraceModule> {
        self.modules
            .values()
            .find(|m| m.is_loaded_at(snap) && m.module_name == name)
    }

    /// Module count.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Section count.
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Static mapping count.
    pub fn static_mapping_count(&self) -> usize {
        self.static_mappings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_module() {
        let mut mgr = TraceModuleManager::new();
        let key = mgr.add_module(TraceModule::new(
            0, "mods[1]", "libc.so", 0x7f000, 0x7ffff, Lifespan::span(0, 10),
        ));
        assert_eq!(mgr.module_count(), 1);
        assert!(mgr.get_module(key).is_some());
    }

    #[test]
    fn test_find_by_name() {
        let mut mgr = TraceModuleManager::new();
        mgr.add_module(TraceModule::new(
            0, "mods[1]", "libc.so", 0x7f000, 0x7ffff, Lifespan::span(0, 10),
        ));
        assert!(mgr.find_module_by_name(5, "libc.so").is_some());
        assert!(mgr.find_module_by_name(5, "missing").is_none());
    }

    #[test]
    fn test_sections_for_module() {
        let mut mgr = TraceModuleManager::new();
        let mkey = mgr.add_module(TraceModule::new(
            0, "mods[1]", "libc.so", 0x7f000, 0x7ffff, Lifespan::span(0, 10),
        ));
        mgr.add_section(TraceSection::new(
            0, mkey, "mods[1].sections[.text]", ".text", 0x7f000, 0x7f7ff,
        ));
        mgr.add_section(TraceSection::new(
            0, mkey, "mods[1].sections[.data]", ".data", 0x7f800, 0x7ffff,
        ));
        assert_eq!(mgr.sections_for_module(mkey).len(), 2);
    }

    #[test]
    fn test_static_mapping() {
        let mut mgr = TraceModuleManager::new();
        let m = TraceStaticMapping::new(0, 0x400000, 0x400fff, 0x0, "file:///tmp/prog");
        let key = mgr.add_static_mapping(m);
        assert!(mgr.get_static_mapping(key).is_some());
    }
}
