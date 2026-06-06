//! Modules service implementation for managing loaded modules and static mappings.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.modules` package.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::api::modules::{MapEntry, MappingChangeEvent, MappingChangeKind};

/// Information about a loaded module in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModuleInfo {
    /// The module name (e.g., "libc.so", "kernel32.dll").
    pub name: String,
    /// The base address in the trace.
    pub base_address: u64,
    /// The length of the module.
    pub length: u64,
    /// The module path on the target filesystem.
    pub path: String,
    /// Whether the module has been mapped to a static program.
    pub mapped: bool,
    /// The program URL it is mapped to.
    pub mapped_to: Option<String>,
}

impl LoadedModuleInfo {
    /// Create a new module info.
    pub fn new(
        name: impl Into<String>,
        base_address: u64,
        length: u64,
        path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            base_address,
            length,
            path: path.into(),
            mapped: false,
            mapped_to: None,
        }
    }

    /// The end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.base_address + self.length
    }

    /// Whether the given address falls within this module.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base_address && addr < self.end_address()
    }
}

/// Information about a section within a loaded module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedSectionInfo {
    /// The section name (e.g., ".text", ".data").
    pub name: String,
    /// The base address.
    pub base_address: u64,
    /// The length.
    pub length: u64,
    /// The parent module name.
    pub module_name: String,
    /// Whether this section is executable.
    pub executable: bool,
    /// Whether this section is writable.
    pub writable: bool,
    /// Whether this section is readable.
    pub readable: bool,
}

impl LoadedSectionInfo {
    /// Create a new section info.
    pub fn new(
        name: impl Into<String>,
        base_address: u64,
        length: u64,
        module_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            base_address,
            length,
            module_name: module_name.into(),
            executable: false,
            writable: false,
            readable: true,
        }
    }

    /// Mark as executable.
    pub fn with_executable(mut self) -> Self {
        self.executable = true;
        self
    }

    /// Mark as writable.
    pub fn with_writable(mut self) -> Self {
        self.writable = true;
        self
    }
}

/// The modules service implementation.
///
/// Ported from Ghidra's debugger modules service plugin.
#[derive(Debug, Default)]
pub struct ModulesServiceImpl {
    /// Loaded modules keyed by name.
    modules: BTreeMap<String, LoadedModuleInfo>,
    /// Loaded sections keyed by (module_name, section_name).
    sections: BTreeMap<(String, String), LoadedSectionInfo>,
    /// Static mapping entries.
    mappings: Vec<MapEntry>,
    /// Change history.
    change_log: Vec<MappingChangeEvent>,
}

impl ModulesServiceImpl {
    /// Create a new modules service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a loaded module.
    pub fn add_module(&mut self, module: LoadedModuleInfo) {
        self.modules.insert(module.name.clone(), module);
    }

    /// Remove a module by name.
    pub fn remove_module(&mut self, name: &str) -> Option<LoadedModuleInfo> {
        // Remove associated sections
        let keys: Vec<_> = self
            .sections
            .keys()
            .filter(|(m, _)| m == name)
            .cloned()
            .collect();
        for key in keys {
            self.sections.remove(&key);
        }
        self.modules.remove(name)
    }

    /// Get a module by name.
    pub fn module(&self, name: &str) -> Option<&LoadedModuleInfo> {
        self.modules.get(name)
    }

    /// Get all loaded modules.
    pub fn modules(&self) -> Vec<&LoadedModuleInfo> {
        self.modules.values().collect()
    }

    /// Add a section.
    pub fn add_section(&mut self, section: LoadedSectionInfo) {
        let key = (section.module_name.clone(), section.name.clone());
        self.sections.insert(key, section);
    }

    /// Get sections for a module.
    pub fn sections_for(&self, module_name: &str) -> Vec<&LoadedSectionInfo> {
        self.sections
            .iter()
            .filter(|((m, _), _)| m == module_name)
            .map(|(_, s)| s)
            .collect()
    }

    /// Add a static mapping.
    pub fn add_mapping(&mut self, entry: MapEntry) {
        self.change_log.push(MappingChangeEvent::new(
            MappingChangeKind::Added,
            entry.clone(),
        ));
        self.mappings.push(entry);
    }

    /// Remove a mapping by index.
    pub fn remove_mapping(&mut self, idx: usize) -> Option<MapEntry> {
        if idx < self.mappings.len() {
            let entry = self.mappings.remove(idx);
            self.change_log.push(MappingChangeEvent::new(
                MappingChangeKind::Removed,
                entry.clone(),
            ));
            Some(entry)
        } else {
            None
        }
    }

    /// Get all mappings.
    pub fn mappings(&self) -> &[MapEntry] {
        &self.mappings
    }

    /// Get the change log.
    pub fn change_log(&self) -> &[MappingChangeEvent] {
        &self.change_log
    }

    /// Find the module containing the given address.
    pub fn module_at(&self, addr: u64) -> Option<&LoadedModuleInfo> {
        self.modules.values().find(|m| m.contains(addr))
    }

    /// Number of loaded modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Number of static mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lifespan;

    #[test]
    fn test_loaded_module_info() {
        let m = LoadedModuleInfo::new("libc.so", 0x7f000000, 0x200000, "/lib/x86_64-linux-gnu/libc.so");
        assert!(m.contains(0x7f001000));
        assert!(!m.contains(0x7f300000));
        assert_eq!(m.end_address(), 0x7f200000);
    }

    #[test]
    fn test_loaded_section_info() {
        let s = LoadedSectionInfo::new(".text", 0x400000, 0x1000, "main.elf")
            .with_executable()
            .with_writable();
        assert!(s.executable);
        assert!(s.writable);
        assert!(s.readable);
    }

    #[test]
    fn test_modules_service() {
        let mut svc = ModulesServiceImpl::new();
        svc.add_module(LoadedModuleInfo::new("main.elf", 0x400000, 0x10000, "/usr/bin/main"));
        svc.add_module(LoadedModuleInfo::new("libc.so", 0x7f000000, 0x200000, "/lib/libc.so"));

        assert_eq!(svc.module_count(), 2);
        assert!(svc.module("main.elf").is_some());
        assert!(svc.module("missing").is_none());
    }

    #[test]
    fn test_module_at_address() {
        let mut svc = ModulesServiceImpl::new();
        svc.add_module(LoadedModuleInfo::new("main.elf", 0x400000, 0x10000, "/usr/bin/main"));

        let m = svc.module_at(0x400500);
        assert!(m.is_some());
        assert_eq!(m.unwrap().name, "main.elf");

        assert!(svc.module_at(0x500000).is_none());
    }

    #[test]
    fn test_sections() {
        let mut svc = ModulesServiceImpl::new();
        svc.add_section(LoadedSectionInfo::new(".text", 0x400000, 0x1000, "main.elf").with_executable());
        svc.add_section(LoadedSectionInfo::new(".data", 0x401000, 0x800, "main.elf"));

        let sections = svc.sections_for("main.elf");
        assert_eq!(sections.len(), 2);
    }

    #[test]
    fn test_mappings() {
        let mut svc = ModulesServiceImpl::new();
        let entry = MapEntry::new(
            "trace1",
            0x400000,
            0x400fff,
            0x7fff0000,
            0x7fff0fff,
            Lifespan::now_on(0),
        );
        svc.add_mapping(entry);

        assert_eq!(svc.mapping_count(), 1);
        assert_eq!(svc.change_log().len(), 1);
        assert_eq!(svc.change_log()[0].kind, MappingChangeKind::Added);
    }

    #[test]
    fn test_remove_module() {
        let mut svc = ModulesServiceImpl::new();
        svc.add_module(LoadedModuleInfo::new("main.elf", 0x400000, 0x10000, "/usr/bin/main"));
        svc.add_section(LoadedSectionInfo::new(".text", 0x400000, 0x1000, "main.elf"));

        let removed = svc.remove_module("main.elf");
        assert!(removed.is_some());
        assert_eq!(svc.module_count(), 0);
        assert!(svc.sections_for("main.elf").is_empty());
    }

    #[test]
    fn test_remove_mapping() {
        let mut svc = ModulesServiceImpl::new();
        let entry = MapEntry::new(
            "trace1", 0x400000, 0x400fff, 0x7fff0000, 0x7fff0fff, Lifespan::now_on(0),
        );
        svc.add_mapping(entry);

        let removed = svc.remove_mapping(0);
        assert!(removed.is_some());
        assert_eq!(svc.mapping_count(), 0);
        assert_eq!(svc.change_log().len(), 2); // Added + Removed
    }

    #[test]
    fn test_loaded_module_serde() {
        let m = LoadedModuleInfo::new("libc.so", 0x7f000000, 0x200000, "/lib/libc.so");
        let json = serde_json::to_string(&m).unwrap();
        let back: LoadedModuleInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "libc.so");
    }

    #[test]
    fn test_section_permissions() {
        let s = LoadedSectionInfo::new(".rodata", 0x402000, 0x500, "main.elf");
        assert!(!s.executable);
        assert!(!s.writable);
        assert!(s.readable);
    }
}
