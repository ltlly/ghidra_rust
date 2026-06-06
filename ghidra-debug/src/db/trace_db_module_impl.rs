//! Database-backed module and section manager implementation.
//!
//! Ported from Ghidra's `ghidra.trace.database.module.DBTraceModuleManager`,
//! `DBTraceModule`, `DBTraceSection`, and `DBTraceStaticMapping`.
//!
//! In Ghidra's trace model, modules represent loaded executables/libraries
//! in the target process. Each module has sections (like .text, .data) that
//! map to address ranges in the trace. The module manager wraps the object
//! manager to provide a convenient API for working with modules.
//!
//! The static mapping manager handles the correspondence between
//! program addresses and trace addresses for each module.


use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// TraceModule
// ---------------------------------------------------------------------------

/// A loaded module in a trace (executable, shared library, etc.).
///
/// Ported from `ghidra.trace.model.modules.TraceModule`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceModuleEntry {
    /// Unique key for this module.
    pub key: i64,
    /// The full path/name of the module (e.g., "/usr/lib/libc.so.6").
    pub path: String,
    /// The short name (e.g., "libc.so.6").
    pub name: String,
    /// The base address in the trace.
    pub base_address: u64,
    /// The size of the module in bytes.
    pub size: u64,
    /// The lifespan during which this module is loaded.
    pub lifespan: Lifespan,
    /// The sections within this module.
    pub sections: Vec<TraceSectionEntry>,
}

impl TraceModuleEntry {
    /// Create a new module entry.
    pub fn new(
        key: i64,
        path: impl Into<String>,
        name: impl Into<String>,
        base_address: u64,
        size: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            path: path.into(),
            name: name.into(),
            base_address,
            size,
            lifespan,
            sections: Vec::new(),
        }
    }

    /// The end address (inclusive).
    pub fn end_address(&self) -> u64 {
        self.base_address + self.size - 1
    }

    /// Check if an address falls within this module.
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.base_address && address <= self.end_address()
    }

    /// Add a section to this module.
    pub fn add_section(&mut self, section: TraceSectionEntry) {
        self.sections.push(section);
    }

    /// Find a section by name.
    pub fn section_by_name(&self, name: &str) -> Option<&TraceSectionEntry> {
        self.sections.iter().find(|s| s.name == name)
    }
}

// ---------------------------------------------------------------------------
// TraceSection
// ---------------------------------------------------------------------------

/// A section within a loaded module.
///
/// Ported from `ghidra.trace.model.modules.TraceSection`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSectionEntry {
    /// Unique key for this section.
    pub key: i64,
    /// The name of the section (e.g., ".text", ".data", ".bss").
    pub name: String,
    /// Start address in the trace.
    pub start_address: u64,
    /// Size of the section in bytes.
    pub size: u64,
    /// The lifespan during which this section exists.
    pub lifespan: Lifespan,
    /// Whether the section is readable.
    pub readable: bool,
    /// Whether the section is writable.
    pub writable: bool,
    /// Whether the section is executable.
    pub executable: bool,
}

impl TraceSectionEntry {
    /// Create a new section entry.
    pub fn new(
        key: i64,
        name: impl Into<String>,
        start_address: u64,
        size: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            name: name.into(),
            start_address,
            size,
            lifespan,
            readable: true,
            writable: false,
            executable: false,
        }
    }

    /// Set permissions.
    pub fn with_permissions(mut self, read: bool, write: bool, exec: bool) -> Self {
        self.readable = read;
        self.writable = write;
        self.executable = exec;
        self
    }

    /// The end address (inclusive).
    pub fn end_address(&self) -> u64 {
        self.start_address + self.size - 1
    }

    /// Check if an address falls within this section.
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.start_address && address <= self.end_address()
    }
}

// ---------------------------------------------------------------------------
// DBTraceModuleManager
// ---------------------------------------------------------------------------

/// Database-backed module manager.
///
/// Ported from `ghidra.trace.database.module.DBTraceModuleManager`.
/// Manages loaded modules and their sections within a trace.
#[derive(Debug, Default)]
pub struct DbTraceModuleManager {
    modules: Vec<TraceModuleEntry>,
    next_module_key: i64,
    next_section_key: i64,
}

impl DbTraceModuleManager {
    /// Create a new module manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new module.
    pub fn add_module(
        &mut self,
        path: impl Into<String>,
        name: impl Into<String>,
        base_address: u64,
        size: u64,
        lifespan: Lifespan,
    ) -> &TraceModuleEntry {
        let key = self.next_module_key;
        self.next_module_key += 1;
        let module = TraceModuleEntry::new(key, path, name, base_address, size, lifespan);
        self.modules.push(module);
        self.modules.last().unwrap()
    }

    /// Add a section to a module.
    pub fn add_section(
        &mut self,
        module_key: i64,
        name: impl Into<String>,
        start_address: u64,
        size: u64,
        lifespan: Lifespan,
    ) -> Option<&TraceSectionEntry> {
        let section_key = self.next_section_key;
        self.next_section_key += 1;
        let section = TraceSectionEntry::new(section_key, name, start_address, size, lifespan);
        let module = self.modules.iter_mut().find(|m| m.key == module_key)?;
        module.add_section(section);
        module.sections.last()
    }

    /// Get all modules.
    pub fn all_modules(&self) -> &[TraceModuleEntry] {
        &self.modules
    }

    /// Get a module by key.
    pub fn get_module(&self, key: i64) -> Option<&TraceModuleEntry> {
        self.modules.iter().find(|m| m.key == key)
    }

    /// Get modules by path.
    pub fn modules_by_path(&self, path: &str) -> Vec<&TraceModuleEntry> {
        self.modules.iter().filter(|m| m.path == path).collect()
    }

    /// Find modules containing the given address at the given snap.
    pub fn modules_at(&self, address: u64, snap: i64) -> Vec<&TraceModuleEntry> {
        self.modules
            .iter()
            .filter(|m| m.lifespan.contains(snap) && m.contains_address(address))
            .collect()
    }

    /// Find the section containing the given address at the given snap.
    pub fn section_at(&self, address: u64, snap: i64) -> Option<(&TraceModuleEntry, &TraceSectionEntry)> {
        for module in &self.modules {
            if !module.lifespan.contains(snap) || !module.contains_address(address) {
                continue;
            }
            for section in &module.sections {
                if section.lifespan.contains(snap) && section.contains_address(address) {
                    return Some((module, section));
                }
            }
        }
        None
    }

    /// Remove a module by key.
    pub fn remove_module(&mut self, key: i64) -> Option<TraceModuleEntry> {
        if let Some(pos) = self.modules.iter().position(|m| m.key == key) {
            Some(self.modules.remove(pos))
        } else {
            None
        }
    }

    /// Get the number of modules.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Check if there are no modules.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_entry_basic() {
        let m = TraceModuleEntry::new(1, "/usr/bin/test", "test", 0x400000, 0x10000, Lifespan::span(0, 100));
        assert_eq!(m.path, "/usr/bin/test");
        assert_eq!(m.name, "test");
        assert_eq!(m.base_address, 0x400000);
        assert_eq!(m.end_address(), 0x40FFFF);
        assert!(m.contains_address(0x400100));
        assert!(!m.contains_address(0x500000));
    }

    #[test]
    fn test_section_entry_basic() {
        let s = TraceSectionEntry::new(1, ".text", 0x400000, 0x8000, Lifespan::span(0, 100))
            .with_permissions(true, false, true);
        assert_eq!(s.name, ".text");
        assert!(s.readable);
        assert!(!s.writable);
        assert!(s.executable);
        assert!(s.contains_address(0x400100));
        assert_eq!(s.end_address(), 0x407FFF);
    }

    #[test]
    fn test_module_manager_add_and_query() {
        let mut mgr = DbTraceModuleManager::new();

        mgr.add_module("/usr/bin/main", "main", 0x400000, 0x10000, Lifespan::span(0, 100));
        mgr.add_module("/usr/lib/libc.so", "libc.so", 0x7F000000, 0x20000, Lifespan::span(10, 100));

        assert_eq!(mgr.len(), 2);
        assert!(!mgr.is_empty());

        // Query by address
        let at_main = mgr.modules_at(0x400100, 50);
        assert_eq!(at_main.len(), 1);
        assert_eq!(at_main[0].name, "main");

        // Query before libc was loaded
        let before_libc = mgr.modules_at(0x7F000100, 5);
        assert_eq!(before_libc.len(), 0);

        // Query after libc was loaded
        let after_libc = mgr.modules_at(0x7F000100, 50);
        assert_eq!(after_libc.len(), 1);
    }

    #[test]
    fn test_module_manager_sections() {
        let mut mgr = DbTraceModuleManager::new();
        mgr.add_module("/usr/bin/main", "main", 0x400000, 0x20000, Lifespan::span(0, 100));

        let text_lifespan = Lifespan::span(0, 100);
        mgr.add_section(0, ".text", 0x400000, 0x10000, text_lifespan);
        mgr.add_section(0, ".data", 0x401000, 0x8000, Lifespan::span(0, 100));

        let module = mgr.get_module(0).unwrap();
        assert_eq!(module.sections.len(), 2);
        assert_eq!(module.section_by_name(".text").unwrap().start_address, 0x400000);
        assert_eq!(module.section_by_name(".data").unwrap().start_address, 0x401000);
    }

    #[test]
    fn test_module_manager_section_at() {
        let mut mgr = DbTraceModuleManager::new();
        mgr.add_module("/usr/bin/main", "main", 0x400000, 0x30000, Lifespan::span(0, 100));
        // Sections don't overlap
        mgr.add_section(0, ".text", 0x400000, 0x8000, Lifespan::span(0, 100));
        mgr.add_section(0, ".data", 0x408000, 0x8000, Lifespan::span(0, 100));

        let (module, section) = mgr.section_at(0x400100, 50).unwrap();
        assert_eq!(module.name, "main");
        assert_eq!(section.name, ".text");

        let (_, section) = mgr.section_at(0x409000, 50).unwrap();
        assert_eq!(section.name, ".data");

        // Address not in any section
        assert!(mgr.section_at(0x500000, 50).is_none());
    }

    #[test]
    fn test_module_manager_remove() {
        let mut mgr = DbTraceModuleManager::new();
        mgr.add_module("/usr/bin/main", "main", 0x400000, 0x10000, Lifespan::span(0, 100));

        assert_eq!(mgr.len(), 1);
        let removed = mgr.remove_module(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "main");
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_module_manager_by_path() {
        let mut mgr = DbTraceModuleManager::new();
        mgr.add_module("/usr/lib/libc.so", "libc_v1", 0x7F000000, 0x20000, Lifespan::span(0, 50));
        mgr.add_module("/usr/lib/libc.so", "libc_v2", 0x7F000000, 0x20000, Lifespan::span(50, 100));

        let libs = mgr.modules_by_path("/usr/lib/libc.so");
        assert_eq!(libs.len(), 2);
    }
}
