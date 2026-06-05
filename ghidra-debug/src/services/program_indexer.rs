//! Program module indexer ported from Java.
//!
//! Ported from `ProgramModuleIndexer` in the Debugger module. Indexes
//! the module/section tree of a program for use in auto-mapping proposals.

use std::collections::HashMap;

/// A module entry indexed from a program.
#[derive(Debug, Clone)]
pub struct IndexedModule {
    /// Module name.
    pub name: String,
    /// Module file path.
    pub file_path: String,
    /// Module path in the program tree.
    pub path: Vec<String>,
    /// Address range of the module.
    pub address_range: (u64, u64),
    /// Child sections.
    pub sections: Vec<IndexedSection>,
}

impl IndexedModule {
    /// Create a new indexed module.
    pub fn new(name: impl Into<String>, file_path: impl Into<String>, base_address: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            file_path: file_path.into(),
            path: Vec::new(),
            address_range: (base_address, base_address + size),
            sections: Vec::new(),
        }
    }

    /// Get the base address.
    pub fn base_address(&self) -> u64 {
        self.address_range.0
    }

    /// Get the end address.
    pub fn end_address(&self) -> u64 {
        self.address_range.1
    }

    /// Get the size.
    pub fn size(&self) -> u64 {
        self.address_range.1 - self.address_range.0
    }

    /// Add a section to this module.
    pub fn add_section(&mut self, section: IndexedSection) {
        self.sections.push(section);
    }
}

/// A section entry within an indexed module.
#[derive(Debug, Clone)]
pub struct IndexedSection {
    /// Section name.
    pub name: String,
    /// Start address.
    pub start_address: u64,
    /// End address (inclusive).
    pub end_address: u64,
    /// Whether the section is executable.
    pub executable: bool,
    /// Whether the section is writable.
    pub writable: bool,
    /// Whether the section is readable.
    pub readable: bool,
}

impl IndexedSection {
    /// Create a new indexed section.
    pub fn new(name: impl Into<String>, start_address: u64, end_address: u64) -> Self {
        Self {
            name: name.into(),
            start_address,
            end_address,
            executable: false,
            writable: false,
            readable: true,
        }
    }

    /// Mark the section as executable.
    pub fn executable(mut self) -> Self {
        self.executable = true;
        self
    }

    /// Mark the section as writable.
    pub fn writable(mut self) -> Self {
        self.writable = true;
        self
    }

    /// Get the section size (end_address - start_address + 1).
    pub fn size(&self) -> u64 {
        self.end_address - self.start_address + 1
    }

    /// Check if the section contains the given address.
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.start_address && address <= self.end_address
    }

    /// Check if the section overlaps with the given range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start_address <= end && start <= self.end_address
    }
}

/// Indexes program modules and sections for mapping proposals.
///
/// Ported from `ProgramModuleIndexer`.
#[derive(Debug, Default)]
pub struct ProgramModuleIndexer {
    /// Program URL or identifier.
    pub url: String,
    /// Language ID.
    pub language_id: String,
    /// Indexed modules.
    pub modules: Vec<IndexedModule>,
    /// Section name to module mapping.
    section_to_module: HashMap<String, String>,
}

impl ProgramModuleIndexer {
    /// Create a new empty indexer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an indexer with a URL and language ID.
    pub fn new_with_config(url: impl Into<String>, language_id: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            language_id: language_id.into(),
            ..Self::default()
        }
    }

    /// Find a module at the given address.
    pub fn module_at(&self, address: u64) -> Option<&IndexedModule> {
        self.modules.iter().find(|m| {
            address >= m.address_range.0 && address < m.address_range.1
        })
    }

    /// Find modules overlapping the given address range.
    pub fn modules_overlapping(&self, start: u64, end: u64) -> Vec<&IndexedModule> {
        self.modules.iter().filter(|m| {
            start < m.address_range.1 && end > m.address_range.0
        }).collect()
    }

    /// Add a module to the index.
    pub fn add_module(&mut self, module: IndexedModule) {
        for section in &module.sections {
            self.section_to_module
                .insert(section.name.clone(), module.name.clone());
        }
        self.modules.push(module);
    }

    /// Get all indexed modules.
    pub fn modules(&self) -> &[IndexedModule] {
        &self.modules
    }

    /// Find a module by name.
    pub fn find_module(&self, name: &str) -> Option<&IndexedModule> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Find the module that contains a section with the given name.
    pub fn module_for_section(&self, section_name: &str) -> Option<&IndexedModule> {
        self.section_to_module
            .get(section_name)
            .and_then(|module_name| self.find_module(module_name))
    }

    /// Get all sections across all modules.
    pub fn all_sections(&self) -> Vec<&IndexedSection> {
        self.modules
            .iter()
            .flat_map(|m| m.sections.iter())
            .collect()
    }

    /// Get all executable sections.
    pub fn executable_sections(&self) -> Vec<&IndexedSection> {
        self.all_sections()
            .into_iter()
            .filter(|s| s.executable)
            .collect()
    }

    /// Get total indexed module count.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Get total indexed section count.
    pub fn section_count(&self) -> usize {
        self.modules.iter().map(|m| m.sections.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_indexer() -> ProgramModuleIndexer {
        let mut indexer = ProgramModuleIndexer::new();
        let mut libc = IndexedModule::new("libc.so", "/usr/lib/libc.so", 0x400000, 0x100000);
        libc.add_section(IndexedSection::new(".text", 0x400000, 0x47FFFF).executable());
        libc.add_section(IndexedSection::new(".data", 0x480000, 0x49FFFF).writable());
        indexer.add_module(libc);

        let mut main = IndexedModule::new("main", "/usr/bin/main", 0x100000, 0x100000);
        main.add_section(IndexedSection::new(".text", 0x100000, 0x15FFFF).executable());
        indexer.add_module(main);
        indexer
    }

    #[test]
    fn test_indexer_basics() {
        let indexer = make_test_indexer();
        assert_eq!(indexer.module_count(), 2);
        assert_eq!(indexer.section_count(), 3);
    }

    #[test]
    fn test_find_module() {
        let indexer = make_test_indexer();
        assert!(indexer.find_module("libc.so").is_some());
        assert!(indexer.find_module("nonexistent").is_none());
    }

    #[test]
    fn test_module_for_section() {
        let indexer = make_test_indexer();
        // Note: ".text" appears in both modules; the last one wins in section_to_module
        let module = indexer.module_for_section(".data");
        assert!(module.is_some());
        assert_eq!(module.unwrap().name, "libc.so");
    }

    #[test]
    fn test_executable_sections() {
        let indexer = make_test_indexer();
        let exec_sections = indexer.executable_sections();
        assert_eq!(exec_sections.len(), 2);
        for s in exec_sections {
            assert!(s.executable);
        }
    }

    #[test]
    fn test_all_sections() {
        let indexer = make_test_indexer();
        assert_eq!(indexer.all_sections().len(), 3);
    }
}
