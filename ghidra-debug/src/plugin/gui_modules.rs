//! Modules/sections GUI data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.modules`
//! package in the Debugger module. Provides module and section data
//! model types for the modules panel.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A module row for the modules panel.
///
/// Ported from Ghidra's module panel data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRow {
    /// Module key.
    pub key: i64,
    /// Module name (e.g., "libc.so", "kernel32.dll").
    pub name: String,
    /// Module base address.
    pub base_address: u64,
    /// Module end address.
    pub max_address: u64,
    /// The address space name.
    pub space_name: String,
    /// The lifespan of this module.
    pub lifespan: Lifespan,
    /// Path in the target object tree.
    pub path: String,
}

impl ModuleRow {
    /// Create a new module row.
    pub fn new(
        key: i64,
        name: impl Into<String>,
        base_address: u64,
        max_address: u64,
    ) -> Self {
        Self {
            key,
            name: name.into(),
            base_address,
            max_address,
            space_name: String::from("ram"),
            lifespan: Lifespan::ALL,
            path: String::new(),
        }
    }

    /// The size of the module in bytes.
    pub fn size(&self) -> u64 {
        if self.max_address >= self.base_address {
            self.max_address - self.base_address + 1
        } else {
            0
        }
    }
}

/// A section row in the modules panel.
///
/// Ported from Ghidra's section panel data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionRow {
    /// Section key.
    pub key: i64,
    /// Parent module key.
    pub module_key: i64,
    /// Section name (e.g., ".text", ".rodata").
    pub name: String,
    /// Section base address.
    pub base_address: u64,
    /// Section end address.
    pub max_address: u64,
    /// The address space name.
    pub space_name: String,
    /// Whether the section is executable.
    pub executable: bool,
    /// Whether the section is writable.
    pub writable: bool,
    /// Path in the target object tree.
    pub path: String,
}

impl SectionRow {
    /// Create a new section row.
    pub fn new(
        key: i64,
        module_key: i64,
        name: impl Into<String>,
        base_address: u64,
        max_address: u64,
    ) -> Self {
        Self {
            key,
            module_key,
            name: name.into(),
            base_address,
            max_address,
            space_name: String::from("ram"),
            executable: false,
            writable: false,
            path: String::new(),
        }
    }

    /// The size of the section in bytes.
    pub fn size(&self) -> u64 {
        if self.max_address >= self.base_address {
            self.max_address - self.base_address + 1
        } else {
            0
        }
    }
}

/// A static mapping row showing a mapping between a trace address range
/// and a static program address range.
///
/// Ported from Ghidra's `StaticMappingRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingRow {
    /// Key.
    pub key: i64,
    /// Static program path/URL.
    pub program_path: String,
    /// Program address range start.
    pub program_min: u64,
    /// Program address range end.
    pub program_max: u64,
    /// Trace address range start.
    pub trace_min: u64,
    /// Trace address range end.
    pub trace_max: u64,
    /// The lifespan of this mapping.
    pub lifespan: Lifespan,
}

impl StaticMappingRow {
    /// Create a new static mapping row.
    pub fn new(
        key: i64,
        program_path: impl Into<String>,
        program_min: u64,
        program_max: u64,
        trace_min: u64,
        trace_max: u64,
    ) -> Self {
        Self {
            key,
            program_path: program_path.into(),
            program_min,
            program_max,
            trace_min,
            trace_max,
            lifespan: Lifespan::ALL,
        }
    }

    /// Map a program address to a trace address.
    pub fn program_to_trace(&self, prog_addr: u64) -> Option<u64> {
        if prog_addr >= self.program_min && prog_addr <= self.program_max {
            Some(self.trace_min + (prog_addr - self.program_min))
        } else {
            None
        }
    }

    /// Map a trace address to a program address.
    pub fn trace_to_program(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr >= self.trace_min && trace_addr <= self.trace_max {
            Some(self.program_min + (trace_addr - self.trace_min))
        } else {
            None
        }
    }

    /// The size of the mapping.
    pub fn size(&self) -> u64 {
        self.program_max - self.program_min + 1
    }
}

/// Column definitions for the modules table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleColumn {
    /// Module name.
    Name,
    /// Base address.
    BaseAddress,
    /// Size.
    Size,
    /// Path in object tree.
    Path,
}

/// Model for the modules display panel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleTableModel {
    modules: Vec<ModuleRow>,
    sections: Vec<SectionRow>,
    mappings: Vec<StaticMappingRow>,
}

impl ModuleTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Get all modules.
    pub fn modules(&self) -> &[ModuleRow] {
        &self.modules
    }

    /// Add a module.
    pub fn add_module(&mut self, module: ModuleRow) {
        self.modules.push(module);
        self.modules.sort_by_key(|m| m.base_address);
    }

    /// Remove a module by key.
    pub fn remove_module(&mut self, key: i64) -> bool {
        let before = self.modules.len();
        self.modules.retain(|m| m.key != key);
        // Also remove associated sections
        self.sections.retain(|s| s.module_key != key);
        self.modules.len() < before
    }

    /// Get sections for a specific module.
    pub fn sections_for_module(&self, module_key: i64) -> Vec<&SectionRow> {
        self.sections
            .iter()
            .filter(|s| s.module_key == module_key)
            .collect()
    }

    /// Add a section.
    pub fn add_section(&mut self, section: SectionRow) {
        self.sections.push(section);
    }

    /// The number of sections.
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Add a static mapping.
    pub fn add_mapping(&mut self, mapping: StaticMappingRow) {
        self.mappings.push(mapping);
    }

    /// Get all static mappings.
    pub fn mappings(&self) -> &[StaticMappingRow] {
        &self.mappings
    }

    /// Find a mapping by trace address.
    pub fn mapping_at_trace(&self, trace_addr: u64) -> Option<&StaticMappingRow> {
        self.mappings.iter().find(|m| {
            trace_addr >= m.trace_min && trace_addr <= m.trace_max
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_row() {
        let row = ModuleRow::new(1, "libc.so", 0x7f0000, 0x7f1fff);
        assert_eq!(row.size(), 0x2000);
        assert_eq!(row.name, "libc.so");
    }

    #[test]
    fn test_section_row() {
        let row = SectionRow::new(1, 10, ".text", 0x400000, 0x400fff);
        assert_eq!(row.size(), 0x1000);
        assert_eq!(row.module_key, 10);
    }

    #[test]
    fn test_static_mapping_row() {
        let mapping = StaticMappingRow::new(1, "program.exe", 0x400000, 0x400fff, 0x7f0000, 0x7f0fff);
        assert_eq!(mapping.program_to_trace(0x400500), Some(0x7f0500));
        assert_eq!(mapping.trace_to_program(0x7f0500), Some(0x400500));
        assert_eq!(mapping.program_to_trace(0x500000), None);
    }

    #[test]
    fn test_module_table_model() {
        let mut model = ModuleTableModel::new();
        model.add_module(ModuleRow::new(1, "libc.so", 0x7f0000, 0x7f1fff));
        model.add_module(ModuleRow::new(2, "main", 0x400000, 0x400fff));
        assert_eq!(model.module_count(), 2);
        // Sorted by address
        assert_eq!(model.modules()[0].name, "main");
        assert_eq!(model.modules()[1].name, "libc.so");
    }

    #[test]
    fn test_module_table_model_sections() {
        let mut model = ModuleTableModel::new();
        model.add_module(ModuleRow::new(1, "main", 0x400000, 0x400fff));
        model.add_section(SectionRow::new(10, 1, ".text", 0x400000, 0x4007ff));
        model.add_section(SectionRow::new(11, 1, ".data", 0x400800, 0x400fff));

        let sections = model.sections_for_module(1);
        assert_eq!(sections.len(), 2);
    }

    #[test]
    fn test_module_table_model_remove() {
        let mut model = ModuleTableModel::new();
        model.add_module(ModuleRow::new(1, "main", 0x400000, 0x400fff));
        model.add_section(SectionRow::new(10, 1, ".text", 0x400000, 0x400fff));
        model.remove_module(1);
        assert_eq!(model.module_count(), 0);
        assert_eq!(model.section_count(), 0);
    }

    #[test]
    fn test_module_table_model_mappings() {
        let mut model = ModuleTableModel::new();
        model.add_mapping(StaticMappingRow::new(
            1, "prog", 0x400000, 0x400fff, 0x7f0000, 0x7f0fff,
        ));
        assert!(model.mapping_at_trace(0x7f0500).is_some());
        assert!(model.mapping_at_trace(0x500000).is_none());
    }
}
