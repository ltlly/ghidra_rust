//! Module operations for trace modules and sections.
//!
//! Ported from Ghidra's `ghidra.trace.model.modules.TraceModuleOperations`,
//! `TraceModuleSpace`, and `TraceConflictedMappingException`.
//!
//! Provides the interface for querying and operating on loaded modules
//! and their sections within a trace.


use serde::{Deserialize, Serialize};

use super::module::{TraceModule, TraceSection, TraceStaticMapping};
use super::Lifespan;

/// Operations for retrieving sections from a trace.
///
/// Ported from Ghidra's `TraceModuleOperations` interface.
/// Modules do not occupy target memory in and of themselves; rather,
/// their sections do. Only the section information is mapped out by
/// memory address. Each section inherits its lifespan from the containing module.
pub trait TraceModuleOperations {
    /// Get all modules.
    fn get_all_modules(&self) -> Vec<&TraceModule>;

    /// Get all modules loaded at the given snap.
    fn get_loaded_modules(&self, snap: i64) -> Vec<&TraceModule>;

    /// Get modules at the given snap and address.
    fn get_modules_at(&self, snap: i64, address: u64) -> Vec<&TraceModule>;

    /// Get the modules loaded at the given snap intersecting the given address range.
    fn get_modules_intersecting(&self, span: &Lifespan, min_addr: u64, max_addr: u64)
        -> Vec<&TraceModule>;

    /// Get all sections.
    fn get_all_sections(&self) -> Vec<&TraceSection>;

    /// Get sections at the given snap and address.
    fn get_sections_at(&self, snap: i64, address: u64) -> Vec<&TraceSection>;

    /// Get the sections loaded at the given snap intersecting the given address range.
    fn get_sections_intersecting(
        &self,
        span: &Lifespan,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<&TraceSection>;
}

/// A module space that ties module operations to a specific address space.
///
/// Ported from Ghidra's `TraceModuleSpace` interface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceModuleSpace {
    /// The address space this module space operates on.
    pub address_space: String,
    /// The modules in this space.
    pub modules: Vec<TraceModule>,
    /// The sections in this space.
    pub sections: Vec<TraceSection>,
    /// The static mappings in this space.
    pub static_mappings: Vec<TraceStaticMapping>,
}

impl TraceModuleSpace {
    /// Create a new module space for the given address space.
    pub fn new(address_space: impl Into<String>) -> Self {
        Self {
            address_space: address_space.into(),
            modules: Vec::new(),
            sections: Vec::new(),
            static_mappings: Vec::new(),
        }
    }

    /// Get the address space name.
    pub fn address_space(&self) -> &str {
        &self.address_space
    }

    /// Add a module to this space.
    pub fn add_module(&mut self, module: TraceModule) {
        self.modules.push(module);
    }

    /// Remove a module by key.
    pub fn remove_module(&mut self, key: i64) -> Option<TraceModule> {
        if let Some(pos) = self.modules.iter().position(|m| m.key == key) {
            Some(self.modules.remove(pos))
        } else {
            None
        }
    }

    /// Add a section to this space.
    pub fn add_section(&mut self, section: TraceSection) {
        self.sections.push(section);
    }

    /// Remove a section by key.
    pub fn remove_section(&mut self, key: i64) -> Option<TraceSection> {
        if let Some(pos) = self.sections.iter().position(|s| s.key == key) {
            Some(self.sections.remove(pos))
        } else {
            None
        }
    }

    /// Add a static mapping.
    pub fn add_static_mapping(&mut self, mapping: TraceStaticMapping) {
        self.static_mappings.push(mapping);
    }

    /// Get sections for a specific module.
    pub fn sections_for_module(&self, module_key: i64) -> Vec<&TraceSection> {
        self.sections
            .iter()
            .filter(|s| s.module_key == module_key)
            .collect()
    }

    /// Get a module by key.
    pub fn get_module(&self, key: i64) -> Option<&TraceModule> {
        self.modules.iter().find(|m| m.key == key)
    }

    /// Get a module by name.
    pub fn get_module_by_name(&self, name: &str) -> Option<&TraceModule> {
        self.modules.iter().find(|m| m.module_name == name)
    }
}

impl TraceModuleOperations for TraceModuleSpace {
    fn get_all_modules(&self) -> Vec<&TraceModule> {
        self.modules.iter().collect()
    }

    fn get_loaded_modules(&self, snap: i64) -> Vec<&TraceModule> {
        self.modules
            .iter()
            .filter(|m| m.lifespan.contains(snap))
            .collect()
    }

    fn get_modules_at(&self, snap: i64, address: u64) -> Vec<&TraceModule> {
        self.modules
            .iter()
            .filter(|m| {
                m.lifespan.contains(snap) && address >= m.min_address && address <= m.max_address
            })
            .collect()
    }

    fn get_modules_intersecting(
        &self,
        span: &Lifespan,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<&TraceModule> {
        self.modules
            .iter()
            .filter(|m| {
                m.lifespan.intersects(span)
                    && m.min_address <= max_addr
                    && m.max_address >= min_addr
            })
            .collect()
    }

    fn get_all_sections(&self) -> Vec<&TraceSection> {
        self.sections.iter().collect()
    }

    fn get_sections_at(&self, snap: i64, address: u64) -> Vec<&TraceSection> {
        self.sections
            .iter()
            .filter(|s| {
                // Section lifespan is inherited from its module
                if let Some(module) = self.get_module(s.module_key) {
                    module.lifespan.contains(snap)
                        && address >= s.min_address
                        && address <= s.max_address
                } else {
                    false
                }
            })
            .collect()
    }

    fn get_sections_intersecting(
        &self,
        span: &Lifespan,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<&TraceSection> {
        self.sections
            .iter()
            .filter(|s| {
                if let Some(module) = self.get_module(s.module_key) {
                    module.lifespan.intersects(span)
                        && s.min_address <= max_addr
                        && s.max_address >= min_addr
                } else {
                    false
                }
            })
            .collect()
    }
}

/// Exception thrown when static mappings conflict.
///
/// Ported from Ghidra's `TraceConflictedMappingException`.
#[derive(Debug, Clone)]
pub struct TraceConflictedMappingException {
    /// The error message.
    pub message: String,
    /// The conflicting static mappings.
    pub conflicts: Vec<TraceStaticMapping>,
}

impl TraceConflictedMappingException {
    /// Create a new conflict exception.
    pub fn new(
        message: impl Into<String>,
        conflicts: Vec<TraceStaticMapping>,
    ) -> Self {
        Self {
            message: message.into(),
            conflicts,
        }
    }

    /// Get the conflicting mappings.
    pub fn get_conflicts(&self) -> &[TraceStaticMapping] {
        &self.conflicts
    }
}

impl std::fmt::Display for TraceConflictedMappingException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.message, self.conflicts)
    }
}

impl std::error::Error for TraceConflictedMappingException {}

/// Builder for constructing a module space with modules and sections.
pub struct ModuleSpaceBuilder {
    space: TraceModuleSpace,
    next_module_key: i64,
    next_section_key: i64,
}

impl ModuleSpaceBuilder {
    /// Create a new builder for the given address space.
    pub fn new(address_space: impl Into<String>) -> Self {
        Self {
            space: TraceModuleSpace::new(address_space),
            next_module_key: 1,
            next_section_key: 1,
        }
    }

    /// Add a module.
    pub fn add_module(
        mut self,
        path: impl Into<String>,
        name: impl Into<String>,
        min_address: u64,
        max_address: u64,
        lifespan: Lifespan,
    ) -> Self {
        let key = self.next_module_key;
        self.next_module_key += 1;
        self.space.add_module(TraceModule::new(
            key,
            path,
            name,
            min_address,
            max_address,
            lifespan,
        ));
        self
    }

    /// Add a section to the most recently added module.
    pub fn add_section(
        mut self,
        path: impl Into<String>,
        name: impl Into<String>,
        min_address: u64,
        max_address: u64,
    ) -> Self {
        let module_key = self.next_module_key - 1;
        let key = self.next_section_key;
        self.next_section_key += 1;
        self.space.add_section(TraceSection::new(
            key,
            module_key,
            path,
            name,
            min_address,
            max_address,
        ));
        self
    }

    /// Build the module space.
    pub fn build(self) -> TraceModuleSpace {
        self.space
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_space_basic() {
        let mut space = TraceModuleSpace::new("ram");
        assert_eq!(space.address_space(), "ram");
        assert!(space.modules.is_empty());

        space.add_module(TraceModule::new(
            1,
            "/lib/libc.so",
            "libc.so",
            0x7f00_0000,
            0x7f01_0000,
            Lifespan::span(0, 100),
        ));
        assert_eq!(space.modules.len(), 1);
    }

    #[test]
    fn test_module_space_loaded_modules() {
        let space = ModuleSpaceBuilder::new("ram")
            .add_module(
                "/lib/libc.so",
                "libc.so",
                0x7f00_0000,
                0x7f01_0000,
                Lifespan::span(0, 50),
            )
            .add_module(
                "/lib/libm.so",
                "libm.so",
                0x7f02_0000,
                0x7f03_0000,
                Lifespan::span(25, 100),
            )
            .build();

        assert_eq!(space.get_loaded_modules(0).len(), 1);
        assert_eq!(space.get_loaded_modules(30).len(), 2);
        assert_eq!(space.get_loaded_modules(60).len(), 1);
    }

    #[test]
    fn test_module_space_modules_at() {
        let space = ModuleSpaceBuilder::new("ram")
            .add_module(
                "/lib/libc.so",
                "libc.so",
                0x7f00_0000,
                0x7f01_0000,
                Lifespan::span(0, 100),
            )
            .build();

        assert_eq!(space.get_modules_at(50, 0x7f00_5000).len(), 1);
        assert_eq!(space.get_modules_at(50, 0x8000_0000).len(), 0);
    }

    #[test]
    fn test_module_space_sections() {
        let space = ModuleSpaceBuilder::new("ram")
            .add_module(
                "/lib/libc.so",
                "libc.so",
                0x7f00_0000,
                0x7f01_0000,
                Lifespan::span(0, 100),
            )
            .add_section("/lib/libc.so", ".text", 0x7f00_1000, 0x7f00_5000)
            .add_section("/lib/libc.so", ".data", 0x7f00_6000, 0x7f00_8000)
            .build();

        assert_eq!(space.sections.len(), 2);
        assert_eq!(space.sections_for_module(1).len(), 2);
    }

    #[test]
    fn test_module_space_get_modules_intersecting() {
        let space = ModuleSpaceBuilder::new("ram")
            .add_module(
                "/lib/libc.so",
                "libc.so",
                0x7f00_0000,
                0x7f01_0000,
                Lifespan::span(0, 100),
            )
            .build();

        let result = space.get_modules_intersecting(&Lifespan::span(50, 150), 0x7f00_5000, 0x7f02_0000);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_module_operations_trait() {
        let space = ModuleSpaceBuilder::new("ram")
            .add_module(
                "/lib/libc.so",
                "libc.so",
                0x7f00_0000,
                0x7f01_0000,
                Lifespan::span(0, 100),
            )
            .build();

        let ops: &dyn TraceModuleOperations = &space;
        assert_eq!(ops.get_all_modules().len(), 1);
        assert_eq!(ops.get_loaded_modules(50).len(), 1);
        assert_eq!(ops.get_loaded_modules(150).len(), 0);
    }

    #[test]
    fn test_conflicted_mapping_exception() {
        let exc = TraceConflictedMappingException::new("conflict", vec![]);
        assert_eq!(exc.message, "conflict");
        assert!(exc.get_conflicts().is_empty());
        assert!(format!("{}", exc).contains("conflict"));
    }

    #[test]
    fn test_module_by_name() {
        let space = ModuleSpaceBuilder::new("ram")
            .add_module(
                "/lib/libc.so",
                "libc.so",
                0x7f00_0000,
                0x7f01_0000,
                Lifespan::span(0, 100),
            )
            .build();

        assert!(space.get_module_by_name("libc.so").is_some());
        assert!(space.get_module_by_name("libm.so").is_none());
    }
}
