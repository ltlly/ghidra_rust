//! Program emulation utilities for the debugger plugin.
//!
//! Ported from Ghidra's `ProgramEmulationUtils`.
//!
//! Provides utilities for setting up and managing emulation of programs
//! within the debugger, including initial state setup, memory region
//! creation, and register initialization.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The type of emulation initialization to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmulationInitType {
    /// Initialize from the current program state.
    FromProgram,
    /// Initialize from a saved trace snapshot.
    FromSnapshot,
    /// Initialize from a core dump.
    FromCoreDump,
    /// Initialize from a minimal state (bare minimum registers).
    Minimal,
}

/// Configuration for program emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationConfig {
    /// The type of initialization.
    pub init_type: EmulationInitType,
    /// The snap to start emulation at.
    pub start_snap: i64,
    /// The thread ID to emulate (None for all threads).
    pub thread_id: Option<u64>,
    /// Initial register values (register name -> value bytes).
    pub initial_registers: HashMap<String, Vec<u8>>,
    /// Memory regions to map (space name -> (offset, size, permissions)).
    pub memory_regions: Vec<MemoryRegionMapping>,
    /// Whether to copy memory contents from the program.
    pub copy_memory: bool,
    /// Whether to copy register context from the program.
    pub copy_context: bool,
    /// Maximum number of emulation steps before timeout.
    pub max_steps: u64,
}

impl EmulationConfig {
    /// Create a new emulation config with default settings.
    pub fn new(init_type: EmulationInitType) -> Self {
        Self {
            init_type,
            start_snap: 0,
            thread_id: None,
            initial_registers: HashMap::new(),
            memory_regions: Vec::new(),
            copy_memory: true,
            copy_context: true,
            max_steps: 10000,
        }
    }

    /// Set the start snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.start_snap = snap;
        self
    }

    /// Set the thread ID.
    pub fn with_thread(mut self, thread_id: u64) -> Self {
        self.thread_id = Some(thread_id);
        self
    }

    /// Add an initial register value.
    pub fn with_register(mut self, name: impl Into<String>, value: Vec<u8>) -> Self {
        self.initial_registers.insert(name.into(), value);
        self
    }

    /// Add a memory region mapping.
    pub fn with_memory_region(mut self, region: MemoryRegionMapping) -> Self {
        self.memory_regions.push(region);
        self
    }

    /// Set whether to copy memory contents.
    pub fn with_copy_memory(mut self, copy: bool) -> Self {
        self.copy_memory = copy;
        self
    }

    /// Set the maximum steps.
    pub fn with_max_steps(mut self, max_steps: u64) -> Self {
        self.max_steps = max_steps;
        self
    }
}

/// Permissions for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPermissions {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub execute: bool,
}

impl MemoryPermissions {
    /// Read-only permissions.
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };

    /// Read-write permissions.
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };

    /// Read-execute permissions.
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };

    /// Read-write-execute permissions.
    pub const RWX: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
}

impl Default for MemoryPermissions {
    fn default() -> Self {
        Self::RW
    }
}

/// A memory region mapping for emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionMapping {
    /// The address space name.
    pub space_name: String,
    /// The start offset.
    pub offset: u64,
    /// The size in bytes.
    pub size: u64,
    /// The permissions.
    pub permissions: MemoryPermissions,
    /// The initial content (None for zero-fill).
    pub content: Option<Vec<u8>>,
    /// The name of this region.
    pub name: String,
}

impl MemoryRegionMapping {
    /// Create a new memory region mapping.
    pub fn new(
        space_name: impl Into<String>,
        offset: u64,
        size: u64,
        permissions: MemoryPermissions,
    ) -> Self {
        Self {
            space_name: space_name.into(),
            offset,
            size,
            permissions,
            content: None,
            name: String::new(),
        }
    }

    /// Set the initial content.
    pub fn with_content(mut self, content: Vec<u8>) -> Self {
        self.content = Some(content);
        self
    }

    /// Set the region name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

/// The result of setting up program emulation.
#[derive(Debug, Clone)]
pub struct EmulationSetupResult {
    /// The trace key where emulation state was set up.
    pub trace_key: i64,
    /// The snap at which emulation starts.
    pub start_snap: i64,
    /// The thread ID being emulated.
    pub thread_id: Option<u64>,
    /// The memory regions that were mapped.
    pub mapped_regions: Vec<MemoryRegionMapping>,
    /// Registers that were initialized.
    pub initialized_registers: Vec<String>,
    /// Any warnings generated during setup.
    pub warnings: Vec<String>,
}

/// Utility functions for program emulation.
pub struct ProgramEmulationUtils;

impl ProgramEmulationUtils {
    /// Set up emulation from a program view.
    ///
    /// This creates a new trace snapshot and initializes it with
    /// the program's memory, registers, and context.
    pub fn setup_from_program(
        program_name: &str,
        config: &EmulationConfig,
    ) -> EmulationSetupResult {
        // In a real implementation, this would:
        // 1. Create a new trace snapshot
        // 2. Copy memory regions from the program
        // 3. Initialize registers from the program context
        // 4. Set up the initial stack
        let mut result = EmulationSetupResult {
            trace_key: 0,
            start_snap: config.start_snap,
            thread_id: config.thread_id,
            mapped_regions: config.memory_regions.clone(),
            initialized_registers: config.initial_registers.keys().cloned().collect(),
            warnings: Vec::new(),
        };
        if program_name.is_empty() {
            result
                .warnings
                .push("No program name provided".to_string());
        }
        result
    }

    /// Create a stack region for emulation.
    pub fn create_stack_region(
        space_name: &str,
        stack_base: u64,
        stack_size: u64,
    ) -> MemoryRegionMapping {
        MemoryRegionMapping::new(space_name, stack_base, stack_size, MemoryPermissions::RW)
            .with_name("Stack")
    }

    /// Create a code region for emulation.
    pub fn create_code_region(
        space_name: &str,
        code_start: u64,
        code_size: u64,
    ) -> MemoryRegionMapping {
        MemoryRegionMapping::new(space_name, code_start, code_size, MemoryPermissions::RX)
            .with_name("Code")
    }

    /// Create a data region for emulation.
    pub fn create_data_region(
        space_name: &str,
        data_start: u64,
        data_size: u64,
    ) -> MemoryRegionMapping {
        MemoryRegionMapping::new(space_name, data_start, data_size, MemoryPermissions::RW)
            .with_name("Data")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulation_config_default() {
        let config = EmulationConfig::new(EmulationInitType::FromProgram);
        assert_eq!(config.init_type, EmulationInitType::FromProgram);
        assert_eq!(config.start_snap, 0);
        assert!(config.thread_id.is_none());
        assert!(config.copy_memory);
        assert!(config.copy_context);
        assert_eq!(config.max_steps, 10000);
    }

    #[test]
    fn test_emulation_config_builder() {
        let config = EmulationConfig::new(EmulationInitType::Minimal)
            .with_snap(5)
            .with_thread(1)
            .with_register("RAX".to_string(), vec![0; 8])
            .with_max_steps(1000);

        assert_eq!(config.start_snap, 5);
        assert_eq!(config.thread_id, Some(1));
        assert!(config.initial_registers.contains_key("RAX"));
        assert_eq!(config.max_steps, 1000);
    }

    #[test]
    fn test_memory_permissions() {
        assert!(MemoryPermissions::R.read);
        assert!(!MemoryPermissions::R.write);
        assert!(!MemoryPermissions::R.execute);

        assert!(MemoryPermissions::RWX.read);
        assert!(MemoryPermissions::RWX.write);
        assert!(MemoryPermissions::RWX.execute);

        assert!(!MemoryPermissions::RX.write);
    }

    #[test]
    fn test_memory_region_mapping() {
        let region = MemoryRegionMapping::new("ram", 0x400000, 0x1000, MemoryPermissions::RX)
            .with_name(".text")
            .with_content(vec![0x90; 0x1000]);

        assert_eq!(region.space_name, "ram");
        assert_eq!(region.offset, 0x400000);
        assert_eq!(region.size, 0x1000);
        assert_eq!(region.name, ".text");
        assert!(region.content.is_some());
        assert_eq!(region.content.unwrap().len(), 0x1000);
    }

    #[test]
    fn test_program_emulation_utils_setup() {
        let config = EmulationConfig::new(EmulationInitType::FromProgram)
            .with_register("RSP", vec![0, 0, 0, 0, 0, 0, 0, 0xF0]);

        let result = ProgramEmulationUtils::setup_from_program("test.exe", &config);
        assert!(result.warnings.is_empty());
        assert_eq!(result.initialized_registers.len(), 1);
    }

    #[test]
    fn test_program_emulation_utils_setup_empty_name() {
        let config = EmulationConfig::new(EmulationInitType::Minimal);
        let result = ProgramEmulationUtils::setup_from_program("", &config);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_create_stack_region() {
        let region = ProgramEmulationUtils::create_stack_region("ram", 0x7FFF0000, 0x10000);
        assert_eq!(region.space_name, "ram");
        assert_eq!(region.offset, 0x7FFF0000);
        assert_eq!(region.size, 0x10000);
        assert_eq!(region.name, "Stack");
        assert!(region.permissions.read);
        assert!(region.permissions.write);
        assert!(!region.permissions.execute);
    }

    #[test]
    fn test_create_code_region() {
        let region = ProgramEmulationUtils::create_code_region("ram", 0x400000, 0x1000);
        assert_eq!(region.name, "Code");
        assert!(region.permissions.execute);
        assert!(!region.permissions.write);
    }

    #[test]
    fn test_create_data_region() {
        let region = ProgramEmulationUtils::create_data_region("ram", 0x600000, 0x2000);
        assert_eq!(region.name, "Data");
        assert!(region.permissions.write);
        assert!(!region.permissions.execute);
    }

    #[test]
    fn test_emulation_init_types() {
        assert_ne!(EmulationInitType::FromProgram, EmulationInitType::Minimal);
        assert_ne!(EmulationInitType::FromSnapshot, EmulationInitType::FromCoreDump);
    }

    #[test]
    fn test_emulation_setup_result_defaults() {
        let config = EmulationConfig::new(EmulationInitType::Minimal);
        let result = ProgramEmulationUtils::setup_from_program("test", &config);
        assert_eq!(result.start_snap, 0);
        assert!(result.thread_id.is_none());
        assert!(result.mapped_regions.is_empty());
    }
}
