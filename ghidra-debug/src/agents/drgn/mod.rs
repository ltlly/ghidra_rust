//! drgn agent for Linux kernel debugging.
//!
//! Rust port of Ghidra's `Debugger-agent-drgn`. This module provides
//! the drgn agent backend that uses the drgn Python library for
//! Linux kernel and userspace debugging.
//!
//! drgn uses "Processes[N]" as its process path prefix, with
//! `RelocatableModule` support for kernel modules.

pub mod arch;
pub mod commands;
pub mod connection;
pub mod drgn_inferior_process;
pub mod drgn_thread;
pub mod hooks;

use serde::{Deserialize, Serialize};

/// drgn-specific object path patterns.
pub mod paths {
    pub const PROCESSES: &str = "Processes";
    pub const PROCESS: &str = "Processes[{procnum}]";
    pub const THREADS: &str = "Processes[{procnum}].Threads";
    pub const THREAD: &str = "Processes[{procnum}].Threads[{tnum}]";
    pub const STACK: &str = "Processes[{procnum}].Threads[{tnum}].Stack";
    pub const FRAME: &str = "Processes[{procnum}].Threads[{tnum}].Stack[{level}]";
    pub const REGS: &str = "Processes[{procnum}].Threads[{tnum}].Stack[{level}].Registers";
    pub const LOCALS: &str = "Processes[{procnum}].Threads[{tnum}].Stack[{level}].Locals";
    pub const MEMORY: &str = "Processes[{procnum}].Memory";
    pub const MODULES: &str = "Processes[{procnum}].Modules";
    pub const MODULE: &str = "Processes[{procnum}].Modules[{modbase}]";
    pub const SECTIONS: &str = "Processes[{procnum}].Modules[{modbase}].Sections";
    pub const ENVIRONMENT: &str = "Processes[{procnum}].Environment";
    pub const SYMBOLS: &str = "Processes[{procnum}].Symbols";
    pub const BREAKPOINTS: &str = "Breakpoints";
    pub const BREAKPOINT: &str = "Breakpoints[{id}]";
}

/// drgn version information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrgnVersion {
    /// Full version string.
    pub full: String,
    /// Version number.
    pub version: String,
    /// Whether kernel debugging is supported.
    pub kernel_supported: bool,
    /// Whether RelocatableModule is available.
    pub relocatable_module_supported: bool,
}

impl DrgnVersion {
    /// Create a new version.
    pub fn new(full: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            full: full.into(),
            version: version.into(),
            kernel_supported: true,
            relocatable_module_supported: true,
        }
    }
}

/// State tracking for the drgn agent.
#[derive(Debug, Default)]
pub struct DrgnState {
    /// Whether a trace is active.
    pub trace_active: bool,
    /// Whether hooks are installed.
    pub hooks_installed: bool,
    /// Currently synchronized process IDs.
    pub synced_processes: Vec<u32>,
    /// Selected process.
    pub selected_process: Option<u32>,
    /// Selected thread.
    pub selected_thread: Option<u32>,
    /// Selected frame.
    pub selected_frame: Option<u32>,
    /// Whether this is a kernel debug session.
    pub is_kernel: bool,
}

impl DrgnState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all tracking state.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Mark a process as synchronized.
    pub fn sync_process(&mut self, proc_id: u32) {
        if !self.synced_processes.contains(&proc_id) {
            self.synced_processes.push(proc_id);
        }
    }

    /// Check if a process is synchronized.
    pub fn is_process_synced(&self, proc_id: u32) -> bool {
        self.synced_processes.contains(&proc_id)
    }
}

/// A drgn module descriptor (equivalent to drgn.Module / drgn.RelocatableModule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrgnModuleInfo {
    /// Module name.
    pub name: String,
    /// Address range (start, end).
    pub address_range: (u64, u64),
    /// Build ID.
    pub build_id: Option<String>,
    /// Debug file bias.
    pub debug_file_bias: Option<u64>,
    /// Debug file path.
    pub debug_file_path: Option<String>,
    /// Debug file status.
    pub debug_file_status: Option<String>,
    /// Loaded file bias.
    pub loaded_file_bias: Option<u64>,
    /// Loaded file path.
    pub loaded_file_path: Option<String>,
    /// Loaded file status.
    pub loaded_file_status: Option<String>,
    /// Whether this is a relocatable module (kernel module).
    pub is_relocatable: bool,
}

impl DrgnModuleInfo {
    /// Get the base address.
    pub fn base(&self) -> u64 {
        self.address_range.0
    }

    /// Get the size.
    pub fn size(&self) -> u64 {
        self.address_range.1 - self.address_range.0
    }
}

/// A section in a relocatable module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrgnSectionInfo {
    /// Section name.
    pub name: String,
    /// Section address.
    pub address: u64,
    /// Section size.
    pub size: u64,
}

/// A symbol from the drgn program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrgnSymbolInfo {
    /// Symbol name.
    pub name: String,
    /// Symbol address.
    pub address: u64,
    /// Symbol size.
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drgn_state() {
        let mut state = DrgnState::new();
        state.is_kernel = true;
        state.sync_process(0);
        assert!(state.is_process_synced(0));
        state.reset();
        assert!(!state.is_kernel);
    }

    #[test]
    fn test_drgn_module_info() {
        let m = DrgnModuleInfo {
            name: "virtio_net".to_string(),
            address_range: (0xffffffffa0000000, 0xffffffffa0010000),
            build_id: Some("abc123".to_string()),
            debug_file_bias: None,
            debug_file_path: None,
            debug_file_status: None,
            loaded_file_bias: None,
            loaded_file_path: Some("/lib/modules/5.15.0/kernel/drivers/net/virtio_net.ko".to_string()),
            loaded_file_status: None,
            is_relocatable: true,
        };
        assert_eq!(m.base(), 0xffffffffa0000000);
        assert_eq!(m.size(), 0x10000);
    }

    #[test]
    fn test_drgn_version() {
        let ver = DrgnVersion::new("drgn 0.0.24", "0.0.24");
        assert!(ver.kernel_supported);
    }
}
