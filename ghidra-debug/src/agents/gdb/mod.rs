//! GDB debugger agent.
//!
//! Rust port of Ghidra's `Debugger-agent-gdb`. This module provides
//! the GDB agent backend that communicates with GDB via GDB/MI protocol
//! and Python extensions (ghidragdb).
//!
//! GDB uses "Inferiors[N]" as its process path prefix, which is mapped
//! to the Ghidra trace object hierarchy.

pub mod arch;
pub mod commands;
pub mod connection;
pub mod gdb_inferior_process;
pub mod gdb_thread;
pub mod hooks;

use serde::{Deserialize, Serialize};

/// GDB-specific object path patterns.
///
/// GDB uses `Inferiors[N]` instead of `Processes[N]`.
pub mod paths {
    /// Inferior container path.
    pub const INFERIORS: &str = "Inferiors";
    /// Single inferior path.
    pub const INFERIOR: &str = "Inferiors[{infnum}]";
    /// Threads within an inferior.
    pub const THREADS: &str = "Inferiors[{infnum}].Threads";
    /// Single thread.
    pub const THREAD: &str = "Inferiors[{infnum}].Threads[{tnum}]";
    /// Stack for a thread.
    pub const STACK: &str = "Inferiors[{infnum}].Threads[{tnum}].Stack";
    /// Single stack frame.
    pub const FRAME: &str = "Inferiors[{infnum}].Threads[{tnum}].Stack[{level}]";
    /// Registers for a frame.
    pub const REGS: &str = "Inferiors[{infnum}].Threads[{tnum}].Stack[{level}].Registers";
    /// Memory space.
    pub const MEMORY: &str = "Inferiors[{infnum}].Memory";
    /// Modules container.
    pub const MODULES: &str = "Inferiors[{infnum}].Modules";
    /// Single module.
    pub const MODULE: &str = "Inferiors[{infnum}].Modules[{modpath}]";
    /// Environment.
    pub const ENVIRONMENT: &str = "Inferiors[{infnum}].Environment";
}

/// GDB version information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GdbVersion {
    /// Full version string.
    pub full: String,
    /// Name (e.g. "GNU gdb").
    pub name: String,
    /// Dotted version (e.g. "13.2").
    pub dotted: String,
    /// Target architecture.
    pub arch: String,
}

impl GdbVersion {
    /// Parse a GDB version string.
    pub fn parse(version_str: &str) -> Self {
        let parts: Vec<&str> = version_str.split_whitespace().collect();
        let name = parts.first().map(|s| s.to_string()).unwrap_or_default();
        let dotted = parts.get(..).map(|p| {
            p.iter().find(|s| s.chars().any(|c| c.is_ascii_digit() && s.contains('.')))
                .unwrap_or(&"0.0")
                .to_string()
        }).unwrap_or_else(|| "0.0".to_string());
        Self {
            full: version_str.to_string(),
            name,
            dotted,
            arch: String::new(),
        }
    }
}

/// State tracking for the GDB agent.
#[derive(Debug, Default)]
pub struct GdbState {
    /// Whether a trace is active.
    pub trace_active: bool,
    /// Whether hooks are installed.
    pub hooks_installed: bool,
    /// Currently synchronized inferior IDs.
    pub synced_infegers: Vec<u32>,
    /// Selected inferior number.
    pub selected_inferior: Option<u32>,
    /// Selected thread number.
    pub selected_thread: Option<u32>,
    /// Selected frame level.
    pub selected_frame: Option<u32>,
}

impl GdbState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all tracking state.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Mark an inferior as synchronized.
    pub fn sync_inferior(&mut self, inf: u32) {
        if !self.synced_infegers.contains(&inf) {
            self.synced_infegers.push(inf);
        }
    }

    /// Check if an inferior is synchronized.
    pub fn is_inferior_synced(&self, inf: u32) -> bool {
        self.synced_infegers.contains(&inf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdb_version_parse() {
        let v = GdbVersion::parse("GNU gdb (Ubuntu 13.2-0ubuntu1) 13.2");
        assert_eq!(v.name, "GNU");
        assert!(v.full.contains("13.2"));
    }

    #[test]
    fn test_gdb_state() {
        let mut state = GdbState::new();
        assert!(!state.trace_active);
        state.trace_active = true;
        state.sync_inferior(1);
        assert!(state.is_inferior_synced(1));
        assert!(!state.is_inferior_synced(2));
        state.reset();
        assert!(!state.trace_active);
    }

    #[test]
    fn test_gdb_paths() {
        assert_eq!(paths::INFERIORS, "Inferiors");
        assert!(paths::THREAD.contains("{infnum}"));
        assert!(paths::REGS.contains("{level}"));
    }
}
