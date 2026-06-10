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

/// GDB stop reason.
///
/// Represents why a thread stopped. In GDB's Python API, stop reasons
/// are communicated via `StopEvent` and its `breakpoints` attribute, or
/// via `InferiorThread.is_stopped()` combined with the stop reason.
/// In GDB/MI, the stop reason appears in `*stopped` async records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GdbStopReason {
    /// Breakpoint hit.
    Breakpoint,
    /// Watchpoint hit.
    Watchpoint,
    /// Read watchpoint hit.
    ReadWatchpoint,
    /// Access watchpoint hit.
    AccessWatchpoint,
    /// Signal received.
    Signal,
    /// Step completed (step-over, step-into, step-inst).
    StepComplete,
    /// Function call finished (step-out / finish).
    FunctionFinished,
    /// Exited normally.
    Exited,
    /// Exited with signal.
    ExitedSignalled,
    /// Location reached (run-to-address completed).
    LocationReached,
    /// Fork.
    Fork,
    /// VFork.
    VFork,
    /// Syscall entry/exit.
    SyscallEntry,
    /// Solib event (shared library loaded/unloaded).
    SolibEvent,
    /// Exec.
    Exec,
    /// Unknown or unspecified.
    Unknown,
}

impl GdbStopReason {
    /// Convert from GDB/MI stop reason string.
    pub fn from_gdb(reason: &str) -> Self {
        match reason.to_lowercase().as_str() {
            "breakpoint-hit" | "breakpoint" => Self::Breakpoint,
            "watchpoint-trigger" | "watchpoint" => Self::Watchpoint,
            "read-watchpoint-trigger" | "read-watchpoint" => Self::ReadWatchpoint,
            "access-watchpoint-trigger" | "access-watchpoint" => Self::AccessWatchpoint,
            "signal-received" | "signal" => Self::Signal,
            "end-stepping-range" | "location-reached" => Self::StepComplete,
            "function-finished" => Self::FunctionFinished,
            "exited-normally" => Self::Exited,
            "exited-signalled" => Self::ExitedSignalled,
            "fork" => Self::Fork,
            "vfork" => Self::VFork,
            "syscall-entry" => Self::SyscallEntry,
            "solib-event" => Self::SolibEvent,
            "exec" => Self::Exec,
            _ => Self::Unknown,
        }
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Breakpoint => "Breakpoint hit",
            Self::Watchpoint => "Watchpoint triggered",
            Self::ReadWatchpoint => "Read watchpoint triggered",
            Self::AccessWatchpoint => "Access watchpoint triggered",
            Self::Signal => "Signal received",
            Self::StepComplete => "Step completed",
            Self::FunctionFinished => "Function finished",
            Self::Exited => "Exited normally",
            Self::ExitedSignalled => "Exited with signal",
            Self::LocationReached => "Location reached",
            Self::Fork => "Fork",
            Self::VFork => "VFork",
            Self::SyscallEntry => "Syscall entry",
            Self::SolibEvent => "Shared library event",
            Self::Exec => "Exec",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this reason implies the inferior is stopped (can be resumed).
    pub fn is_stopped(&self) -> bool {
        !matches!(self, Self::Exited | Self::ExitedSignalled | Self::Unknown)
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

    #[test]
    fn test_gdb_stop_reason_from_gdb() {
        assert_eq!(GdbStopReason::from_gdb("breakpoint-hit"), GdbStopReason::Breakpoint);
        assert_eq!(GdbStopReason::from_gdb("signal-received"), GdbStopReason::Signal);
        assert_eq!(GdbStopReason::from_gdb("end-stepping-range"), GdbStopReason::StepComplete);
        assert_eq!(GdbStopReason::from_gdb("function-finished"), GdbStopReason::FunctionFinished);
        assert_eq!(GdbStopReason::from_gdb("exited-normally"), GdbStopReason::Exited);
        assert_eq!(GdbStopReason::from_gdb("exited-signalled"), GdbStopReason::ExitedSignalled);
        assert_eq!(GdbStopReason::from_gdb("watchpoint-trigger"), GdbStopReason::Watchpoint);
        assert_eq!(GdbStopReason::from_gdb("fork"), GdbStopReason::Fork);
        assert_eq!(GdbStopReason::from_gdb("unknown_reason"), GdbStopReason::Unknown);
    }

    #[test]
    fn test_gdb_stop_reason_description() {
        assert_eq!(GdbStopReason::Breakpoint.description(), "Breakpoint hit");
        assert_eq!(GdbStopReason::Signal.description(), "Signal received");
        assert_eq!(GdbStopReason::StepComplete.description(), "Step completed");
    }

    #[test]
    fn test_gdb_stop_reason_is_stopped() {
        assert!(GdbStopReason::Breakpoint.is_stopped());
        assert!(GdbStopReason::Signal.is_stopped());
        assert!(GdbStopReason::StepComplete.is_stopped());
        assert!(!GdbStopReason::Exited.is_stopped());
        assert!(!GdbStopReason::ExitedSignalled.is_stopped());
        assert!(!GdbStopReason::Unknown.is_stopped());
    }
}
