//! Thread access for pcode trace execution.
//!
//! Ported from Ghidra's `DefaultPcodeTraceThreadAccess` in
//! `ghidra.pcode.exec.trace.data`. Provides thread-specific data
//! access during pcode execution over traces.

use serde::{Deserialize, Serialize};

/// Default pcode trace thread access.
///
/// Provides thread context during pcode execution, including the
/// current thread, process, and their register/memory state.
///
/// Ported from `DefaultPcodeTraceThreadAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultPcodeTraceThreadAccess {
    /// The thread key (unique identifier within the trace).
    pub thread_key: i64,
    /// The process key (parent of the thread).
    pub process_key: i64,
    /// The snap at which this access is valid.
    pub snap: i64,
    /// The thread name.
    pub thread_name: String,
    /// The process name.
    pub process_name: String,
    /// The program counter register name (e.g., "PC", "RIP", "EIP").
    pub pc_register_name: String,
    /// The stack pointer register name (e.g., "SP", "RSP", "ESP").
    pub sp_register_name: String,
}

impl DefaultPcodeTraceThreadAccess {
    /// Create a new thread access.
    pub fn new(
        thread_key: i64,
        process_key: i64,
        snap: i64,
        thread_name: impl Into<String>,
        process_name: impl Into<String>,
    ) -> Self {
        Self {
            thread_key,
            process_key,
            snap,
            thread_name: thread_name.into(),
            process_name: process_name.into(),
            pc_register_name: "PC".into(),
            sp_register_name: "SP".into(),
        }
    }

    /// Set the PC register name.
    pub fn with_pc_register(mut self, name: impl Into<String>) -> Self {
        self.pc_register_name = name.into();
        self
    }

    /// Set the SP register name.
    pub fn with_sp_register(mut self, name: impl Into<String>) -> Self {
        self.sp_register_name = name.into();
        self
    }

    /// Whether this access is for the given thread.
    pub fn is_thread(&self, thread_key: i64) -> bool {
        self.thread_key == thread_key
    }

    /// Whether this access is for the given process.
    pub fn is_process(&self, process_key: i64) -> bool {
        self.process_key == process_key
    }
}

/// Access scope for pcode trace data operations.
///
/// Defines what data is accessible during pcode execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcodeTraceAccessScope {
    /// Full access to all trace data.
    Full,
    /// Read-only access (no writes).
    ReadOnly,
    /// Access limited to a specific thread's registers.
    ThreadOnly,
    /// Access limited to a specific process.
    ProcessOnly,
}

impl Default for PcodeTraceAccessScope {
    fn default() -> Self {
        Self::Full
    }
}

/// A composite pcode trace data access configuration.
///
/// Combines thread access with scope and memory access information
/// for comprehensive pcode execution context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTraceDataAccessConfig {
    /// The thread access context.
    pub thread_access: DefaultPcodeTraceThreadAccess,
    /// The access scope.
    pub scope: PcodeTraceAccessScope,
    /// Whether to track memory reads.
    pub track_reads: bool,
    /// Whether to track memory writes.
    pub track_writes: bool,
    /// Whether to track register reads.
    pub track_register_reads: bool,
    /// Whether to track register writes.
    pub track_register_writes: bool,
    /// Names of address spaces that are accessible.
    pub accessible_spaces: Vec<String>,
}

impl PcodeTraceDataAccessConfig {
    /// Create a new configuration with default settings.
    pub fn new(thread_access: DefaultPcodeTraceThreadAccess) -> Self {
        Self {
            thread_access,
            scope: PcodeTraceAccessScope::Full,
            track_reads: false,
            track_writes: false,
            track_register_reads: false,
            track_register_writes: false,
            accessible_spaces: Vec::new(),
        }
    }

    /// Enable read tracking.
    pub fn with_read_tracking(mut self) -> Self {
        self.track_reads = true;
        self.track_register_reads = true;
        self
    }

    /// Enable write tracking.
    pub fn with_write_tracking(mut self) -> Self {
        self.track_writes = true;
        self.track_register_writes = true;
        self
    }

    /// Set the access scope.
    pub fn with_scope(mut self, scope: PcodeTraceAccessScope) -> Self {
        self.scope = scope;
        self
    }

    /// Add an accessible address space.
    pub fn add_space(&mut self, space: impl Into<String>) {
        self.accessible_spaces.push(space.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_access() {
        let access = DefaultPcodeTraceThreadAccess::new(1, 10, 0, "main", "test.exe")
            .with_pc_register("RIP")
            .with_sp_register("RSP");

        assert_eq!(access.thread_key, 1);
        assert_eq!(access.process_key, 10);
        assert_eq!(access.thread_name, "main");
        assert_eq!(access.pc_register_name, "RIP");
        assert_eq!(access.sp_register_name, "RSP");
        assert!(access.is_thread(1));
        assert!(!access.is_thread(2));
        assert!(access.is_process(10));
    }

    #[test]
    fn test_access_scope() {
        assert_eq!(PcodeTraceAccessScope::default(), PcodeTraceAccessScope::Full);
        assert_ne!(
            PcodeTraceAccessScope::ReadOnly,
            PcodeTraceAccessScope::ThreadOnly
        );
    }

    #[test]
    fn test_data_access_config() {
        let thread = DefaultPcodeTraceThreadAccess::new(1, 10, 0, "main", "test.exe");
        let config = PcodeTraceDataAccessConfig::new(thread)
            .with_read_tracking()
            .with_write_tracking()
            .with_scope(PcodeTraceAccessScope::ThreadOnly);

        assert!(config.track_reads);
        assert!(config.track_writes);
        assert_eq!(config.scope, PcodeTraceAccessScope::ThreadOnly);
    }

    #[test]
    fn test_data_access_config_spaces() {
        let thread = DefaultPcodeTraceThreadAccess::new(1, 10, 0, "main", "test.exe");
        let mut config = PcodeTraceDataAccessConfig::new(thread);
        config.add_space("ram");
        config.add_space("register");
        assert_eq!(config.accessible_spaces.len(), 2);
    }
}
