//! Pcode trace access layer.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace` package.
//! Provides access to trace data for pcode emulation, including
//! memory reads/writes, register access, and data access patterns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The type of access to trace memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceAccessType {
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// Execute access.
    Execute,
    /// Read-write access.
    ReadWrite,
}

impl TraceAccessType {
    /// Whether this access type includes read.
    pub fn is_read(&self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite | Self::Execute)
    }

    /// Whether this access type includes write.
    pub fn is_write(&self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }

    /// Whether this access type includes execute.
    pub fn is_execute(&self) -> bool {
        matches!(self, Self::Execute)
    }
}

/// A record of a memory access during pcode execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryAccessRecord {
    /// The address that was accessed.
    pub address: u64,
    /// The size in bytes.
    pub size: u32,
    /// The type of access.
    pub access_type: TraceAccessType,
    /// The bytes read or written (for debugging/tracing).
    pub bytes: Vec<u8>,
    /// The snapshot at which the access occurred.
    pub snap: i64,
}

impl TraceMemoryAccessRecord {
    /// Create a new memory access record.
    pub fn new(
        address: u64,
        size: u32,
        access_type: TraceAccessType,
        bytes: Vec<u8>,
        snap: i64,
    ) -> Self {
        Self {
            address,
            size,
            access_type,
            bytes,
            snap,
        }
    }

    /// Get the end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.size as u64
    }
}

/// Configuration for pcode trace access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTraceAccessConfig {
    /// The trace key.
    pub trace_key: i64,
    /// The snapshot to read from.
    pub snap: i64,
    /// The thread key (for register access).
    pub thread_key: Option<i64>,
    /// The frame level (for register access).
    pub frame_level: Option<i32>,
    /// Whether to record memory access history.
    pub record_accesses: bool,
}

impl PcodeTraceAccessConfig {
    /// Create a new config for the given trace and snapshot.
    pub fn new(trace_key: i64, snap: i64) -> Self {
        Self {
            trace_key,
            snap,
            thread_key: None,
            frame_level: None,
            record_accesses: false,
        }
    }

    /// Set the thread for register access.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Set the frame level.
    pub fn with_frame(mut self, frame_level: i32) -> Self {
        self.frame_level = Some(frame_level);
        self
    }

    /// Enable recording of memory accesses.
    pub fn with_recording(mut self, record: bool) -> Self {
        self.record_accesses = record;
        self
    }
}

/// Pcode memory access interface for traces.
///
/// Provides methods to read and write memory during pcode execution,
/// operating on trace data at a specific snapshot.
#[derive(Debug)]
pub struct PcodeTraceMemoryAccess {
    config: PcodeTraceAccessConfig,
    /// Recorded memory accesses (if enabled).
    access_log: Vec<TraceMemoryAccessRecord>,
}

impl PcodeTraceMemoryAccess {
    /// Create a new memory access interface.
    pub fn new(config: PcodeTraceAccessConfig) -> Self {
        Self {
            config,
            access_log: Vec::new(),
        }
    }

    /// Get the current config.
    pub fn config(&self) -> &PcodeTraceAccessConfig {
        &self.config
    }

    /// Get the access log.
    pub fn access_log(&self) -> &[TraceMemoryAccessRecord] {
        &self.access_log
    }

    /// Record a memory access.
    pub fn record_access(&mut self, record: TraceMemoryAccessRecord) {
        if self.config.record_accesses {
            self.access_log.push(record);
        }
    }

    /// Clear the access log.
    pub fn clear_log(&mut self) {
        self.access_log.clear();
    }

    /// Get the total number of recorded accesses.
    pub fn access_count(&self) -> usize {
        self.access_log.len()
    }
}

/// Pcode register access interface for traces.
///
/// Provides methods to read and write register values during pcode
/// execution, operating on trace register context at a specific snapshot.
#[derive(Debug)]
pub struct PcodeTraceRegistersAccess {
    config: PcodeTraceAccessConfig,
    /// Cache of register values for the current execution step.
    register_cache: HashMap<String, Vec<u8>>,
}

impl PcodeTraceRegistersAccess {
    /// Create a new register access interface.
    pub fn new(config: PcodeTraceAccessConfig) -> Self {
        Self {
            config,
            register_cache: HashMap::new(),
        }
    }

    /// Get the config.
    pub fn config(&self) -> &PcodeTraceAccessConfig {
        &self.config
    }

    /// Cache a register value.
    pub fn cache_register(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.register_cache.insert(name.into(), value);
    }

    /// Get a cached register value.
    pub fn get_cached(&self, name: &str) -> Option<&Vec<u8>> {
        self.register_cache.get(name)
    }

    /// Clear the register cache.
    pub fn clear_cache(&mut self) {
        self.register_cache.clear();
    }

    /// Get all cached register names.
    pub fn cached_registers(&self) -> Vec<&String> {
        self.register_cache.keys().collect()
    }
}

/// Pcode data access interface combining memory and register access.
#[derive(Debug)]
pub struct PcodeTraceDataAccess {
    /// The memory access layer.
    pub memory: PcodeTraceMemoryAccess,
    /// The register access layer.
    pub registers: PcodeTraceRegistersAccess,
}

impl PcodeTraceDataAccess {
    /// Create a new data access combining memory and registers.
    pub fn new(config: PcodeTraceAccessConfig) -> Self {
        Self {
            memory: PcodeTraceMemoryAccess::new(config.clone()),
            registers: PcodeTraceRegistersAccess::new(config),
        }
    }

    /// Get the trace key.
    pub fn trace_key(&self) -> i64 {
        self.memory.config().trace_key
    }

    /// Get the snapshot.
    pub fn snap(&self) -> i64 {
        self.memory.config().snap
    }

    /// Get the thread key.
    pub fn thread_key(&self) -> Option<i64> {
        self.memory.config().thread_key
    }
}

/// Default pcode trace access providing a unified interface.
#[derive(Debug)]
pub struct DefaultPcodeTraceAccess {
    /// The combined data access.
    pub data: PcodeTraceDataAccess,
}

impl DefaultPcodeTraceAccess {
    /// Create a new default access.
    pub fn new(trace_key: i64, snap: i64) -> Self {
        let config = PcodeTraceAccessConfig::new(trace_key, snap);
        Self {
            data: PcodeTraceDataAccess::new(config),
        }
    }

    /// Create with thread context.
    pub fn with_thread(trace_key: i64, snap: i64, thread_key: i64) -> Self {
        let config = PcodeTraceAccessConfig::new(trace_key, snap).with_thread(thread_key);
        Self {
            data: PcodeTraceDataAccess::new(config),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_type() {
        assert!(TraceAccessType::Read.is_read());
        assert!(!TraceAccessType::Read.is_write());
        assert!(TraceAccessType::ReadWrite.is_read());
        assert!(TraceAccessType::ReadWrite.is_write());
        assert!(TraceAccessType::Execute.is_execute());
    }

    #[test]
    fn test_memory_access_record() {
        let record = TraceMemoryAccessRecord::new(
            0x400000,
            4,
            TraceAccessType::Read,
            vec![0x12, 0x34, 0x56, 0x78],
            0,
        );
        assert_eq!(record.end_address(), 0x400004);
    }

    #[test]
    fn test_access_config() {
        let config = PcodeTraceAccessConfig::new(1, 0)
            .with_thread(42)
            .with_frame(3)
            .with_recording(true);
        assert_eq!(config.thread_key, Some(42));
        assert_eq!(config.frame_level, Some(3));
        assert!(config.record_accesses);
    }

    #[test]
    fn test_memory_access_recording() {
        let config = PcodeTraceAccessConfig::new(1, 0).with_recording(true);
        let mut access = PcodeTraceMemoryAccess::new(config);
        assert_eq!(access.access_count(), 0);

        access.record_access(TraceMemoryAccessRecord::new(
            0x400000, 4, TraceAccessType::Read, vec![0; 4], 0,
        ));
        assert_eq!(access.access_count(), 1);

        access.clear_log();
        assert_eq!(access.access_count(), 0);
    }

    #[test]
    fn test_register_access() {
        let config = PcodeTraceAccessConfig::new(1, 0).with_thread(1);
        let mut regs = PcodeTraceRegistersAccess::new(config);
        assert!(regs.get_cached("RAX").is_none());

        regs.cache_register("RAX", vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        assert!(regs.get_cached("RAX").is_some());
        assert_eq!(regs.cached_registers().len(), 1);

        regs.clear_cache();
        assert!(regs.get_cached("RAX").is_none());
    }

    #[test]
    fn test_data_access() {
        let config = PcodeTraceAccessConfig::new(1, 5)
            .with_thread(42);
        let access = PcodeTraceDataAccess::new(config);
        assert_eq!(access.trace_key(), 1);
        assert_eq!(access.snap(), 5);
        assert_eq!(access.thread_key(), Some(42));
    }

    #[test]
    fn test_default_pcode_access() {
        let access = DefaultPcodeTraceAccess::new(1, 0);
        assert_eq!(access.data.trace_key(), 1);
        assert_eq!(access.data.snap(), 0);
    }

    #[test]
    fn test_default_access_with_thread() {
        let access = DefaultPcodeTraceAccess::with_thread(1, 0, 42);
        assert_eq!(access.data.thread_key(), Some(42));
    }

    #[test]
    fn test_access_type_display() {
        assert!(TraceAccessType::Read.is_read());
        assert!(!TraceAccessType::Execute.is_write());
        assert!(TraceAccessType::Execute.is_execute());
    }
}
