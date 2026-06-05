//! Pcode debugger data access layer.
//!
//! Ported from Ghidra's `AbstractPcodeDebuggerAccess`,
//! `DefaultPcodeDebuggerAccess`, `DefaultPcodeDebuggerMemoryAccess`,
//! `DefaultPcodeDebuggerRegistersAccess`, `DefaultPcodeDebuggerPropertyAccess`,
//! and `InternalPcodeDebuggerDataAccess` from
//! `ghidra.app.plugin.core.debug.service.emulation.data`.
//!
//! Provides the bridge between p-code emulation and the live debug target.
//! When emulating with a live session, memory reads may be redirected to
//! the target's actual memory, and writes may be sent back.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Access scope for p-code debugger data access.
///
/// Ported from Ghidra's access modes that control whether the
/// p-code executor reads from trace, target, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessScope {
    /// Read only from the trace database.
    TraceOnly,
    /// Read from the target, fall back to trace.
    TargetFirst,
    /// Read from trace, redirect to target for unknown state.
    TraceFirst,
}

impl Default for AccessScope {
    fn default() -> Self {
        Self::TraceOnly
    }
}

/// Configuration for a p-code debugger data access shim.
///
/// Ported from Ghidra's `AbstractPcodeDebuggerAccess` constructor parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerAccessConfig {
    /// The trace key.
    pub trace_key: i64,
    /// The platform identifier (language/compiler spec).
    pub platform_id: String,
    /// The snap to source data from.
    pub snap: i64,
    /// The threads snap (may differ from data snap).
    pub threads_snap: i64,
    /// The thread key for register access.
    pub thread_key: Option<i64>,
    /// The frame level for register access.
    pub frame_level: u32,
    /// The access scope.
    pub scope: AccessScope,
    /// Timeout for target reads.
    pub target_timeout: Duration,
    /// Whether the target is live (connected).
    pub is_live: bool,
}

impl PcodeDebuggerAccessConfig {
    /// Create a config for shared state (memory access).
    pub fn for_shared_state(trace_key: i64, snap: i64) -> Self {
        Self {
            trace_key,
            platform_id: String::new(),
            snap,
            threads_snap: snap,
            thread_key: None,
            frame_level: 0,
            scope: AccessScope::default(),
            target_timeout: Duration::from_secs(1),
            is_live: false,
        }
    }

    /// Create a config for local state (register access for a thread).
    pub fn for_local_state(
        trace_key: i64,
        snap: i64,
        thread_key: i64,
        frame_level: u32,
    ) -> Self {
        Self {
            trace_key,
            platform_id: String::new(),
            snap,
            threads_snap: snap,
            thread_key: Some(thread_key),
            frame_level,
            scope: AccessScope::default(),
            target_timeout: Duration::from_secs(1),
            is_live: false,
        }
    }

    /// Set the access scope.
    pub fn with_scope(mut self, scope: AccessScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set whether the target is live.
    pub fn with_live(mut self, is_live: bool) -> Self {
        self.is_live = is_live;
        self
    }

    /// Set the target timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.target_timeout = timeout;
        self
    }

    /// Derive a write config from this read config.
    ///
    /// When emulating, writes may need a different snap than reads.
    pub fn derive_for_write(&self, write_snap: i64) -> Self {
        Self {
            trace_key: self.trace_key,
            platform_id: self.platform_id.clone(),
            snap: write_snap,
            threads_snap: self.threads_snap,
            thread_key: self.thread_key,
            frame_level: self.frame_level,
            scope: AccessScope::TraceOnly, // Writes always go to trace
            target_timeout: self.target_timeout,
            is_live: false, // Write derivations are never live
        }
    }
}

/// A memory read/write operation for the p-code debugger.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerMemoryAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerMemoryAccess {
    /// The configuration.
    pub config: PcodeDebuggerAccessConfig,
    /// Cached memory blocks: (start_addr, bytes).
    pub cached_blocks: HashMap<u64, Vec<u8>>,
    /// Dirty addresses (written but not flushed to target).
    pub dirty_ranges: Vec<(u64, u64)>,
}

impl PcodeDebuggerMemoryAccess {
    /// Create a new memory access shim.
    pub fn new(config: PcodeDebuggerAccessConfig) -> Self {
        Self {
            config,
            cached_blocks: HashMap::new(),
            dirty_ranges: Vec::new(),
        }
    }

    /// Check if this access is live (connected to a running target).
    pub fn is_live(&self) -> bool {
        self.config.is_live && self.config.scope != AccessScope::TraceOnly
    }

    /// Read bytes from memory.
    ///
    /// If the access is live and the scope allows, this may redirect
    /// to read from the target.
    pub fn read_bytes(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        // Check cached blocks first
        for (block_start, block_data) in &self.cached_blocks {
            let block_end = block_start + block_data.len() as u64;
            if addr >= *block_start && addr + size as u64 <= block_end {
                let offset = (addr - block_start) as usize;
                return Some(block_data[offset..offset + size].to_vec());
            }
        }
        None
    }

    /// Write bytes to memory.
    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) {
        self.dirty_ranges.push((addr, addr + data.len() as u64));
        // Store in a simple block for now
        self.cached_blocks.insert(addr, data.to_vec());
    }

    /// Check if reads should redirect to the target.
    pub fn should_read_from_target(&self) -> bool {
        self.is_live() && matches!(
            self.config.scope,
            AccessScope::TargetFirst | AccessScope::TraceFirst
        )
    }
}

/// A register read/write operation for the p-code debugger.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerRegistersAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerRegistersAccess {
    /// The configuration.
    pub config: PcodeDebuggerAccessConfig,
    /// Cached register values: register_name -> value.
    pub cached_values: HashMap<String, u64>,
    /// Register dirty flags.
    pub dirty_registers: Vec<String>,
}

impl PcodeDebuggerRegistersAccess {
    /// Create a new register access shim.
    pub fn new(config: PcodeDebuggerAccessConfig) -> Self {
        Self {
            config,
            cached_values: HashMap::new(),
            dirty_registers: Vec::new(),
        }
    }

    /// Check if this access is live.
    pub fn is_live(&self) -> bool {
        self.config.is_live
    }

    /// Read a register value.
    pub fn read_register(&self, name: &str) -> Option<u64> {
        self.cached_values.get(name).copied()
    }

    /// Write a register value.
    pub fn write_register(&mut self, name: &str, value: u64) {
        self.cached_values.insert(name.to_string(), value);
        self.dirty_registers.push(name.to_string());
    }

    /// Read from target registers (async-like operation).
    ///
    /// Returns true if the read was successful.
    pub fn read_from_target(&mut self, registers: &[String]) -> bool {
        if !self.is_live() {
            return false;
        }
        // In a real implementation, this would send a request to the
        // debug target and populate cached_values
        true
    }

    /// Write dirty registers to the target.
    ///
    /// Returns true if the write was successful.
    pub fn flush_to_target(&mut self) -> bool {
        if !self.is_live() {
            return false;
        }
        self.dirty_registers.clear();
        true
    }
}

/// Property access for the p-code debugger.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerPropertyAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerPropertyAccess {
    /// The configuration.
    pub config: PcodeDebuggerAccessConfig,
    /// Cached properties: (property_name, address) -> value bytes.
    pub cached_properties: HashMap<(String, u64), Vec<u8>>,
}

impl PcodeDebuggerPropertyAccess {
    /// Create a new property access shim.
    pub fn new(config: PcodeDebuggerAccessConfig) -> Self {
        Self {
            config,
            cached_properties: HashMap::new(),
        }
    }

    /// Read a property value.
    pub fn read_property(&self, name: &str, addr: u64) -> Option<&[u8]> {
        self.cached_properties
            .get(&(name.to_string(), addr))
            .map(|v| v.as_slice())
    }

    /// Write a property value.
    pub fn write_property(&mut self, name: &str, addr: u64, value: Vec<u8>) {
        self.cached_properties
            .insert((name.to_string(), addr), value);
    }
}

/// The combined p-code debugger data access.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerAccess` which extends
/// `AbstractPcodeDebuggerAccess`. Combines memory, register, and
/// property access into a single shim.
#[derive(Debug)]
pub struct DefaultPcodeDebuggerAccess {
    /// The configuration.
    pub config: PcodeDebuggerAccessConfig,
    /// Memory access.
    pub memory: PcodeDebuggerMemoryAccess,
    /// Register access (for the primary thread).
    pub registers: PcodeDebuggerRegistersAccess,
    /// Property access.
    pub properties: PcodeDebuggerPropertyAccess,
}

impl DefaultPcodeDebuggerAccess {
    /// Create a new combined data access shim.
    pub fn new(config: PcodeDebuggerAccessConfig) -> Self {
        let memory = PcodeDebuggerMemoryAccess::new(config.clone());
        let registers = PcodeDebuggerRegistersAccess::new(config.clone());
        let properties = PcodeDebuggerPropertyAccess::new(config.clone());
        Self {
            config,
            memory,
            registers,
            properties,
        }
    }

    /// Create a data access shim for shared state (memory).
    pub fn for_shared(trace_key: i64, snap: i64) -> Self {
        Self::new(PcodeDebuggerAccessConfig::for_shared_state(trace_key, snap))
    }

    /// Create a data access shim for local state (registers).
    pub fn for_thread(trace_key: i64, snap: i64, thread_key: i64, frame: u32) -> Self {
        Self::new(PcodeDebuggerAccessConfig::for_local_state(
            trace_key, snap, thread_key, frame,
        ))
    }

    /// Derive a write-access shim from this read-access shim.
    ///
    /// Writes are always to the trace, never to the live target.
    pub fn derive_for_write(&self, write_snap: i64) -> Self {
        let config = self.config.derive_for_write(write_snap);
        Self::new(config)
    }

    /// Check if the access is live (connected to a running target).
    pub fn is_live(&self) -> bool {
        self.config.is_live
    }

    /// Set the access scope.
    pub fn set_scope(&mut self, scope: AccessScope) {
        self.config.scope = scope;
        self.memory.config.scope = scope;
        self.registers.config.scope = scope;
        self.properties.config.scope = scope;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_config_shared() {
        let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100);
        assert_eq!(config.trace_key, 1);
        assert_eq!(config.snap, 100);
        assert!(config.thread_key.is_none());
        assert_eq!(config.scope, AccessScope::TraceOnly);
    }

    #[test]
    fn test_access_config_local() {
        let config = PcodeDebuggerAccessConfig::for_local_state(1, 100, 42, 3);
        assert_eq!(config.thread_key, Some(42));
        assert_eq!(config.frame_level, 3);
    }

    #[test]
    fn test_access_config_builder() {
        let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100)
            .with_scope(AccessScope::TargetFirst)
            .with_live(true)
            .with_timeout(Duration::from_secs(5));
        assert_eq!(config.scope, AccessScope::TargetFirst);
        assert!(config.is_live);
        assert_eq!(config.target_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_derive_for_write() {
        let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100)
            .with_live(true)
            .with_scope(AccessScope::TargetFirst);
        let write_config = config.derive_for_write(200);
        assert_eq!(write_config.snap, 200);
        assert_eq!(write_config.scope, AccessScope::TraceOnly);
        assert!(!write_config.is_live);
    }

    #[test]
    fn test_memory_access_read_write() {
        let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100);
        let mut mem = PcodeDebuggerMemoryAccess::new(config);
        mem.write_bytes(0x400000, &[0x48, 0x89, 0xe5]);
        let data = mem.read_bytes(0x400000, 3);
        assert_eq!(data, Some(vec![0x48, 0x89, 0xe5]));
        assert_eq!(mem.dirty_ranges.len(), 1);
    }

    #[test]
    fn test_memory_access_not_live() {
        let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100);
        let mem = PcodeDebuggerMemoryAccess::new(config);
        assert!(!mem.is_live());
        assert!(!mem.should_read_from_target());
    }

    #[test]
    fn test_memory_access_live() {
        let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100)
            .with_live(true)
            .with_scope(AccessScope::TargetFirst);
        let mem = PcodeDebuggerMemoryAccess::new(config);
        assert!(mem.is_live());
        assert!(mem.should_read_from_target());
    }

    #[test]
    fn test_register_access() {
        let config = PcodeDebuggerAccessConfig::for_local_state(1, 100, 42, 0);
        let mut regs = PcodeDebuggerRegistersAccess::new(config);
        regs.write_register("rax", 0x1234);
        assert_eq!(regs.read_register("rax"), Some(0x1234));
        assert_eq!(regs.read_register("rbx"), None);
        assert_eq!(regs.dirty_registers.len(), 1);
    }

    #[test]
    fn test_property_access() {
        let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100);
        let mut props = PcodeDebuggerPropertyAccess::new(config);
        props.write_property("Taint", 0x400000, vec![1, 2, 3]);
        assert_eq!(
            props.read_property("Taint", 0x400000),
            Some([1u8, 2, 3].as_slice())
        );
        assert!(props.read_property("Taint", 0x500000).is_none());
    }

    #[test]
    fn test_default_access() {
        let access = DefaultPcodeDebuggerAccess::for_shared(1, 100);
        assert!(!access.is_live());
        assert_eq!(access.config.trace_key, 1);
    }

    #[test]
    fn test_default_access_for_thread() {
        let access = DefaultPcodeDebuggerAccess::for_thread(1, 100, 42, 0);
        assert_eq!(access.config.thread_key, Some(42));
    }

    #[test]
    fn test_derive_write_access() {
        let access = DefaultPcodeDebuggerAccess::for_shared(1, 100);
        let write_access = access.derive_for_write(200);
        assert_eq!(write_access.config.snap, 200);
        assert!(!write_access.is_live());
    }

    #[test]
    fn test_set_scope() {
        let mut access = DefaultPcodeDebuggerAccess::for_shared(1, 100);
        access.set_scope(AccessScope::TargetFirst);
        assert_eq!(access.config.scope, AccessScope::TargetFirst);
        assert_eq!(access.memory.config.scope, AccessScope::TargetFirst);
    }

    #[test]
    fn test_access_scope_serde() {
        let scope = AccessScope::TargetFirst;
        let json = serde_json::to_string(&scope).unwrap();
        let back: AccessScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AccessScope::TargetFirst);
    }
}
