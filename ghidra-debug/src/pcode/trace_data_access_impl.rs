//! Pcode trace data access implementations.
//!
//! Ported from `ghidra/pcode/exec/trace/data/` package.
//! Provides the data access layer for pcode execution over traces:
//! - `AbstractPcodeTraceAccess`: base access interface
//! - `AbstractPcodeTraceDataAccess`: data access implementation
//! - `DefaultPcodeTraceAccess`: default access combining all sub-interfaces
//! - `DefaultPcodeTraceMemoryAccess`: memory-specific access
//! - `DefaultPcodeTraceRegistersAccess`: register-specific access
//! - `DefaultPcodeTracePropertyAccess`: property-specific access
//! - `DefaultPcodeTraceThreadAccess`: thread-specific access

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Base trait for pcode trace access.
///
/// Ported from `PcodeTraceAccess.java`.
pub trait PcodeTraceAccess: std::fmt::Debug + Send + Sync {
    /// Get the trace key.
    fn trace_key(&self) -> i64;

    /// Get the current snap.
    fn snap(&self) -> i64;

    /// Get the thread key, if scoped to a thread.
    fn thread_key(&self) -> Option<i64>;

    /// Get the frame level, if scoped to a stack frame.
    fn frame_level(&self) -> Option<u32>;
}

/// Memory access trait for pcode trace.
///
/// Ported from `PcodeTraceMemoryAccess.java`.
pub trait PcodeTraceMemoryAccess: PcodeTraceAccess {
    /// Read bytes from memory.
    fn read_memory(&self, space: &str, offset: u64, length: usize) -> Option<Vec<u8>>;

    /// Write bytes to memory.
    fn write_memory(&mut self, space: &str, offset: u64, data: &[u8]) -> Result<(), String>;

    /// Get the memory state (known/unknown) at an address.
    fn memory_state(&self, space: &str, offset: u64) -> MemoryState;
}

/// Register access trait for pcode trace.
///
/// Ported from `PcodeTraceRegistersAccess.java`.
pub trait PcodeTraceRegistersAccess: PcodeTraceAccess {
    /// Read a register value.
    fn read_register(&self, name: &str) -> Option<Vec<u8>>;

    /// Write a register value.
    fn write_register(&mut self, name: &str, value: &[u8]) -> Result<(), String>;

    /// Get all register names.
    fn register_names(&self) -> Vec<String>;

    /// Get register state (known/unknown).
    fn register_state(&self, name: &str) -> MemoryState;
}

/// Property access trait for pcode trace.
///
/// Ported from `PcodeTracePropertyAccess.java`.
pub trait PcodeTracePropertyAccess: PcodeTraceAccess {
    /// Get a property value.
    fn get_property(&self, name: &str, space: &str, offset: u64) -> Option<String>;

    /// Set a property value.
    fn set_property(&mut self, name: &str, space: &str, offset: u64, value: &str);
}

/// Thread access trait for pcode trace.
///
/// Ported from `PcodeTraceThreadAccess.java`.
pub trait PcodeTraceThreadAccess: PcodeTraceAccess {
    /// Get the thread name.
    fn thread_name(&self) -> Option<String>;

    /// Get the thread's register container key path.
    fn thread_register_container(&self) -> Option<String>;
}

/// Combined access trait providing all sub-interfaces.
///
/// Ported from `DefaultPcodeTraceAccess.java`.
pub trait DefaultPcodeTraceAccess:
    PcodeTraceMemoryAccess + PcodeTraceRegistersAccess + PcodeTracePropertyAccess + PcodeTraceThreadAccess
{
    /// Get a combined view of the current state.
    fn snapshot(&self) -> PcodeTraceSnapshot;
}

/// Memory state for trace bytes/registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryState {
    /// Value is known.
    Known,
    /// Value is unknown.
    Unknown,
}

/// A snapshot of pcode trace state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTraceSnapshot {
    /// Trace key.
    pub trace_key: i64,
    /// Snap.
    pub snap: i64,
    /// Thread key.
    pub thread_key: Option<i64>,
    /// Register values.
    pub registers: BTreeMap<String, Vec<u8>>,
    /// Register states.
    pub register_states: BTreeMap<String, MemoryState>,
}

impl PcodeTraceSnapshot {
    /// Create a new snapshot.
    pub fn new(trace_key: i64, snap: i64) -> Self {
        Self {
            trace_key,
            snap,
            thread_key: None,
            registers: BTreeMap::new(),
            register_states: BTreeMap::new(),
        }
    }
}

/// Concrete implementation of pcode trace data access.
///
/// Ported from `AbstractPcodeTraceDataAccess.java` and
/// `DefaultPcodeTraceDataAccess.java`.
#[derive(Debug)]
pub struct ConcretePcodeTraceDataAccess {
    trace_key: i64,
    snap: i64,
    thread_key: Option<i64>,
    frame_level: Option<u32>,
    /// In-memory register storage.
    registers: BTreeMap<String, Vec<u8>>,
    /// Register states.
    register_states: BTreeMap<String, MemoryState>,
    /// In-memory memory storage: (space, offset) -> bytes.
    memory: BTreeMap<(String, u64), Vec<u8>>,
    /// Memory states.
    memory_states: BTreeMap<(String, u64), MemoryState>,
    /// Properties.
    properties: BTreeMap<(String, String, u64), String>,
}

impl ConcretePcodeTraceDataAccess {
    /// Create a new data access.
    pub fn new(trace_key: i64, snap: i64) -> Self {
        Self {
            trace_key,
            snap,
            thread_key: None,
            frame_level: None,
            registers: BTreeMap::new(),
            register_states: BTreeMap::new(),
            memory: BTreeMap::new(),
            memory_states: BTreeMap::new(),
            properties: BTreeMap::new(),
        }
    }

    /// Scope to a thread.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Scope to a frame level.
    pub fn with_frame_level(mut self, frame_level: u32) -> Self {
        self.frame_level = Some(frame_level);
        self
    }
}

impl PcodeTraceAccess for ConcretePcodeTraceDataAccess {
    fn trace_key(&self) -> i64 {
        self.trace_key
    }

    fn snap(&self) -> i64 {
        self.snap
    }

    fn thread_key(&self) -> Option<i64> {
        self.thread_key
    }

    fn frame_level(&self) -> Option<u32> {
        self.frame_level
    }
}

impl PcodeTraceMemoryAccess for ConcretePcodeTraceDataAccess {
    fn read_memory(&self, space: &str, offset: u64, length: usize) -> Option<Vec<u8>> {
        // Simple implementation: read exact match
        self.memory
            .get(&(space.to_string(), offset))
            .map(|v| v[..length.min(v.len())].to_vec())
    }

    fn write_memory(&mut self, space: &str, offset: u64, data: &[u8]) -> Result<(), String> {
        self.memory
            .insert((space.to_string(), offset), data.to_vec());
        self.memory_states
            .insert((space.to_string(), offset), MemoryState::Known);
        Ok(())
    }

    fn memory_state(&self, space: &str, offset: u64) -> MemoryState {
        self.memory_states
            .get(&(space.to_string(), offset))
            .copied()
            .unwrap_or(MemoryState::Unknown)
    }
}

impl PcodeTraceRegistersAccess for ConcretePcodeTraceDataAccess {
    fn read_register(&self, name: &str) -> Option<Vec<u8>> {
        self.registers.get(name).cloned()
    }

    fn write_register(&mut self, name: &str, value: &[u8]) -> Result<(), String> {
        self.registers.insert(name.to_string(), value.to_vec());
        self.register_states
            .insert(name.to_string(), MemoryState::Known);
        Ok(())
    }

    fn register_names(&self) -> Vec<String> {
        self.registers.keys().cloned().collect()
    }

    fn register_state(&self, name: &str) -> MemoryState {
        self.register_states
            .get(name)
            .copied()
            .unwrap_or(MemoryState::Unknown)
    }
}

impl PcodeTracePropertyAccess for ConcretePcodeTraceDataAccess {
    fn get_property(&self, name: &str, space: &str, offset: u64) -> Option<String> {
        self.properties
            .get(&(name.to_string(), space.to_string(), offset))
            .cloned()
    }

    fn set_property(&mut self, name: &str, space: &str, offset: u64, value: &str) {
        self.properties.insert(
            (name.to_string(), space.to_string(), offset),
            value.to_string(),
        );
    }
}

impl PcodeTraceThreadAccess for ConcretePcodeTraceDataAccess {
    fn thread_name(&self) -> Option<String> {
        self.thread_key.map(|k| format!("thread-{}", k))
    }

    fn thread_register_container(&self) -> Option<String> {
        self.thread_key.map(|k| format!("Threads[{}].Registers", k))
    }
}

impl DefaultPcodeTraceAccess for ConcretePcodeTraceDataAccess {
    fn snapshot(&self) -> PcodeTraceSnapshot {
        PcodeTraceSnapshot {
            trace_key: self.trace_key,
            snap: self.snap,
            thread_key: self.thread_key,
            registers: self.registers.clone(),
            register_states: self.register_states.clone(),
        }
    }
}

/// Pcode utility functions.
///
/// Ported from `DebuggerPcodeUtils.java`.
pub struct DebuggerPcodeUtils;

impl DebuggerPcodeUtils {
    /// Get the address size for a given language.
    pub fn address_size(language_id: &str) -> usize {
        if language_id.contains("64") {
            8
        } else if language_id.contains("32") {
            4
        } else {
            4 // default
        }
    }

    /// Check if a language is big-endian.
    pub fn is_big_endian(language_id: &str) -> bool {
        language_id.contains(":BE:")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concrete_pcode_trace_data_access() {
        let access = ConcretePcodeTraceDataAccess::new(1, 0)
            .with_thread(42);

        assert_eq!(access.trace_key(), 1);
        assert_eq!(access.snap(), 0);
        assert_eq!(access.thread_key(), Some(42));
    }

    #[test]
    fn test_memory_read_write() {
        let mut access = ConcretePcodeTraceDataAccess::new(1, 0);

        access.write_memory("ram", 0x400000, &[0xDE, 0xAD]).unwrap();
        let data = access.read_memory("ram", 0x400000, 2);
        assert_eq!(data, Some(vec![0xDE, 0xAD]));
    }

    #[test]
    fn test_register_read_write() {
        let mut access = ConcretePcodeTraceDataAccess::new(1, 0);

        access.write_register("RAX", &[0x42; 8]).unwrap();
        let val = access.read_register("RAX");
        assert_eq!(val, Some(vec![0x42; 8]));
        assert_eq!(access.register_state("RAX"), MemoryState::Known);
        assert_eq!(access.register_state("RBX"), MemoryState::Unknown);
    }

    #[test]
    fn test_property_access() {
        let mut access = ConcretePcodeTraceDataAccess::new(1, 0);

        access.set_property("color", "ram", 0x400000, "red");
        assert_eq!(
            access.get_property("color", "ram", 0x400000),
            Some("red".into())
        );
        assert_eq!(access.get_property("color", "ram", 0x500000), None);
    }

    #[test]
    fn test_thread_access() {
        let access = ConcretePcodeTraceDataAccess::new(1, 0)
            .with_thread(42);
        assert_eq!(access.thread_name(), Some("thread-42".into()));
        assert_eq!(
            access.thread_register_container(),
            Some("Threads[42].Registers".into())
        );
    }

    #[test]
    fn test_snapshot() {
        let mut access = ConcretePcodeTraceDataAccess::new(1, 0);
        access.write_register("RAX", &[0x42; 8]).unwrap();

        let snap = access.snapshot();
        assert_eq!(snap.trace_key, 1);
        assert!(snap.registers.contains_key("RAX"));
    }

    #[test]
    fn test_pcode_utils() {
        assert_eq!(DebuggerPcodeUtils::address_size("x86:LE:64:default"), 8);
        assert_eq!(DebuggerPcodeUtils::address_size("x86:LE:32:default"), 4);
        assert!(!DebuggerPcodeUtils::is_big_endian("x86:LE:64:default"));
        assert!(DebuggerPcodeUtils::is_big_endian("PowerPC:BE:64:default"));
    }
}
