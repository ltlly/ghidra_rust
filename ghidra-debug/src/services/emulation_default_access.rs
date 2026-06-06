//! Default pcode debugger access implementation.
//!
//! Ported from Ghidra's `DefaultPcodeDebuggerAccess`.
//!
//! Provides a unified interface for accessing memory and registers at
//! a particular point in time (snap) during emulation.

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

/// Default implementation of pcode debugger access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultPcodeDebuggerAccess {
    snap: i64,
    thread_key: Option<i64>,
    frame_level: i32,
    memory_cache: BTreeMap<u64, Vec<u8>>,
    register_cache: BTreeMap<String, Vec<u8>>,
    memory_states: BTreeMap<u64, MemoryAccessState>,
}

/// State of a memory location in the debugger access cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryAccessState {
    /// Memory is known and has been read/written.
    Known,
    /// Memory is known to be uninitialized.
    Unknown,
    /// Memory access produced an error.
    Error,
}

impl DefaultPcodeDebuggerAccess {
    /// Create a new access object for the given snap.
    pub fn new(snap: i64) -> Self {
        Self { snap, ..Default::default() }
    }

    /// Set the thread key for this access.
    pub fn with_thread(mut self, t: i64) -> Self {
        self.thread_key = Some(t);
        self
    }

    /// Set the frame level for this access.
    pub fn with_frame_level(mut self, level: i32) -> Self {
        self.frame_level = level;
        self
    }

    /// Get the current snap.
    pub fn snap(&self) -> i64 {
        self.snap
    }

    /// Get the thread key, if set.
    pub fn thread_key(&self) -> Option<i64> {
        self.thread_key
    }

    /// Get the frame level.
    pub fn frame_level(&self) -> i32 {
        self.frame_level
    }

    /// Write data to a memory address in the cache.
    pub fn write_memory(&mut self, addr: u64, data: &[u8]) {
        self.memory_cache.insert(addr, data.to_vec());
        self.memory_states.insert(addr, MemoryAccessState::Known);
    }

    /// Read data from a memory address in the cache.
    pub fn read_memory(&self, addr: u64) -> Option<&Vec<u8>> {
        self.memory_cache.get(&addr)
    }

    /// Get the state of a memory address.
    pub fn memory_state(&self, addr: u64) -> MemoryAccessState {
        self.memory_states.get(&addr).copied().unwrap_or(MemoryAccessState::Unknown)
    }

    /// Write a register value.
    pub fn write_register(&mut self, name: &str, val: &[u8]) {
        self.register_cache.insert(name.into(), val.to_vec());
    }

    /// Read a register value.
    pub fn read_register(&self, name: &str) -> Option<&Vec<u8>> {
        self.register_cache.get(name)
    }

    /// Check if a register is defined.
    pub fn has_register(&self, name: &str) -> bool {
        self.register_cache.contains_key(name)
    }

    /// Get the names of all registers with cached values.
    pub fn register_names(&self) -> Vec<&str> {
        self.register_cache.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of cached memory entries.
    pub fn memory_entry_count(&self) -> usize {
        self.memory_cache.len()
    }

    /// Get the number of cached register entries.
    pub fn register_entry_count(&self) -> usize {
        self.register_cache.len()
    }

    /// Read a u64 value from memory (little-endian).
    pub fn read_u64_le(&self, addr: u64) -> Option<u64> {
        self.read_memory(addr).and_then(|v| {
            if v.len() >= 8 {
                Some(u64::from_le_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]))
            } else {
                None
            }
        })
    }

    /// Write a u64 value to memory (little-endian).
    pub fn write_u64_le(&mut self, addr: u64, val: u64) {
        self.write_memory(addr, &val.to_le_bytes());
    }

    /// Clear all cached data.
    pub fn clear(&mut self) {
        self.memory_cache.clear();
        self.register_cache.clear();
        self.memory_states.clear();
    }

    /// Clear only memory cache.
    pub fn clear_memory(&mut self) {
        self.memory_cache.clear();
        self.memory_states.clear();
    }

    /// Clear only register cache.
    pub fn clear_registers(&mut self) {
        self.register_cache.clear();
    }

    /// Merge another access object into this one.
    pub fn merge_from(&mut self, other: &DefaultPcodeDebuggerAccess) {
        for (addr, data) in &other.memory_cache {
            self.memory_cache.insert(*addr, data.clone());
        }
        for (addr, state) in &other.memory_states {
            self.memory_states.insert(*addr, *state);
        }
        for (name, val) in &other.register_cache {
            self.register_cache.insert(name.clone(), val.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_basic() {
        let mut a = DefaultPcodeDebuggerAccess::new(0).with_thread(1);
        assert_eq!(a.snap(), 0);
        assert_eq!(a.thread_key(), Some(1));
        a.write_memory(0x1000, &[0xAA]);
        assert_eq!(a.read_memory(0x1000), Some(&vec![0xAA]));
    }

    #[test]
    fn test_memory_state() {
        let mut a = DefaultPcodeDebuggerAccess::new(0);
        assert_eq!(a.memory_state(0x1000), MemoryAccessState::Unknown);
        a.write_memory(0x1000, &[0xFF]);
        assert_eq!(a.memory_state(0x1000), MemoryAccessState::Known);
    }

    #[test]
    fn test_register_access() {
        let mut a = DefaultPcodeDebuggerAccess::new(0);
        a.write_register("rax", &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        assert!(a.has_register("rax"));
        assert!(!a.has_register("rbx"));
        assert_eq!(a.read_register("rax").unwrap().len(), 8);
        assert_eq!(a.register_names().len(), 1);
    }

    #[test]
    fn test_u64_le_read_write() {
        let mut a = DefaultPcodeDebuggerAccess::new(0);
        a.write_u64_le(0x1000, 0x1234_5678_9ABC_DEF0);
        assert_eq!(a.read_u64_le(0x1000), Some(0x1234_5678_9ABC_DEF0));
    }

    #[test]
    fn test_entry_counts() {
        let mut a = DefaultPcodeDebuggerAccess::new(0);
        assert_eq!(a.memory_entry_count(), 0);
        assert_eq!(a.register_entry_count(), 0);
        a.write_memory(0x100, &[1]);
        a.write_memory(0x200, &[2]);
        a.write_register("rax", &[0; 8]);
        assert_eq!(a.memory_entry_count(), 2);
        assert_eq!(a.register_entry_count(), 1);
    }

    #[test]
    fn test_clear_methods() {
        let mut a = DefaultPcodeDebuggerAccess::new(0);
        a.write_memory(0x100, &[1]);
        a.write_register("rax", &[0; 8]);
        a.clear_memory();
        assert_eq!(a.memory_entry_count(), 0);
        assert_eq!(a.register_entry_count(), 1);
        a.clear_registers();
        assert_eq!(a.register_entry_count(), 0);
    }

    #[test]
    fn test_merge_from() {
        let mut a = DefaultPcodeDebuggerAccess::new(0);
        a.write_memory(0x100, &[1]);
        let mut b = DefaultPcodeDebuggerAccess::new(0);
        b.write_memory(0x200, &[2]);
        b.write_register("rbx", &[0; 8]);
        a.merge_from(&b);
        assert_eq!(a.memory_entry_count(), 2);
        assert_eq!(a.register_entry_count(), 1);
    }

    #[test]
    fn test_frame_level() {
        let a = DefaultPcodeDebuggerAccess::new(5).with_frame_level(2);
        assert_eq!(a.frame_level(), 2);
    }

    #[test]
    fn test_read_nonexistent() {
        let a = DefaultPcodeDebuggerAccess::new(0);
        assert!(a.read_memory(0xDEAD).is_none());
        assert!(a.read_register("nonexistent").is_none());
        assert!(a.read_u64_le(0xDEAD).is_none());
    }
}
