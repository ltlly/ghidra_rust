//! Default pcode debugger memory access.
//!
//! Ported from Ghidra's `DefaultPcodeDebuggerMemoryAccess`.
//!
//! Provides memory state tracking for pcode emulation.

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

use crate::model::TraceMemoryState;

/// Default memory access with state tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultPcodeDebuggerMemoryAccess {
    data: BTreeMap<u64, Vec<u8>>,
    state: BTreeMap<u64, TraceMemoryState>,
}

impl DefaultPcodeDebuggerMemoryAccess {
    /// Create a new empty memory access.
    pub fn new() -> Self { Self::default() }

    /// Set the state of a memory address.
    pub fn set_state(&mut self, addr: u64, s: TraceMemoryState) { self.state.insert(addr, s); }

    /// Get the state of a memory address.
    pub fn get_state(&self, addr: u64) -> TraceMemoryState {
        self.state.get(&addr).copied().unwrap_or(TraceMemoryState::Unknown)
    }

    /// Write bytes to a memory address and mark it as Known.
    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) {
        self.data.insert(addr, data.to_vec());
        self.set_state(addr, TraceMemoryState::Known);
    }

    /// Read bytes from a memory address.
    pub fn read_bytes(&self, addr: u64) -> Option<&Vec<u8>> { self.data.get(&addr) }

    /// Write a u64 value (little-endian).
    pub fn write_u64_le(&mut self, addr: u64, val: u64) { self.write_bytes(addr, &val.to_le_bytes()); }

    /// Read a u64 value (little-endian).
    pub fn read_u64_le(&self, addr: u64) -> Option<u64> {
        self.read_bytes(addr).and_then(|v| {
            if v.len() >= 8 { Some(u64::from_le_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]])) }
            else { None }
        })
    }

    /// Write a u32 value (little-endian).
    pub fn write_u32_le(&mut self, addr: u64, val: u32) { self.write_bytes(addr, &val.to_le_bytes()); }

    /// Read a u32 value (little-endian).
    pub fn read_u32_le(&self, addr: u64) -> Option<u32> {
        self.read_bytes(addr).and_then(|v| {
            if v.len() >= 4 { Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]])) }
            else { None }
        })
    }

    /// Get the number of tracked memory entries.
    pub fn entry_count(&self) -> usize { self.data.len() }

    /// Clear all data and states.
    pub fn clear(&mut self) { self.data.clear(); self.state.clear(); }

    /// Merge data from another memory access.
    pub fn merge_from(&mut self, other: &DefaultPcodeDebuggerMemoryAccess) {
        for (addr, data) in &other.data { self.data.insert(*addr, data.clone()); }
        for (addr, state) in &other.state { self.state.insert(*addr, *state); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_write_read() {
        let mut m = DefaultPcodeDebuggerMemoryAccess::new();
        m.write_bytes(0x100, &[1, 2, 3]);
        assert_eq!(m.get_state(0x100), TraceMemoryState::Known);
        assert_eq!(m.read_bytes(0x100), Some(&vec![1, 2, 3]));
    }

    #[test]
    fn test_mem_unknown_state() {
        let m = DefaultPcodeDebuggerMemoryAccess::new();
        assert_eq!(m.get_state(0xDEAD), TraceMemoryState::Unknown);
        assert!(m.read_bytes(0xDEAD).is_none());
    }

    #[test]
    fn test_mem_u64_le() {
        let mut m = DefaultPcodeDebuggerMemoryAccess::new();
        m.write_u64_le(0x200, 0xCAFEBABE_12345678);
        assert_eq!(m.read_u64_le(0x200), Some(0xCAFEBABE_12345678));
    }

    #[test]
    fn test_mem_u32_le() {
        let mut m = DefaultPcodeDebuggerMemoryAccess::new();
        m.write_u32_le(0x300, 0xDEADBEEF);
        assert_eq!(m.read_u32_le(0x300), Some(0xDEADBEEF));
    }

    #[test]
    fn test_mem_entry_count() {
        let mut m = DefaultPcodeDebuggerMemoryAccess::new();
        assert_eq!(m.entry_count(), 0);
        m.write_bytes(0x100, &[1]);
        m.write_bytes(0x200, &[2]);
        assert_eq!(m.entry_count(), 2);
    }

    #[test]
    fn test_mem_clear() {
        let mut m = DefaultPcodeDebuggerMemoryAccess::new();
        m.write_bytes(0x100, &[1]);
        m.clear();
        assert_eq!(m.entry_count(), 0);
        assert_eq!(m.get_state(0x100), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_mem_merge() {
        let mut m1 = DefaultPcodeDebuggerMemoryAccess::new();
        m1.write_bytes(0x100, &[0xAA]);
        let mut m2 = DefaultPcodeDebuggerMemoryAccess::new();
        m2.write_bytes(0x200, &[0xBB]);
        m1.merge_from(&m2);
        assert_eq!(m1.entry_count(), 2);
        assert_eq!(m1.read_bytes(0x200), Some(&vec![0xBB]));
    }

    #[test]
    fn test_mem_state_override() {
        let mut m = DefaultPcodeDebuggerMemoryAccess::new();
        m.write_bytes(0x100, &[1]);
        assert_eq!(m.get_state(0x100), TraceMemoryState::Known);
        m.set_state(0x100, TraceMemoryState::Error);
        assert_eq!(m.get_state(0x100), TraceMemoryState::Error);
    }
}
