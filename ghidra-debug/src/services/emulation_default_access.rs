//! Default pcode debugger access implementation.
//!
//! Ported from Ghidra's `DefaultPcodeDebuggerAccess`.

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
}

impl DefaultPcodeDebuggerAccess {
    pub fn new(snap: i64) -> Self { Self { snap, ..Default::default() } }
    pub fn with_thread(mut self, t: i64) -> Self { self.thread_key = Some(t); self }
    pub fn snap(&self) -> i64 { self.snap }
    pub fn write_memory(&mut self, addr: u64, data: &[u8]) { self.memory_cache.insert(addr, data.to_vec()); }
    pub fn read_memory(&self, addr: u64) -> Option<&Vec<u8>> { self.memory_cache.get(&addr) }
    pub fn write_register(&mut self, name: &str, val: &[u8]) { self.register_cache.insert(name.into(), val.to_vec()); }
    pub fn read_register(&self, name: &str) -> Option<&Vec<u8>> { self.register_cache.get(name) }
    pub fn clear(&mut self) { self.memory_cache.clear(); self.register_cache.clear(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_access() {
        let mut a = DefaultPcodeDebuggerAccess::new(0).with_thread(1);
        a.write_memory(0x1000, &[0xAA]);
        assert_eq!(a.read_memory(0x1000), Some(&vec![0xAA]));
    }
}
