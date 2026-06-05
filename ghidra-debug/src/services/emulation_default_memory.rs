//! Default pcode debugger memory access.
//!
//! Ported from Ghidra's `DefaultPcodeDebuggerMemoryAccess`.

use serde::{Deserialize, Serialize};

use crate::model::TraceMemoryState;

/// Default memory access with state tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultPcodeDebuggerMemoryAccess {
    data: std::collections::BTreeMap<u64, Vec<u8>>,
    state: std::collections::BTreeMap<u64, TraceMemoryState>,
}

impl DefaultPcodeDebuggerMemoryAccess {
    pub fn new() -> Self { Self::default() }
    pub fn set_state(&mut self, addr: u64, s: TraceMemoryState) { self.state.insert(addr, s); }
    pub fn get_state(&self, addr: u64) -> TraceMemoryState { self.state.get(&addr).copied().unwrap_or(TraceMemoryState::Unknown) }
    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) { self.data.insert(addr, data.to_vec()); self.set_state(addr, TraceMemoryState::Known); }
    pub fn read_bytes(&self, addr: u64) -> Option<&Vec<u8>> { self.data.get(&addr) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mem() {
        let mut m = DefaultPcodeDebuggerMemoryAccess::new();
        m.write_bytes(0x100, &[1, 2, 3]);
        assert_eq!(m.get_state(0x100), TraceMemoryState::Known);
    }
}
