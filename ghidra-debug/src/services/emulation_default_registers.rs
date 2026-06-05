//! Default pcode debugger registers access.
//!
//! Ported from Ghidra's `DefaultPcodeDebuggerRegistersAccess`.

use serde::{Deserialize, Serialize};

/// Default register access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultPcodeDebuggerRegistersAccess {
    defs: std::collections::BTreeMap<String, usize>,
    values: std::collections::BTreeMap<String, Vec<u8>>,
}

impl DefaultPcodeDebuggerRegistersAccess {
    pub fn new() -> Self { Self::default() }
    pub fn define(&mut self, name: &str, size: usize) { self.defs.insert(name.into(), size); }
    pub fn size_of(&self, name: &str) -> Option<usize> { self.defs.get(name).copied() }
    pub fn write(&mut self, name: &str, val: &[u8]) { self.values.insert(name.into(), val.to_vec()); }
    pub fn read(&self, name: &str) -> Option<&Vec<u8>> { self.values.get(name) }
    pub fn names(&self) -> Vec<&str> { self.defs.keys().map(|s| s.as_str()).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_regs() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        r.define("rax", 8);
        r.write("rax", &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        assert_eq!(r.size_of("rax"), Some(8));
        assert_eq!(r.read("rax").unwrap().len(), 8);
    }
}
