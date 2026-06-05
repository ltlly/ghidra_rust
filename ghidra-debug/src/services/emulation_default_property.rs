//! Default pcode debugger property access.
//!
//! Ported from Ghidra's `DefaultPcodeDebuggerPropertyAccess`.

use serde::{Deserialize, Serialize};

/// Default property access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultPcodeDebuggerPropertyAccess {
    props: std::collections::BTreeMap<(String, u64), Vec<u8>>,
}

impl DefaultPcodeDebuggerPropertyAccess {
    pub fn new() -> Self { Self::default() }
    pub fn set(&mut self, name: &str, addr: u64, val: &[u8]) { self.props.insert((name.into(), addr), val.to_vec()); }
    pub fn get(&self, name: &str, addr: u64) -> Option<&Vec<u8>> { self.props.get(&(name.into(), addr)) }
    pub fn remove(&mut self, name: &str, addr: u64) -> bool { self.props.remove(&(name.into(), addr)).is_some() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_props() {
        let mut p = DefaultPcodeDebuggerPropertyAccess::new();
        p.set("color", 0x100, &[255, 0, 0]);
        assert_eq!(p.get("color", 0x100), Some(&vec![255, 0, 0]));
    }
}
