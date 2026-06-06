//! Default pcode debugger property access.
//!
//! Ported from Ghidra's `DefaultPcodeDebuggerPropertyAccess`.
//!
//! Provides property map storage for addresses, keyed by both a
//! property name and an address.

use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet};

/// Default property access implementation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultPcodeDebuggerPropertyAccess {
    props: BTreeMap<(String, u64), Vec<u8>>,
}

impl DefaultPcodeDebuggerPropertyAccess {
    /// Create a new empty property access.
    pub fn new() -> Self { Self::default() }

    /// Set a property value for a given name and address.
    pub fn set(&mut self, name: &str, addr: u64, val: &[u8]) {
        self.props.insert((name.into(), addr), val.to_vec());
    }

    /// Get a property value for a given name and address.
    pub fn get(&self, name: &str, addr: u64) -> Option<&Vec<u8>> {
        self.props.get(&(name.into(), addr))
    }

    /// Remove a property. Returns true if it existed.
    pub fn remove(&mut self, name: &str, addr: u64) -> bool {
        self.props.remove(&(name.into(), addr)).is_some()
    }

    /// Check if a property exists.
    pub fn contains(&self, name: &str, addr: u64) -> bool {
        self.props.contains_key(&(name.into(), addr))
    }

    /// Get all unique property names.
    pub fn property_names(&self) -> BTreeSet<&str> {
        self.props.keys().map(|(name, _)| name.as_str()).collect()
    }

    /// Get all addresses that have a given property.
    pub fn addresses_for(&self, name: &str) -> Vec<u64> {
        self.props.keys().filter(|(n, _)| n == name).map(|(_, addr)| *addr).collect()
    }

    /// Get the total number of property entries.
    pub fn entry_count(&self) -> usize { self.props.len() }

    /// Clear all properties.
    pub fn clear(&mut self) { self.props.clear(); }

    /// Set a boolean flag property (stored as a single byte).
    pub fn set_flag(&mut self, name: &str, addr: u64, val: bool) {
        self.set(name, addr, &[val as u8]);
    }

    /// Get a boolean flag property.
    pub fn get_flag(&self, name: &str, addr: u64) -> Option<bool> {
        self.get(name, addr).and_then(|v| v.first()).map(|&b| b != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_props_set_get() {
        let mut p = DefaultPcodeDebuggerPropertyAccess::new();
        p.set("color", 0x100, &[255, 0, 0]);
        assert_eq!(p.get("color", 0x100), Some(&vec![255, 0, 0]));
    }

    #[test]
    fn test_props_contains() {
        let mut p = DefaultPcodeDebuggerPropertyAccess::new();
        assert!(!p.contains("inst", 0x100));
        p.set("inst", 0x100, &[1]);
        assert!(p.contains("inst", 0x100));
    }

    #[test]
    fn test_props_remove() {
        let mut p = DefaultPcodeDebuggerPropertyAccess::new();
        p.set("inst", 0x100, &[1]);
        assert!(p.remove("inst", 0x100));
        assert!(!p.contains("inst", 0x100));
        assert!(!p.remove("inst", 0x100));
    }

    #[test]
    fn test_props_names() {
        let mut p = DefaultPcodeDebuggerPropertyAccess::new();
        p.set("color", 0x100, &[0]);
        p.set("inst", 0x200, &[1]);
        p.set("inst", 0x300, &[1]);
        let names = p.property_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains("color"));
        assert!(names.contains("inst"));
    }

    #[test]
    fn test_props_addresses_for() {
        let mut p = DefaultPcodeDebuggerPropertyAccess::new();
        p.set("inst", 0x100, &[1]);
        p.set("inst", 0x200, &[1]);
        p.set("inst", 0x300, &[1]);
        p.set("data", 0x100, &[0]);
        let addrs = p.addresses_for("inst");
        assert_eq!(addrs.len(), 3);
    }

    #[test]
    fn test_props_entry_count() {
        let mut p = DefaultPcodeDebuggerPropertyAccess::new();
        assert_eq!(p.entry_count(), 0);
        p.set("a", 0x100, &[1]);
        p.set("b", 0x200, &[2]);
        assert_eq!(p.entry_count(), 2);
    }

    #[test]
    fn test_props_clear() {
        let mut p = DefaultPcodeDebuggerPropertyAccess::new();
        p.set("a", 0x100, &[1]);
        p.clear();
        assert_eq!(p.entry_count(), 0);
    }

    #[test]
    fn test_props_flag() {
        let mut p = DefaultPcodeDebuggerPropertyAccess::new();
        p.set_flag("breakpoint", 0x400000, true);
        assert_eq!(p.get_flag("breakpoint", 0x400000), Some(true));
        p.set_flag("breakpoint", 0x400004, false);
        assert_eq!(p.get_flag("breakpoint", 0x400004), Some(false));
        assert_eq!(p.get_flag("breakpoint", 0xDEAD), None);
    }
}
