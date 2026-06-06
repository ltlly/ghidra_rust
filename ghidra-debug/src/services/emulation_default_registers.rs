//! Default pcode debugger registers access.
//!
//! Ported from Ghidra's `DefaultPcodeDebuggerRegistersAccess`.
//!
//! Provides register definition and value storage for pcode emulation.

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

/// Default register access implementation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultPcodeDebuggerRegistersAccess {
    defs: BTreeMap<String, usize>,
    values: BTreeMap<String, Vec<u8>>,
}

impl DefaultPcodeDebuggerRegistersAccess {
    /// Create a new empty register access.
    pub fn new() -> Self { Self::default() }

    /// Define a register with the given name and size (in bytes).
    pub fn define(&mut self, name: &str, size: usize) { self.defs.insert(name.into(), size); }

    /// Get the size of a register, if defined.
    pub fn size_of(&self, name: &str) -> Option<usize> { self.defs.get(name).copied() }

    /// Write a register value. Pads to register size if defined.
    pub fn write(&mut self, name: &str, val: &[u8]) {
        if let Some(&size) = self.defs.get(name) {
            let mut padded = vec![0u8; size];
            let copy_len = val.len().min(size);
            padded[..copy_len].copy_from_slice(&val[..copy_len]);
            self.values.insert(name.into(), padded);
        } else {
            self.values.insert(name.into(), val.to_vec());
        }
    }

    /// Write a u64 value (little-endian).
    pub fn write_u64_le(&mut self, name: &str, val: u64) { self.write(name, &val.to_le_bytes()); }

    /// Read a register value.
    pub fn read(&self, name: &str) -> Option<&Vec<u8>> { self.values.get(name) }

    /// Read a register value as u64 (little-endian).
    pub fn read_u64_le(&self, name: &str) -> Option<u64> {
        self.read(name).and_then(|v| {
            if v.len() >= 8 { Some(u64::from_le_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]])) }
            else { None }
        })
    }

    /// Get the names of all defined registers.
    pub fn names(&self) -> Vec<&str> { self.defs.keys().map(|s| s.as_str()).collect() }

    /// Get the number of defined registers.
    pub fn defined_count(&self) -> usize { self.defs.len() }

    /// Get the number of registers with written values.
    pub fn written_count(&self) -> usize { self.values.len() }

    /// Check if a register is defined.
    pub fn is_defined(&self, name: &str) -> bool { self.defs.contains_key(name) }

    /// Check if a register has a value written.
    pub fn has_value(&self, name: &str) -> bool { self.values.contains_key(name) }

    /// Clear all register values (keeps definitions).
    pub fn clear_values(&mut self) { self.values.clear(); }

    /// Clear everything (definitions and values).
    pub fn clear(&mut self) { self.defs.clear(); self.values.clear(); }

    /// Define a standard x86-64 register set.
    pub fn define_x86_64_standard(&mut self) {
        for reg in &["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags"] {
            self.define(reg, 8);
        }
        for reg in &["cs", "ds", "es", "fs", "gs", "ss"] {
            self.define(reg, 2);
        }
    }

    /// Define a standard AARCH64 register set.
    pub fn define_aarch64_standard(&mut self) {
        for i in 0..=30 { self.define(&format!("x{}", i), 8); }
        self.define("sp", 8);
        self.define("pc", 8);
        self.define("pstate", 8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regs_basic() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        r.define("rax", 8);
        r.write("rax", &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        assert_eq!(r.size_of("rax"), Some(8));
        assert_eq!(r.read("rax").unwrap().len(), 8);
    }

    #[test]
    fn test_regs_u64_le() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        r.define("rax", 8);
        r.write_u64_le("rax", 0x1234_5678_9ABC_DEF0);
        assert_eq!(r.read_u64_le("rax"), Some(0x1234_5678_9ABC_DEF0));
    }

    #[test]
    fn test_regs_write_padded() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        r.define("eax", 4);
        r.write("eax", &[0xFF, 0x01]);
        let v = r.read("eax").unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v[0], 0xFF);
        assert_eq!(v[1], 0x01);
    }

    #[test]
    fn test_regs_query() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        assert!(!r.is_defined("rax"));
        assert!(!r.has_value("rax"));
        r.define("rax", 8);
        assert!(r.is_defined("rax"));
        r.write("rax", &[0; 8]);
        assert!(r.has_value("rax"));
    }

    #[test]
    fn test_regs_counts() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        assert_eq!(r.defined_count(), 0);
        assert_eq!(r.written_count(), 0);
        r.define("rax", 8);
        r.define("rbx", 8);
        assert_eq!(r.defined_count(), 2);
        r.write("rax", &[0; 8]);
        assert_eq!(r.written_count(), 1);
    }

    #[test]
    fn test_regs_clear_values() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        r.define("rax", 8);
        r.write("rax", &[0; 8]);
        r.clear_values();
        assert_eq!(r.defined_count(), 1);
        assert_eq!(r.written_count(), 0);
    }

    #[test]
    fn test_regs_clear_all() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        r.define("rax", 8);
        r.clear();
        assert_eq!(r.defined_count(), 0);
    }

    #[test]
    fn test_regs_names_sorted() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        r.define("rdx", 8);
        r.define("rax", 8);
        let names = r.names();
        assert_eq!(names.len(), 2);
        assert_eq!(names[0], "rax");
        assert_eq!(names[1], "rdx");
    }

    #[test]
    fn test_regs_x86_64_standard() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        r.define_x86_64_standard();
        assert!(r.is_defined("rax"));
        assert!(r.is_defined("rsp"));
        assert!(r.is_defined("rip"));
        assert!(r.is_defined("cs"));
        assert_eq!(r.size_of("rax"), Some(8));
        assert_eq!(r.size_of("cs"), Some(2));
        assert_eq!(r.defined_count(), 24);
    }

    #[test]
    fn test_regs_aarch64_standard() {
        let mut r = DefaultPcodeDebuggerRegistersAccess::new();
        r.define_aarch64_standard();
        assert!(r.is_defined("x0"));
        assert!(r.is_defined("x30"));
        assert!(r.is_defined("sp"));
        assert!(r.is_defined("pc"));
        assert_eq!(r.defined_count(), 34);
    }

    #[test]
    fn test_regs_undefined() {
        let r = DefaultPcodeDebuggerRegistersAccess::new();
        assert_eq!(r.size_of("nonexistent"), None);
        assert!(r.read("nonexistent").is_none());
        assert!(r.read_u64_le("nonexistent").is_none());
    }
}
