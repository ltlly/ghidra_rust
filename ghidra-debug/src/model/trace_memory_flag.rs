//! TraceMemoryFlag - memory region flags (permissions).
//!
//! Ported from Ghidra's `ghidra.trace.model.memory.TraceMemoryFlag`.

use serde::{Deserialize, Serialize};

/// Flags describing a memory region's attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceMemoryFlag {
    /// Memory is readable.
    Read,
    /// Memory is writable.
    Write,
    /// Memory is executable.
    Execute,
    /// Memory is volatile (may change unexpectedly).
    Volatile,
    /// Memory is in external storage.
    External,
}

impl TraceMemoryFlag {
    /// Check if this flag is a permission flag.
    pub fn is_permission(&self) -> bool {
        matches!(self, Self::Read | Self::Write | Self::Execute)
    }

    /// Get all permission flags.
    pub fn all_permissions() -> &'static [TraceMemoryFlag] {
        &[TraceMemoryFlag::Read, TraceMemoryFlag::Write, TraceMemoryFlag::Execute]
    }
}

/// A set of memory flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryFlagSet {
    flags: Vec<TraceMemoryFlag>,
}

impl MemoryFlagSet {
    /// Create a new empty flag set.
    pub fn new() -> Self {
        Self { flags: Vec::new() }
    }

    /// Create a flag set from a slice.
    pub fn from_slice(flags: &[TraceMemoryFlag]) -> Self {
        Self {
            flags: flags.to_vec(),
        }
    }

    /// Check if the set contains a flag.
    pub fn contains(&self, flag: TraceMemoryFlag) -> bool {
        self.flags.contains(&flag)
    }

    /// Add a flag.
    pub fn add(&mut self, flag: TraceMemoryFlag) {
        if !self.flags.contains(&flag) {
            self.flags.push(flag);
        }
    }

    /// Remove a flag.
    pub fn remove(&mut self, flag: TraceMemoryFlag) {
        self.flags.retain(|f| *f != flag);
    }

    /// Check if readable.
    pub fn is_readable(&self) -> bool {
        self.contains(TraceMemoryFlag::Read)
    }

    /// Check if writable.
    pub fn is_writable(&self) -> bool {
        self.contains(TraceMemoryFlag::Write)
    }

    /// Check if executable.
    pub fn is_executable(&self) -> bool {
        self.contains(TraceMemoryFlag::Execute)
    }

    /// Get the number of flags.
    pub fn len(&self) -> usize {
        self.flags.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }

    /// Iterate over flags.
    pub fn iter(&self) -> impl Iterator<Item = &TraceMemoryFlag> {
        self.flags.iter()
    }

    /// RWX shortcut.
    pub fn rwx() -> Self {
        Self::from_slice(&[
            TraceMemoryFlag::Read,
            TraceMemoryFlag::Write,
            TraceMemoryFlag::Execute,
        ])
    }

    /// Read-only shortcut.
    pub fn read_only() -> Self {
        Self::from_slice(&[TraceMemoryFlag::Read])
    }

    /// Read-execute shortcut.
    pub fn read_execute() -> Self {
        Self::from_slice(&[TraceMemoryFlag::Read, TraceMemoryFlag::Execute])
    }

    /// Read-write shortcut.
    pub fn read_write() -> Self {
        Self::from_slice(&[TraceMemoryFlag::Read, TraceMemoryFlag::Write])
    }
}

impl Default for MemoryFlagSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Register value converter - converts register values between different representations.
#[derive(Debug, Clone)]
pub struct RegisterValueConverter {
    /// The register name.
    pub register_name: String,
    /// The register size in bytes.
    pub size: u32,
}

impl RegisterValueConverter {
    /// Create a new converter.
    pub fn new(register_name: impl Into<String>, size: u32) -> Self {
        Self {
            register_name: register_name.into(),
            size,
        }
    }

    /// Convert a big-endian byte slice to a u64 value.
    pub fn bytes_to_u64_be(bytes: &[u8]) -> u64 {
        let mut val: u64 = 0;
        for &b in bytes.iter().take(8) {
            val = (val << 8) | b as u64;
        }
        val
    }

    /// Convert a little-endian byte slice to a u64 value.
    pub fn bytes_to_u64_le(bytes: &[u8]) -> u64 {
        let mut val: u64 = 0;
        for (i, &b) in bytes.iter().take(8).enumerate() {
            val |= (b as u64) << (i * 8);
        }
        val
    }

    /// Convert a u64 value to big-endian bytes.
    pub fn u64_to_bytes_be(value: u64, size: u32) -> Vec<u8> {
        (0..size).map(|i| ((value >> ((size - 1 - i) * 8)) & 0xFF) as u8).collect()
    }

    /// Convert a u64 value to little-endian bytes.
    pub fn u64_to_bytes_le(value: u64, size: u32) -> Vec<u8> {
        (0..size).map(|i| ((value >> (i * 8)) & 0xFF) as u8).collect()
    }
}

/// Register value error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RegisterValueError {
    /// The register value has an unexpected size.
    #[error("Unexpected register size: expected {expected}, got {actual}")]
    SizeMismatch {
        /// Expected size in bytes.
        expected: u32,
        /// Actual size in bytes.
        actual: u32,
    },

    /// The register value is not available.
    #[error("Register value not available")]
    NotAvailable,

    /// The register value is in an error state.
    #[error("Register value in error state")]
    ErrorState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_flags() {
        let mut flags = MemoryFlagSet::rwx();
        assert!(flags.is_readable());
        assert!(flags.is_writable());
        assert!(flags.is_executable());

        flags.remove(TraceMemoryFlag::Execute);
        assert!(!flags.is_executable());
    }

    #[test]
    fn test_flag_set_operations() {
        let mut set = MemoryFlagSet::new();
        assert!(set.is_empty());

        set.add(TraceMemoryFlag::Read);
        set.add(TraceMemoryFlag::Write);
        assert_eq!(set.len(), 2);

        // Adding duplicate doesn't increase count
        set.add(TraceMemoryFlag::Read);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_register_value_converter() {
        let converter = RegisterValueConverter::new("RAX", 8);

        let bytes = RegisterValueConverter::u64_to_bytes_le(0x1234567890ABCDEF, 8);
        let value = RegisterValueConverter::bytes_to_u64_le(&bytes);
        assert_eq!(value, 0x1234567890ABCDEF);

        let bytes_be = RegisterValueConverter::u64_to_bytes_be(0x1234567890ABCDEF, 8);
        let value_be = RegisterValueConverter::bytes_to_u64_be(&bytes_be);
        assert_eq!(value_be, 0x1234567890ABCDEF);

        assert_eq!(converter.register_name, "RAX");
        assert_eq!(converter.size, 8);
    }

    #[test]
    fn test_register_value_error() {
        let err = RegisterValueError::SizeMismatch { expected: 8, actual: 4 };
        assert!(err.to_string().contains("8"));
        assert!(err.to_string().contains("4"));
    }

    #[test]
    fn test_flag_permission_check() {
        assert!(TraceMemoryFlag::Read.is_permission());
        assert!(TraceMemoryFlag::Write.is_permission());
        assert!(!TraceMemoryFlag::Volatile.is_permission());
    }
}
