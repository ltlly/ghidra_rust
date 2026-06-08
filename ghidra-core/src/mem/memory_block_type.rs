//! Memory block type classification.
//!
//! This module provides the [`MemoryBlockType`] enum which classifies memory
//! blocks into three categories: default (standard initialized/uninitialized),
//! bit-mapped, and byte-mapped.
//!
//! # Correspondence to Ghidra
//!
//! This is a direct translation of `ghidra.program.model.mem.MemoryBlockType`.
//! The Java source is a simple enum with three values: `DEFAULT`, `BIT_MAPPED`,
//! and `BYTE_MAPPED`. This Rust version adds `Display` and `PartialEq`
//! implementations and helper methods for classification.
//!
//! # Examples
//!
//! ```
//! use ghidra_core::mem::memory_block_type::MemoryBlockType;
//!
//! let block_type = MemoryBlockType::Default;
//! assert_eq!(block_type.name(), "Default");
//! assert_eq!(format!("{}", block_type), "Default");
//!
//! assert!(MemoryBlockType::BitMapped.is_mapped());
//! assert!(MemoryBlockType::ByteMapped.is_mapped());
//! assert!(!MemoryBlockType::Default.is_mapped());
//! ```

use std::fmt;

// ============================================================================
// MemoryBlockType
// ============================================================================

/// The type of a memory block.
///
/// Corresponds to Ghidra's `ghidra.program.model.mem.MemoryBlockType` enum.
/// Each memory block in a program is classified into one of these three types.
///
/// # Variants
///
/// * `Default` — A standard memory block (initialized or uninitialized).
///   This is the most common type, representing a contiguous region of bytes
///   loaded from a file or created by the analysis.
///
/// * `BitMapped` — A bit-mapped memory block. Each byte in this block maps
///   to a single bit in a source memory region. This is used for certain
///   embedded processor memory models where individual bits are addressable.
///
/// * `ByteMapped` — A byte-mapped memory block. Bytes in this block map to
///   another memory region via a [`ByteMappingScheme`](super::ByteMappingScheme).
///   The mapping can be 1:1 (every byte maps) or N:M (decimation pattern).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryBlockType {
    /// Standard initialized/uninitialized block.
    Default,
    /// Bit-mapped block (each byte maps to a single bit in source).
    BitMapped,
    /// Byte-mapped block (bytes map to another memory region).
    ByteMapped,
}

impl MemoryBlockType {
    /// Human-readable name of this block type.
    ///
    /// Returns the same string as `MemoryBlockType.toString()` in the Java
    /// implementation.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_block_type::MemoryBlockType;
    ///
    /// assert_eq!(MemoryBlockType::Default.name(), "Default");
    /// assert_eq!(MemoryBlockType::BitMapped.name(), "Bit Mapped");
    /// assert_eq!(MemoryBlockType::ByteMapped.name(), "Byte Mapped");
    /// ```
    pub fn name(&self) -> &'static str {
        match self {
            MemoryBlockType::Default => "Default",
            MemoryBlockType::BitMapped => "Bit Mapped",
            MemoryBlockType::ByteMapped => "Byte Mapped",
        }
    }

    /// Returns `true` if this block type represents any kind of mapping
    /// (either bit-mapped or byte-mapped).
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_block_type::MemoryBlockType;
    ///
    /// assert!(!MemoryBlockType::Default.is_mapped());
    /// assert!(MemoryBlockType::BitMapped.is_mapped());
    /// assert!(MemoryBlockType::ByteMapped.is_mapped());
    /// ```
    pub fn is_mapped(&self) -> bool {
        matches!(self, MemoryBlockType::BitMapped | MemoryBlockType::ByteMapped)
    }

    /// Returns `true` if this is a standard (non-mapped) block type.
    ///
    /// This is the inverse of [`is_mapped`](Self::is_mapped).
    pub fn is_default(&self) -> bool {
        matches!(self, MemoryBlockType::Default)
    }

    /// Returns `true` if this is a bit-mapped block type.
    pub fn is_bit_mapped(&self) -> bool {
        matches!(self, MemoryBlockType::BitMapped)
    }

    /// Returns `true` if this is a byte-mapped block type.
    pub fn is_byte_mapped(&self) -> bool {
        matches!(self, MemoryBlockType::ByteMapped)
    }

    /// Returns the storage ID used for persistent serialization.
    ///
    /// This ID corresponds to the ordinal value used when storing block types
    /// in the Ghidra database.
    ///
    /// * `Default` = 0
    /// * `BitMapped` = 1
    /// * `ByteMapped` = 2
    pub fn storage_id(&self) -> u8 {
        match self {
            MemoryBlockType::Default => 0,
            MemoryBlockType::BitMapped => 1,
            MemoryBlockType::ByteMapped => 2,
        }
    }

    /// Returns the `MemoryBlockType` for the given storage ID.
    ///
    /// Returns `None` if the ID does not correspond to a known block type.
    pub fn from_storage_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(MemoryBlockType::Default),
            1 => Some(MemoryBlockType::BitMapped),
            2 => Some(MemoryBlockType::ByteMapped),
            _ => None,
        }
    }
}

impl fmt::Display for MemoryBlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_name() {
        assert_eq!(MemoryBlockType::Default.name(), "Default");
    }

    #[test]
    fn test_bit_mapped_name() {
        assert_eq!(MemoryBlockType::BitMapped.name(), "Bit Mapped");
    }

    #[test]
    fn test_byte_mapped_name() {
        assert_eq!(MemoryBlockType::ByteMapped.name(), "Byte Mapped");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", MemoryBlockType::Default), "Default");
        assert_eq!(format!("{}", MemoryBlockType::BitMapped), "Bit Mapped");
        assert_eq!(format!("{}", MemoryBlockType::ByteMapped), "Byte Mapped");
    }

    #[test]
    fn test_is_mapped() {
        assert!(!MemoryBlockType::Default.is_mapped());
        assert!(MemoryBlockType::BitMapped.is_mapped());
        assert!(MemoryBlockType::ByteMapped.is_mapped());
    }

    #[test]
    fn test_is_default() {
        assert!(MemoryBlockType::Default.is_default());
        assert!(!MemoryBlockType::BitMapped.is_default());
        assert!(!MemoryBlockType::ByteMapped.is_default());
    }

    #[test]
    fn test_is_bit_mapped() {
        assert!(!MemoryBlockType::Default.is_bit_mapped());
        assert!(MemoryBlockType::BitMapped.is_bit_mapped());
        assert!(!MemoryBlockType::ByteMapped.is_bit_mapped());
    }

    #[test]
    fn test_is_byte_mapped() {
        assert!(!MemoryBlockType::Default.is_byte_mapped());
        assert!(!MemoryBlockType::BitMapped.is_byte_mapped());
        assert!(MemoryBlockType::ByteMapped.is_byte_mapped());
    }

    #[test]
    fn test_storage_id_roundtrip() {
        for id in 0..=2 {
            let block_type = MemoryBlockType::from_storage_id(id).unwrap();
            assert_eq!(block_type.storage_id(), id);
        }
    }

    #[test]
    fn test_from_storage_id_invalid() {
        assert!(MemoryBlockType::from_storage_id(3).is_none());
        assert!(MemoryBlockType::from_storage_id(255).is_none());
    }

    #[test]
    fn test_equality() {
        assert_eq!(MemoryBlockType::Default, MemoryBlockType::Default);
        assert_ne!(MemoryBlockType::Default, MemoryBlockType::BitMapped);
        assert_ne!(MemoryBlockType::BitMapped, MemoryBlockType::ByteMapped);
    }

    #[test]
    fn test_copy() {
        let t = MemoryBlockType::ByteMapped;
        let t2 = t;
        assert_eq!(t, t2);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(MemoryBlockType::Default);
        set.insert(MemoryBlockType::BitMapped);
        set.insert(MemoryBlockType::ByteMapped);
        assert_eq!(set.len(), 3);
    }
}
