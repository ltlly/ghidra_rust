//! Source type classification for symbols and references.
//!
//! This module provides the [`SourceType`] enum which indicates the origin
//! or provenance of a markup (symbol, reference, etc.) in a program.
//!
//! # Correspondence to Ghidra
//!
//! This is a direct translation of `ghidra.program.model.symbol.SourceType`.
//! The Java version defines a simple enum with priority ordering and storage
//! IDs. This Rust version adds helper methods for comparison, serialization,
//! and display.
//!
//! # Priority Order
//!
//! From highest to lowest priority:
//! 1. [`UserDefined`](SourceType::UserDefined) — content entered by the user
//! 2. [`Imported`](SourceType::Imported) — content from reliable import data
//! 3. [`Analysis`](SourceType::Analysis) — content produced by an analyzer
//! 4. [`AI`](SourceType::AI) — content produced by AI assistance (same as Analysis)
//! 5. [`Default`](SourceType::Default) — dynamically produced content (lowest)

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// SourceType
// ============================================================================

/// Indicates the general source/origin of a markup made to a program.
///
/// The priority order (highest to lowest) is:
/// 1. [`UserDefined`](SourceType::UserDefined)
/// 2. [`Imported`](SourceType::Imported)
/// 3. [`Analysis`](SourceType::Analysis) / [`AI`](SourceType::AI) (equal)
/// 4. [`Default`](SourceType::Default) (lowest)
///
/// # Examples
///
/// ```
/// use ghidra_core::symbol::source_type::SourceType;
///
/// assert!(SourceType::UserDefined.is_higher_priority_than(SourceType::Default));
/// assert!(SourceType::Imported.is_higher_priority_than(SourceType::Analysis));
/// assert_eq!(SourceType::Default.display_string(), "Default");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceType {
    /// Dynamically produced content (lowest priority). Storage ID 1.
    Default,
    /// Content produced by an analyzer. Storage ID 2.
    Analysis,
    /// Content produced through AI assistance. Storage ID 2 (same level as Analysis).
    AI,
    /// Content produced during import of reliable data. Storage ID 3.
    Imported,
    /// Content produced by the user (highest priority). Storage ID 4.
    UserDefined,
}

impl SourceType {
    /// Source types indexed by storage ID.
    const BY_STORAGE_ID: [Option<SourceType>; 5] = [
        Some(SourceType::Analysis),    // 0
        Some(SourceType::UserDefined), // 1
        Some(SourceType::Default),     // 2
        Some(SourceType::Imported),    // 3
        Some(SourceType::AI),          // 4
    ];

    /// Returns the numeric priority. Higher numbers mean higher priority.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::symbol::source_type::SourceType;
    ///
    /// assert_eq!(SourceType::Default.priority(), 1);
    /// assert_eq!(SourceType::Analysis.priority(), 2);
    /// assert_eq!(SourceType::UserDefined.priority(), 4);
    /// ```
    pub fn priority(self) -> u8 {
        match self {
            SourceType::Default => 1,
            SourceType::Analysis => 2,
            SourceType::AI => 2,
            SourceType::Imported => 3,
            SourceType::UserDefined => 4,
        }
    }

    /// Returns the storage ID for persistent serialization.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::symbol::source_type::SourceType;
    ///
    /// assert_eq!(SourceType::Default.storage_id(), 2);
    /// assert_eq!(SourceType::Analysis.storage_id(), 0);
    /// assert_eq!(SourceType::UserDefined.storage_id(), 1);
    /// ```
    pub fn storage_id(self) -> u8 {
        match self {
            SourceType::Default => 2,
            SourceType::Analysis => 0,
            SourceType::AI => 4,
            SourceType::Imported => 3,
            SourceType::UserDefined => 1,
        }
    }

    /// Returns the `SourceType` for the given storage ID.
    ///
    /// Returns `None` if the ID does not correspond to a known source type.
    pub fn from_storage_id(id: u8) -> Option<SourceType> {
        Self::BY_STORAGE_ID.get(id as usize).copied().flatten()
    }

    /// Returns `true` if this source type has higher priority than `other`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::symbol::source_type::SourceType;
    ///
    /// assert!(SourceType::UserDefined.is_higher_priority_than(SourceType::Default));
    /// assert!(!SourceType::Default.is_higher_priority_than(SourceType::UserDefined));
    /// ```
    pub fn is_higher_priority_than(self, other: SourceType) -> bool {
        self.priority() > other.priority()
    }

    /// Returns `true` if this source type has higher or equal priority.
    pub fn is_higher_or_equal_priority_than(self, other: SourceType) -> bool {
        self.priority() >= other.priority()
    }

    /// Returns `true` if this source type has lower priority than `other`.
    pub fn is_lower_priority_than(self, other: SourceType) -> bool {
        self.priority() < other.priority()
    }

    /// Returns `true` if this source type has lower or equal priority.
    pub fn is_lower_or_equal_priority_than(self, other: SourceType) -> bool {
        self.priority() <= other.priority()
    }

    /// Returns a user-friendly display string.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::symbol::source_type::SourceType;
    ///
    /// assert_eq!(SourceType::UserDefined.display_string(), "User Defined");
    /// assert_eq!(SourceType::AI.display_string(), "AI");
    /// ```
    pub fn display_string(self) -> &'static str {
        match self {
            SourceType::Default => "Default",
            SourceType::Analysis => "Analysis",
            SourceType::AI => "AI",
            SourceType::Imported => "Imported",
            SourceType::UserDefined => "User Defined",
        }
    }
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_string())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        assert!(SourceType::UserDefined.priority() > SourceType::Imported.priority());
        assert!(SourceType::Imported.priority() > SourceType::Analysis.priority());
        assert!(SourceType::Analysis.priority() > SourceType::Default.priority());
        assert_eq!(SourceType::Analysis.priority(), SourceType::AI.priority());
    }

    #[test]
    fn test_storage_id_roundtrip() {
        for id in 0..=4 {
            let st = SourceType::from_storage_id(id).unwrap();
            assert_eq!(st.storage_id(), id);
        }
    }

    #[test]
    fn test_from_storage_id_invalid() {
        assert!(SourceType::from_storage_id(5).is_none());
        assert!(SourceType::from_storage_id(255).is_none());
    }

    #[test]
    fn test_is_higher_priority_than() {
        assert!(SourceType::UserDefined.is_higher_priority_than(SourceType::Default));
        assert!(SourceType::Imported.is_higher_priority_than(SourceType::Analysis));
        assert!(!SourceType::Default.is_higher_priority_than(SourceType::UserDefined));
        assert!(!SourceType::Analysis.is_higher_priority_than(SourceType::AI));
    }

    #[test]
    fn test_is_lower_priority_than() {
        assert!(SourceType::Default.is_lower_priority_than(SourceType::UserDefined));
        assert!(!SourceType::UserDefined.is_lower_priority_than(SourceType::Default));
        assert!(!SourceType::Analysis.is_lower_priority_than(SourceType::AI));
    }

    #[test]
    fn test_display_string() {
        assert_eq!(SourceType::Default.display_string(), "Default");
        assert_eq!(SourceType::Analysis.display_string(), "Analysis");
        assert_eq!(SourceType::AI.display_string(), "AI");
        assert_eq!(SourceType::Imported.display_string(), "Imported");
        assert_eq!(SourceType::UserDefined.display_string(), "User Defined");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", SourceType::UserDefined), "User Defined");
        assert_eq!(format!("{}", SourceType::Default), "Default");
    }

    #[test]
    fn test_equality() {
        assert_eq!(SourceType::Default, SourceType::Default);
        assert_ne!(SourceType::Default, SourceType::Analysis);
        assert_ne!(SourceType::Analysis, SourceType::AI);
    }

    #[test]
    fn test_copy_clone() {
        let st = SourceType::UserDefined;
        let cloned = st;
        assert_eq!(st, cloned);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SourceType::Default);
        set.insert(SourceType::Analysis);
        set.insert(SourceType::AI);
        set.insert(SourceType::Imported);
        set.insert(SourceType::UserDefined);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn test_serde_roundtrip() {
        let st = SourceType::UserDefined;
        let json = serde_json::to_string(&st).unwrap();
        let deserialized: SourceType = serde_json::from_str(&json).unwrap();
        assert_eq!(st, deserialized);
    }
}
