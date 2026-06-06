//! Scalar Table -- display and analyze scalar constants in a program.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.scalartable` Java package.
//!
//! Provides model-level logic for collecting, categorizing, and displaying
//! scalar (integer) constants found in a program's instructions.
//!
//! # Architecture
//!
//! - [`ScalarEntry`] -- a single scalar value occurrence.
//! - [`ScalarTableModel`] -- the data model for the scalar table.
//! - [`ScalarCategory`] -- categorization of scalar values.

/// Scalar value search model, row objects, and plugin.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.scalartable` Java package.
pub mod model;

/// Scalar search model, plugin, provider, dialog, and range filter.
///
/// Ported from `ghidra.app.plugin.core.scalartable.ScalarSearchPlugin`,
/// `ScalarSearchProvider`, `ScalarSearchDialog`, `ScalarSearchModel`,
/// `ScalarSearchContext`, `ScalarColumnConstraintProvider`,
/// `RangeFilterTextField`, and mapper types.
pub mod search;

use ghidra_core::Address;
use std::collections::BTreeMap;

// ============================================================================
// ScalarCategory -- categorization of scalar values
// ============================================================================

/// Categories for scalar values found in instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScalarCategory {
    /// A small value (fits in a byte).
    Small,
    /// A medium value (fits in a 16-bit word).
    Medium,
    /// A large value (requires 32 or 64 bits).
    Large,
    /// A power of two.
    PowerOfTwo,
    /// An ASCII character value.
    Ascii,
    /// A known constant (e.g. from an equate).
    Known,
}

impl ScalarCategory {
    /// Categorize a scalar value.
    pub fn categorize(value: u64) -> Self {
        if value <= 0xFF {
            Self::Small
        } else if value <= 0xFFFF {
            Self::Medium
        } else if value.is_power_of_two() {
            Self::PowerOfTwo
        } else if value >= 0x20 && value <= 0x7E {
            // This path only reachable for values > 0xFFFF that are also ASCII range
            // (impossible, but kept for completeness)
            Self::Ascii
        } else {
            Self::Large
        }
    }

    /// Categorize considering ASCII range.
    pub fn categorize_with_ascii(value: u64, size: usize) -> Self {
        if size == 1 && value >= 0x20 && value <= 0x7E {
            Self::Ascii
        } else if value.is_power_of_two() {
            Self::PowerOfTwo
        } else {
            Self::categorize(value)
        }
    }
}

impl std::fmt::Display for ScalarCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Small => write!(f, "Small"),
            Self::Medium => write!(f, "Medium"),
            Self::Large => write!(f, "Large"),
            Self::PowerOfTwo => write!(f, "Power of Two"),
            Self::Ascii => write!(f, "ASCII"),
            Self::Known => write!(f, "Known"),
        }
    }
}

// ============================================================================
// ScalarEntry -- a single scalar occurrence
// ============================================================================

/// A single scalar value occurrence in a program.
#[derive(Debug, Clone)]
pub struct ScalarEntry {
    /// The scalar value.
    pub value: u64,
    /// The address where this scalar was found.
    pub address: Address,
    /// The operand index where this scalar appears.
    pub operand_index: usize,
    /// The size of the scalar in bytes.
    pub size: usize,
    /// The category of this scalar.
    pub category: ScalarCategory,
    /// The number of times this value appears in the program.
    pub occurrence_count: u32,
}

impl ScalarEntry {
    /// Create a new scalar entry.
    pub fn new(value: u64, address: Address, operand_index: usize, size: usize) -> Self {
        let category = ScalarCategory::categorize_with_ascii(value, size);
        Self {
            value,
            address,
            operand_index,
            size,
            category,
            occurrence_count: 1,
        }
    }
}

// ============================================================================
// ScalarTableModel -- data model for the scalar table
// ============================================================================

/// The data model for the scalar table viewer.
///
/// Collects and indexes scalar values found during instruction analysis.
#[derive(Debug, Default)]
pub struct ScalarTableModel {
    /// All scalar entries.
    entries: Vec<ScalarEntry>,
    /// Index by value: value -> list of indices into `entries`.
    by_value: BTreeMap<u64, Vec<usize>>,
    /// Index by category.
    by_category: BTreeMap<ScalarCategory, Vec<usize>>,
}

impl ScalarTableModel {
    /// Create a new empty table model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a scalar entry.
    pub fn add_entry(&mut self, entry: ScalarEntry) {
        let idx = self.entries.len();
        self.by_value.entry(entry.value).or_default().push(idx);
        self.by_category
            .entry(entry.category)
            .or_default()
            .push(idx);
        self.entries.push(entry);
    }

    /// Get all entries.
    pub fn get_all_entries(&self) -> &[ScalarEntry] {
        &self.entries
    }

    /// Get entries for a specific value.
    pub fn get_entries_for_value(&self, value: u64) -> Vec<&ScalarEntry> {
        self.by_value
            .get(&value)
            .map(|indices| indices.iter().filter_map(|&i| self.entries.get(i)).collect())
            .unwrap_or_default()
    }

    /// Get entries for a specific category.
    pub fn get_entries_for_category(&self, category: ScalarCategory) -> Vec<&ScalarEntry> {
        self.by_category
            .get(&category)
            .map(|indices| indices.iter().filter_map(|&i| self.entries.get(i)).collect())
            .unwrap_or_default()
    }

    /// Return the total number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Return the number of unique scalar values.
    pub fn unique_value_count(&self) -> usize {
        self.by_value.len()
    }

    /// Get the most common scalar values (sorted by occurrence count, descending).
    pub fn most_common_values(&self, limit: usize) -> Vec<(u64, usize)> {
        let mut counts: Vec<(u64, usize)> = self
            .by_value
            .iter()
            .map(|(&val, indices)| (val, indices.len()))
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(limit);
        counts
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_value.clear();
        self.by_category.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_category() {
        assert_eq!(ScalarCategory::categorize(0x42), ScalarCategory::Small);
        assert_eq!(ScalarCategory::categorize(0x1234), ScalarCategory::Medium);
        // 0x10000 = 65536 is a power of two but exceeds Medium range; PowerOfTwo takes precedence
        assert_eq!(ScalarCategory::categorize(0x10000), ScalarCategory::PowerOfTwo);
        assert_eq!(ScalarCategory::categorize(0x100), ScalarCategory::Medium);
        assert_eq!(ScalarCategory::categorize(0x123456), ScalarCategory::Large);
    }

    #[test]
    fn test_scalar_category_ascii() {
        assert_eq!(
            ScalarCategory::categorize_with_ascii(0x41, 1),
            ScalarCategory::Ascii
        );
        assert_eq!(
            ScalarCategory::categorize_with_ascii(0x41, 4),
            ScalarCategory::Small
        );
    }

    #[test]
    fn test_scalar_entry() {
        let entry = ScalarEntry::new(0x41, Address::new(0x1000), 0, 1);
        assert_eq!(entry.category, ScalarCategory::Ascii);
    }

    #[test]
    fn test_table_model_add_and_get() {
        let mut model = ScalarTableModel::new();
        model.add_entry(ScalarEntry::new(0x41, Address::new(0x1000), 0, 1));
        model.add_entry(ScalarEntry::new(0x41, Address::new(0x2000), 1, 1));
        assert_eq!(model.entry_count(), 2);
        assert_eq!(model.unique_value_count(), 1);
    }

    #[test]
    fn test_get_entries_for_value() {
        let mut model = ScalarTableModel::new();
        model.add_entry(ScalarEntry::new(0x41, Address::new(0x1000), 0, 1));
        model.add_entry(ScalarEntry::new(0x42, Address::new(0x2000), 0, 1));
        let entries = model.get_entries_for_value(0x41);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_most_common_values() {
        let mut model = ScalarTableModel::new();
        for i in 0..10 {
            model.add_entry(ScalarEntry::new(0x10, Address::new(0x1000 + i), 0, 1));
        }
        model.add_entry(ScalarEntry::new(0x20, Address::new(0x2000), 0, 1));
        let common = model.most_common_values(5);
        assert_eq!(common[0].0, 0x10);
        assert_eq!(common[0].1, 10);
    }

    #[test]
    fn test_get_entries_for_category() {
        let mut model = ScalarTableModel::new();
        model.add_entry(ScalarEntry::new(0x41, Address::new(0x1000), 0, 1));
        model.add_entry(ScalarEntry::new(0x1234, Address::new(0x2000), 0, 2));
        let ascii_entries = model.get_entries_for_category(ScalarCategory::Ascii);
        assert_eq!(ascii_entries.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut model = ScalarTableModel::new();
        model.add_entry(ScalarEntry::new(0x41, Address::new(0x1000), 0, 1));
        model.clear();
        assert_eq!(model.entry_count(), 0);
    }

    #[test]
    fn test_category_display() {
        assert_eq!(ScalarCategory::Small.to_string(), "Small");
        assert_eq!(ScalarCategory::PowerOfTwo.to_string(), "Power of Two");
    }
}
