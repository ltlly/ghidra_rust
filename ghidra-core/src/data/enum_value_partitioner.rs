//! Enum value partitioning for bitmask display.
//!
//! Port of Ghidra's `EnumValuePartitioner.java`.
//!
//! When an enum is in bitmask mode, this class helps partition an arbitrary
//! value into its constituent enum entries.

use std::collections::BTreeMap;
use std::fmt;

/// Partitions a value into its constituent enum bitmask entries.
///
/// Port of Ghidra's `EnumValuePartitioner.java`. Given an enum's value-to-name
/// mappings, this can decompose an arbitrary integer into the combination of
/// named values.
#[derive(Debug, Clone)]
pub struct EnumValuePartitioner {
    /// The enum values mapping name -> value.
    values: BTreeMap<String, i64>,
}

impl EnumValuePartitioner {
    /// Create a new partitioner with the given enum values.
    pub fn new(values: BTreeMap<String, i64>) -> Self {
        Self { values }
    }

    /// Create a partitioner from an iterator of (name, value) pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, i64)>) -> Self {
        Self {
            values: pairs.into_iter().collect(),
        }
    }

    /// Partition a value into its constituent named components.
    ///
    /// Returns a list of (name, value) pairs where each value is a single bit
    /// from the original value that has a corresponding enum entry. If the value
    /// cannot be fully represented by enum entries, a remainder entry is included.
    pub fn partition(&self, target: i64) -> Vec<PartitionEntry> {
        let mut result = Vec::new();
        let mut remaining = target;

        // Sort values by value (descending) for greedy decomposition
        let mut sorted: Vec<(&String, &i64)> = self.values.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));

        for (name, value) in &sorted {
            let val = **value;
            if val == 0 {
                continue; // Skip zero entries
            }
            if (remaining & val) == val {
                result.push(PartitionEntry {
                    name: (*name).clone(),
                    value: val,
                });
                remaining &= !val;
            }
        }

        // Add a remainder entry if any bits are left
        if remaining != 0 {
            result.push(PartitionEntry {
                name: format!("0x{:x}", remaining as u64),
                value: remaining,
            });
        }

        result
    }

    /// Find the name for a single value.
    pub fn get_name(&self, value: i64) -> Option<&str> {
        self.values
            .iter()
            .find(|(_, &v)| v == value)
            .map(|(k, _)| k.as_str())
    }

    /// Get the value for a given name.
    pub fn get_value(&self, name: &str) -> Option<i64> {
        self.values.get(name).copied()
    }

    /// Check if a value can be fully represented by enum entries.
    pub fn can_represent(&self, value: i64) -> bool {
        let partitioned = self.partition(value);
        !partitioned.iter().any(|e| e.name.starts_with("0x"))
    }

    /// Get all enum values.
    pub fn values(&self) -> &BTreeMap<String, i64> {
        &self.values
    }
}

impl fmt::Display for EnumValuePartitioner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnumValuePartitioner ({} entries)",
            self.values.len()
        )
    }
}

/// A single entry in a partition result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionEntry {
    /// The name of this partition entry.
    pub name: String,
    /// The value of this partition entry.
    pub value: i64,
}

impl fmt::Display for PartitionEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:x})", self.name, self.value as u64)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_flag_enum() -> EnumValuePartitioner {
        let mut values = BTreeMap::new();
        values.insert("READ".to_string(), 0x01);
        values.insert("WRITE".to_string(), 0x02);
        values.insert("EXEC".to_string(), 0x04);
        values.insert("ALL".to_string(), 0x07);
        EnumValuePartitioner::new(values)
    }

    #[test]
    fn test_partition_single_flag() {
        let p = make_flag_enum();
        let result = p.partition(0x01);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "READ");
        assert_eq!(result[0].value, 0x01);
    }

    #[test]
    fn test_partition_combined_flags() {
        let p = make_flag_enum();
        let result = p.partition(0x03); // READ | WRITE
        assert_eq!(result.len(), 2);
        let names: Vec<&str> = result.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"READ"));
        assert!(names.contains(&"WRITE"));
    }

    #[test]
    fn test_partition_all_flag() {
        let p = make_flag_enum();
        let result = p.partition(0x07);
        // Should match ALL = 0x07
        assert!(result.iter().any(|e| e.name == "ALL"));
    }

    #[test]
    fn test_partition_remainder() {
        let p = make_flag_enum();
        let result = p.partition(0x0F); // 0x08 has no entry
        assert!(result.iter().any(|e| e.name == "ALL")); // 0x07
        assert!(result.iter().any(|e| e.name.starts_with("0x"))); // remainder 0x08
    }

    #[test]
    fn test_partition_zero() {
        let p = make_flag_enum();
        let result = p.partition(0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_name() {
        let p = make_flag_enum();
        assert_eq!(p.get_name(0x01), Some("READ"));
        assert_eq!(p.get_name(0x99), None);
    }

    #[test]
    fn test_get_value() {
        let p = make_flag_enum();
        assert_eq!(p.get_value("READ"), Some(0x01));
        assert_eq!(p.get_value("NONEXISTENT"), None);
    }

    #[test]
    fn test_can_represent() {
        let p = make_flag_enum();
        assert!(p.can_represent(0x01));
        assert!(p.can_represent(0x03));
        assert!(p.can_represent(0x07));
        assert!(!p.can_represent(0x08));
        assert!(!p.can_represent(0x0F));
    }

    #[test]
    fn test_display() {
        let p = make_flag_enum();
        let s = format!("{}", p);
        assert!(s.contains("4 entries"));
    }

    #[test]
    fn test_partition_entry_display() {
        let entry = PartitionEntry {
            name: "READ".to_string(),
            value: 0x01,
        };
        assert_eq!(format!("{}", entry), "READ (0x1)");
    }
}
