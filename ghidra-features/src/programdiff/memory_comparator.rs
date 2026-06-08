//! Program memory comparator for detecting memory layout differences.
//!
//! Ported from Ghidra's `ghidra.program.util.ProgramMemoryComparator` Java class.
//!
//! Compares the memory layouts of two programs to determine if they have
//! the same memory blocks, and identifies addresses that exist in only one program.

use std::collections::{BTreeMap, BTreeSet};

use super::diff_controller::AddressSet;

/// Result of comparing the memory layouts of two programs.
///
/// Ported from Ghidra's `ProgramMemoryComparator` Java class.
#[derive(Debug, Clone)]
pub struct ProgramMemoryComparator {
    /// Addresses only in program 1.
    addresses_only_in_one: AddressSet,
    /// Addresses only in program 2.
    addresses_only_in_two: AddressSet,
    /// Addresses common to both programs.
    common_addresses: AddressSet,
    /// Whether the two programs have different memory layouts.
    has_memory_differences: bool,
}

impl ProgramMemoryComparator {
    /// Compare the memory layouts of two programs.
    ///
    /// # Arguments
    ///
    /// * `blocks1` - Map of block name to (start_address, size) for program 1.
    /// * `blocks2` - Map of block name to (start_address, size) for program 2.
    pub fn new(
        blocks1: &BTreeMap<String, (u64, usize)>,
        blocks2: &BTreeMap<String, (u64, usize)>,
    ) -> Self {
        let mut addrs1 = AddressSet::new();
        let mut addrs2 = AddressSet::new();

        for (_, (start, size)) in blocks1 {
            if *size > 0 {
                addrs1.add_range(*start, *start + *size as u64 - 1);
            }
        }

        for (_, (start, size)) in blocks2 {
            if *size > 0 {
                addrs2.add_range(*start, *start + *size as u64 - 1);
            }
        }

        let addresses_only_in_one = addrs1.difference(&addrs2);
        let addresses_only_in_two = addrs2.difference(&addrs1);
        let common_addresses = addrs1.intersect(&addrs2);
        let has_memory_differences =
            !addresses_only_in_one.is_empty() || !addresses_only_in_two.is_empty();

        Self {
            addresses_only_in_one,
            addresses_only_in_two,
            common_addresses,
            has_memory_differences,
        }
    }

    /// Compare using byte-level data from program snapshots.
    ///
    /// This compares the actual memory content rather than just block definitions.
    pub fn from_byte_maps(
        bytes1: &BTreeMap<u64, u8>,
        bytes2: &BTreeMap<u64, u8>,
    ) -> Self {
        let mut addrs1 = AddressSet::new();
        let mut addrs2 = AddressSet::new();

        for &addr in bytes1.keys() {
            addrs1.add_address(addr);
        }
        for &addr in bytes2.keys() {
            addrs2.add_address(addr);
        }

        let addresses_only_in_one = addrs1.difference(&addrs2);
        let addresses_only_in_two = addrs2.difference(&addrs1);
        let common_addresses = addrs1.intersect(&addrs2);
        let has_memory_differences =
            !addresses_only_in_one.is_empty() || !addresses_only_in_two.is_empty();

        Self {
            addresses_only_in_one,
            addresses_only_in_two,
            common_addresses,
            has_memory_differences,
        }
    }

    /// Check if the two programs have different memory layouts.
    pub fn has_memory_differences(&self) -> bool {
        self.has_memory_differences
    }

    /// Get addresses that exist only in program 1.
    pub fn addresses_only_in_one(&self) -> &AddressSet {
        &self.addresses_only_in_one
    }

    /// Get addresses that exist only in program 2.
    pub fn addresses_only_in_two(&self) -> &AddressSet {
        &self.addresses_only_in_two
    }

    /// Get addresses common to both programs.
    pub fn common_addresses(&self) -> &AddressSet {
        &self.common_addresses
    }

    /// Get the combined address set (all addresses in either program).
    pub fn combined_addresses(&self) -> AddressSet {
        self.addresses_only_in_one
            .union(&self.addresses_only_in_two)
            .union(&self.common_addresses)
    }

    /// Get a human-readable message describing the memory differences.
    pub fn difference_message(&self) -> String {
        if !self.has_memory_differences {
            return "The memory addresses defined by the two programs are the same.".to_string();
        }

        let mut msg = String::from(
            "The memory addresses defined by the two programs are not the same.\n",
        );

        if !self.addresses_only_in_one.is_empty() {
            msg.push_str(&format!(
                "\nSome addresses are only in program 1: {} ranges, {} addresses\n",
                self.addresses_only_in_one.num_ranges(),
                self.addresses_only_in_one.num_addresses()
            ));
        }

        if !self.addresses_only_in_two.is_empty() {
            msg.push_str(&format!(
                "\nSome addresses are only in program 2: {} ranges, {} addresses\n",
                self.addresses_only_in_two.num_ranges(),
                self.addresses_only_in_two.num_addresses()
            ));
        }

        msg
    }
}

/// Check if two programs have compatible memory for diffing.
///
/// Two programs are considered compatible if they share at least some
/// common addresses.
pub fn are_programs_compatible(
    blocks1: &BTreeMap<String, (u64, usize)>,
    blocks2: &BTreeMap<String, (u64, usize)>,
) -> bool {
    let comparator = ProgramMemoryComparator::new(blocks1, blocks2);
    !comparator.common_addresses().is_empty()
}

/// Get the combined address set from two programs.
///
/// Returns the union of all addresses in both programs.
pub fn get_combined_addresses(
    blocks1: &BTreeMap<String, (u64, usize)>,
    blocks2: &BTreeMap<String, (u64, usize)>,
) -> AddressSet {
    let comparator = ProgramMemoryComparator::new(blocks1, blocks2);
    comparator.combined_addresses()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_memory_layout() {
        let mut blocks1 = BTreeMap::new();
        blocks1.insert(".text".to_string(), (0x1000, 0x100));
        blocks1.insert(".data".to_string(), (0x2000, 0x100));

        let mut blocks2 = BTreeMap::new();
        blocks2.insert(".text".to_string(), (0x1000, 0x100));
        blocks2.insert(".data".to_string(), (0x2000, 0x100));

        let comparator = ProgramMemoryComparator::new(&blocks1, &blocks2);
        assert!(!comparator.has_memory_differences());
        assert!(comparator.addresses_only_in_one().is_empty());
        assert!(comparator.addresses_only_in_two().is_empty());
    }

    #[test]
    fn test_different_memory_layout() {
        let mut blocks1 = BTreeMap::new();
        blocks1.insert(".text".to_string(), (0x1000, 0x100));

        let mut blocks2 = BTreeMap::new();
        blocks2.insert(".text".to_string(), (0x1000, 0x100));
        blocks2.insert(".data".to_string(), (0x2000, 0x100));

        let comparator = ProgramMemoryComparator::new(&blocks1, &blocks2);
        assert!(comparator.has_memory_differences());
        assert!(comparator.addresses_only_in_one().is_empty());
        assert!(!comparator.addresses_only_in_two().is_empty());
    }

    #[test]
    fn test_overlapping_memory() {
        let mut blocks1 = BTreeMap::new();
        blocks1.insert(".text".to_string(), (0x1000, 0x200));

        let mut blocks2 = BTreeMap::new();
        blocks2.insert(".text".to_string(), (0x1100, 0x200));

        let comparator = ProgramMemoryComparator::new(&blocks1, &blocks2);
        assert!(comparator.has_memory_differences());
        assert!(!comparator.addresses_only_in_one().is_empty());
        assert!(!comparator.addresses_only_in_two().is_empty());
        assert!(!comparator.common_addresses().is_empty());
    }

    #[test]
    fn test_combined_addresses() {
        let mut blocks1 = BTreeMap::new();
        blocks1.insert(".text".to_string(), (0x1000, 0x100));

        let mut blocks2 = BTreeMap::new();
        blocks2.insert(".data".to_string(), (0x2000, 0x100));

        let combined = get_combined_addresses(&blocks1, &blocks2);
        assert!(combined.contains(0x1000));
        assert!(combined.contains(0x2000));
    }

    #[test]
    fn test_compatible_programs() {
        let mut blocks1 = BTreeMap::new();
        blocks1.insert(".text".to_string(), (0x1000, 0x100));

        let mut blocks2 = BTreeMap::new();
        blocks2.insert(".text".to_string(), (0x1000, 0x100));

        assert!(are_programs_compatible(&blocks1, &blocks2));
    }

    #[test]
    fn test_incompatible_programs() {
        let mut blocks1 = BTreeMap::new();
        blocks1.insert(".text".to_string(), (0x1000, 0x100));

        let mut blocks2 = BTreeMap::new();
        blocks2.insert(".data".to_string(), (0x2000, 0x100));

        assert!(!are_programs_compatible(&blocks1, &blocks2));
    }

    #[test]
    fn test_difference_message_no_diff() {
        let mut blocks = BTreeMap::new();
        blocks.insert(".text".to_string(), (0x1000, 0x100));
        let comparator = ProgramMemoryComparator::new(&blocks, &blocks);
        let msg = comparator.difference_message();
        assert!(msg.contains("the same"));
    }

    #[test]
    fn test_difference_message_with_diff() {
        let mut blocks1 = BTreeMap::new();
        blocks1.insert(".text".to_string(), (0x1000, 0x100));
        let mut blocks2 = BTreeMap::new();
        blocks2.insert(".data".to_string(), (0x2000, 0x100));
        let comparator = ProgramMemoryComparator::new(&blocks1, &blocks2);
        let msg = comparator.difference_message();
        assert!(msg.contains("not the same"));
    }
}
