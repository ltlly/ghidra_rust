//! Reference utility functions for the location references feature.
//!
//! Ported from `ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils`.
//!
//! Provides helper functions for finding references to various program
//! elements (data types, labels, addresses, mnemonics, etc.).

use std::collections::{BTreeMap, BTreeSet};

use ghidra_core::Address;

use super::locationreferences::{DescriptorKind, LocationReference, LocationDescriptor};

// ---------------------------------------------------------------------------
// ReferenceUtils
// ---------------------------------------------------------------------------

/// Utility functions for finding and collecting references.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils`.
pub struct ReferenceUtils;

impl ReferenceUtils {
    /// Filter a list of references to only include those within a given address set.
    pub fn filter_by_address_set(
        references: &[LocationReference],
        addresses: &BTreeSet<Address>,
    ) -> Vec<LocationReference> {
        references
            .iter()
            .filter(|r| addresses.contains(&r.location_of_use()))
            .cloned()
            .collect()
    }

    /// Group references by their reference type.
    pub fn group_by_ref_type(
        references: &[LocationReference],
    ) -> BTreeMap<String, Vec<LocationReference>> {
        let mut groups: BTreeMap<String, Vec<LocationReference>> = BTreeMap::new();
        for r in references {
            groups
                .entry(r.ref_type_string().to_string())
                .or_default()
                .push(r.clone());
        }
        groups
    }

    /// Filter references to only those within a given address range (inclusive).
    pub fn filter_by_range(
        references: &[LocationReference],
        start: Address,
        end: Address,
    ) -> Vec<LocationReference> {
        references
            .iter()
            .filter(|r| {
                let addr = r.location_of_use();
                addr >= start && addr <= end
            })
            .cloned()
            .collect()
    }

    /// Get unique addresses from a set of references.
    pub fn unique_addresses(references: &[LocationReference]) -> BTreeSet<Address> {
        references.iter().map(|r| r.location_of_use()).collect()
    }

    /// Filter out offcut references.
    pub fn excluding_offcuts(references: &[LocationReference]) -> Vec<LocationReference> {
        references
            .iter()
            .filter(|r| !r.is_offcut_reference())
            .cloned()
            .collect()
    }

    /// Sort references by address.
    pub fn sort_by_address(references: &mut [LocationReference]) {
        references.sort_by(|a, b| a.location_of_use().cmp(&b.location_of_use()));
    }

    /// Merge two sorted lists of references, removing duplicates.
    pub fn merge_sorted(
        list1: &[LocationReference],
        list2: &[LocationReference],
    ) -> Vec<LocationReference> {
        let mut result = Vec::with_capacity(list1.len() + list2.len());
        let (mut i, mut j) = (0, 0);

        while i < list1.len() && j < list2.len() {
            match list1[i].location_of_use().cmp(&list2[j].location_of_use()) {
                std::cmp::Ordering::Less => {
                    result.push(list1[i].clone());
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    result.push(list2[j].clone());
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    // Deduplicate: keep the first one
                    result.push(list1[i].clone());
                    i += 1;
                    j += 1;
                }
            }
        }
        result.extend_from_slice(&list1[i..]);
        result.extend_from_slice(&list2[j..]);
        result
    }

    /// Count references by type.
    pub fn count_by_type(references: &[LocationReference]) -> BTreeMap<String, usize> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for r in references {
            *counts
                .entry(r.ref_type_string().to_string())
                .or_insert(0) += 1;
        }
        counts
    }

    /// Create a simple address-based descriptor.
    pub fn create_address_descriptor(
        address: Address,
        label: impl Into<String>,
        program_name: impl Into<String>,
    ) -> LocationDescriptor {
        LocationDescriptor::new(
            DescriptorKind::Address,
            address,
            label,
            program_name,
        )
    }

    /// Create a data type descriptor.
    pub fn create_data_type_descriptor(
        address: Address,
        type_name: impl Into<String>,
        program_name: impl Into<String>,
    ) -> LocationDescriptor {
        LocationDescriptor::new(
            DescriptorKind::DataType,
            address,
            type_name,
            program_name,
        )
    }

    /// Create a label descriptor.
    pub fn create_label_descriptor(
        address: Address,
        label: impl Into<String>,
        program_name: impl Into<String>,
    ) -> LocationDescriptor {
        LocationDescriptor::new(
            DescriptorKind::Label,
            address,
            label,
            program_name,
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn refs() -> Vec<LocationReference> {
        vec![
            LocationReference::with_ref_type(addr(0x1000), "READ", false),
            LocationReference::with_ref_type(addr(0x2000), "WRITE", false),
            LocationReference::with_ref_type(addr(0x3000), "READ", false),
            LocationReference::with_ref_type(addr(0x4000), "CALL", false),
        ]
    }

    #[test]
    fn test_filter_by_address_set() {
        let references = refs();
        let mut addrs = BTreeSet::new();
        addrs.insert(addr(0x1000));
        addrs.insert(addr(0x3000));

        let filtered = ReferenceUtils::filter_by_address_set(&references, &addrs);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].location_of_use(), addr(0x1000));
        assert_eq!(filtered[1].location_of_use(), addr(0x3000));
    }

    #[test]
    fn test_group_by_ref_type() {
        let references = refs();
        let groups = ReferenceUtils::group_by_ref_type(&references);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups["READ"].len(), 2);
        assert_eq!(groups["WRITE"].len(), 1);
        assert_eq!(groups["CALL"].len(), 1);
    }

    #[test]
    fn test_filter_by_range() {
        let references = refs();
        let filtered = ReferenceUtils::filter_by_range(&references, addr(0x1500), addr(0x3500));
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].location_of_use(), addr(0x2000));
        assert_eq!(filtered[1].location_of_use(), addr(0x3000));
    }

    #[test]
    fn test_unique_addresses() {
        let references = refs();
        let unique = ReferenceUtils::unique_addresses(&references);
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn test_excluding_offcuts() {
        let mut references = refs();
        references.push(LocationReference::with_ref_type(addr(0x5000), "READ", true));
        let no_offcuts = ReferenceUtils::excluding_offcuts(&references);
        assert_eq!(no_offcuts.len(), 4);
    }

    #[test]
    fn test_sort_by_address() {
        let mut references = vec![
            LocationReference::new(addr(0x3000)),
            LocationReference::new(addr(0x1000)),
            LocationReference::new(addr(0x2000)),
        ];
        ReferenceUtils::sort_by_address(&mut references);
        assert_eq!(references[0].location_of_use(), addr(0x1000));
        assert_eq!(references[1].location_of_use(), addr(0x2000));
        assert_eq!(references[2].location_of_use(), addr(0x3000));
    }

    #[test]
    fn test_merge_sorted() {
        let list1 = vec![
            LocationReference::new(addr(0x1000)),
            LocationReference::new(addr(0x3000)),
        ];
        let list2 = vec![
            LocationReference::new(addr(0x2000)),
            LocationReference::new(addr(0x4000)),
        ];
        let merged = ReferenceUtils::merge_sorted(&list1, &list2);
        assert_eq!(merged.len(), 4);
        assert_eq!(merged[0].location_of_use(), addr(0x1000));
        assert_eq!(merged[1].location_of_use(), addr(0x2000));
        assert_eq!(merged[2].location_of_use(), addr(0x3000));
        assert_eq!(merged[3].location_of_use(), addr(0x4000));
    }

    #[test]
    fn test_merge_sorted_dedup() {
        let list1 = vec![LocationReference::new(addr(0x1000))];
        let list2 = vec![LocationReference::new(addr(0x1000))];
        let merged = ReferenceUtils::merge_sorted(&list1, &list2);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_count_by_type() {
        let references = refs();
        let counts = ReferenceUtils::count_by_type(&references);
        assert_eq!(counts["READ"], 2);
        assert_eq!(counts["WRITE"], 1);
        assert_eq!(counts["CALL"], 1);
    }

    #[test]
    fn test_create_descriptors() {
        let desc = ReferenceUtils::create_address_descriptor(addr(0x1000), "main", "test.exe");
        assert_eq!(desc.kind(), &DescriptorKind::Address);

        let desc = ReferenceUtils::create_data_type_descriptor(addr(0x1000), "int", "test.exe");
        assert_eq!(desc.kind(), &DescriptorKind::DataType);

        let desc = ReferenceUtils::create_label_descriptor(addr(0x1000), "myLabel", "test.exe");
        assert_eq!(desc.kind(), &DescriptorKind::Label);
    }
}
