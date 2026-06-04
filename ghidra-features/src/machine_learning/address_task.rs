//! Task for gathering addresses to classify.
//!
//! Ported from `GetAddressesToClassifyTask.java` in the MachineLearning
//! extension.
//!
//! This module provides utilities for collecting candidate addresses
//! from a program's address space that need to be classified by the
//! random forest model.

use std::collections::BTreeSet;

/// Configuration for the address gathering task.
#[derive(Debug, Clone)]
pub struct AddressGatherConfig {
    /// Minimum address to consider.
    pub min_address: u64,
    /// Maximum address to consider.
    pub max_address: u64,
    /// Instruction alignment (bytes).
    pub alignment: usize,
    /// Minimum function size in bytes.
    pub min_func_size: usize,
    /// Maximum number of starts to return (0 = unlimited).
    pub max_starts: usize,
    /// Addresses to exclude (already classified or known).
    pub excluded: BTreeSet<u64>,
}

impl AddressGatherConfig {
    /// Create a new configuration with sensible defaults.
    pub fn new(min_address: u64, max_address: u64, alignment: usize) -> Self {
        Self {
            min_address,
            max_address,
            alignment: alignment.max(1),
            min_func_size: 1,
            max_starts: 0,
            excluded: BTreeSet::new(),
        }
    }

    /// Set the minimum function size.
    pub fn with_min_func_size(mut self, size: usize) -> Self {
        self.min_func_size = size;
        self
    }

    /// Set the maximum number of starts to return.
    pub fn with_max_starts(mut self, max: usize) -> Self {
        self.max_starts = max;
        self
    }

    /// Add addresses to exclude.
    pub fn with_excluded(mut self, excluded: BTreeSet<u64>) -> Self {
        self.excluded = excluded;
        self
    }
}

/// Result of the address gathering operation.
#[derive(Debug, Clone)]
pub struct AddressGatherResult {
    /// The candidate addresses to classify.
    pub addresses: Vec<u64>,
    /// Total number of addresses considered (before max_starts limit).
    pub total_considered: usize,
}

/// Gathers addresses from a program's address space for classification.
///
/// Collects all aligned addresses within the configured range, excluding
/// known addresses and respecting the maximum count limit.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::machine_learning::address_task::AddressGatherConfig;
/// use std::collections::BTreeSet;
///
/// let config = AddressGatherConfig::new(0x1000, 0x2000, 4)
///     .with_min_func_size(16)
///     .with_max_starts(100);
///
/// let result = config.gather_addresses();
/// assert!(result.addresses.len() <= 100);
/// ```
impl AddressGatherConfig {
    /// Gather aligned addresses within the configured range.
    ///
    /// Returns addresses aligned to `alignment`, excluding any
    /// addresses in the `excluded` set, up to `max_starts` count.
    pub fn gather_addresses(&self) -> AddressGatherResult {
        let mut addresses = Vec::new();
        let mut total = 0usize;

        // Align the start address upward
        let aligned_start = if self.min_address % self.alignment as u64 == 0 {
            self.min_address
        } else {
            self.min_address + self.alignment as u64
                - (self.min_address % self.alignment as u64)
        };

        let mut addr = aligned_start;
        while addr < self.max_address {
            if !self.excluded.contains(&addr) {
                total += 1;
                if self.max_starts == 0 || addresses.len() < self.max_starts {
                    addresses.push(addr);
                }
            }
            addr += self.alignment as u64;
        }

        AddressGatherResult {
            addresses,
            total_considered: total,
        }
    }

    /// Gather addresses and return only those that are not in a
    /// provided set of known addresses.
    pub fn gather_new_addresses(
        &self,
        known: &BTreeSet<u64>,
    ) -> AddressGatherResult {
        let mut combined_excluded = self.excluded.clone();
        combined_excluded.extend(known.iter().copied());
        let config = Self {
            excluded: combined_excluded,
            ..self.clone()
        };
        config.gather_addresses()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gather_basic() {
        let config = AddressGatherConfig::new(0x1000, 0x1010, 4);
        let result = config.gather_addresses();
        assert_eq!(result.addresses.len(), 4); // 0x1000, 0x1004, 0x1008, 0x100c
        assert_eq!(result.addresses, vec![0x1000, 0x1004, 0x1008, 0x100c]);
    }

    #[test]
    fn test_gather_with_alignment() {
        let config = AddressGatherConfig::new(0x1001, 0x1020, 4);
        let result = config.gather_addresses();
        // Should align up from 0x1001 to 0x1004
        assert_eq!(result.addresses[0], 0x1004);
    }

    #[test]
    fn test_gather_with_exclusion() {
        let mut excluded = BTreeSet::new();
        excluded.insert(0x1004);
        let config = AddressGatherConfig::new(0x1000, 0x1010, 4)
            .with_excluded(excluded);
        let result = config.gather_addresses();
        assert_eq!(result.addresses, vec![0x1000, 0x1008, 0x100c]);
        assert_eq!(result.total_considered, 3);
    }

    #[test]
    fn test_gather_max_starts() {
        let config = AddressGatherConfig::new(0x1000, 0x2000, 4)
            .with_max_starts(5);
        let result = config.gather_addresses();
        assert_eq!(result.addresses.len(), 5);
    }

    #[test]
    fn test_gather_new_addresses() {
        let config = AddressGatherConfig::new(0x1000, 0x1010, 4);
        let mut known = BTreeSet::new();
        known.insert(0x1000);
        known.insert(0x1004);
        let result = config.gather_new_addresses(&known);
        assert_eq!(result.addresses, vec![0x1008, 0x100c]);
    }

    #[test]
    fn test_alignment_minimum_1() {
        let config = AddressGatherConfig::new(0, 10, 0);
        assert_eq!(config.alignment, 1); // Should be clamped to 1
    }

    #[test]
    fn test_gather_empty_range() {
        let config = AddressGatherConfig::new(0x2000, 0x1000, 4);
        let result = config.gather_addresses();
        assert!(result.addresses.is_empty());
    }

    #[test]
    fn test_gather_builder_chain() {
        let config = AddressGatherConfig::new(0x1000, 0x2000, 8)
            .with_min_func_size(16)
            .with_max_starts(10);
        assert_eq!(config.min_func_size, 16);
        assert_eq!(config.max_starts, 10);
        assert_eq!(config.alignment, 8);
    }
}
