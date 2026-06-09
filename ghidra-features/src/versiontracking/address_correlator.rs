//! Address correlator -- maps addresses between source and destination programs.
//!
//! Corresponds to Ghidra's `VTAddressCorrelator` Java class and the related
//! `AddressCorrelation` / `AddressMapping` types.
//!
//! This module provides a higher-level wrapper that takes a program-level view
//! of address correlation: given a set of matched functions, it builds an
//! aggregate address mapping that can be used to translate offsets within a
//! source function to offsets within the corresponding destination function.

use std::collections::HashMap;

use ghidra_core::addr::Address;

use crate::versiontracking::correlator::address::{
    AddressCorrelation, AddressCorrelator, AddressMapping,
    ExactMatchAddressCorrelator, LinearAddressCorrelator,
    StraightLineCorrelation, VtHashedFunctionAddressCorrelator,
};
use crate::versiontracking::helpers::{function_listing_rows, listing_bytes, listing_mnemonics};
use crate::versiontracking::options::VtOptions;

/// A program-level address correlator that combines multiple low-level
/// address correlators to produce mappings for a pair of programs.
pub struct VtAddressCorrelator {
    correlators: Vec<Box<dyn AddressCorrelator>>,
    options: VtOptions,
}

impl VtAddressCorrelator {
    /// Create a new address correlator with default correlators.
    pub fn new() -> Self {
        let mut correlators: Vec<Box<dyn AddressCorrelator>> = Vec::new();
        correlators.push(Box::new(ExactMatchAddressCorrelator::new()));
        correlators.push(Box::new(StraightLineCorrelation::new()));
        correlators.push(Box::new(LinearAddressCorrelator::new()));
        // Sort by priority so that lower-priority (higher precedence) correlators run first.
        correlators.sort_by_key(|c| c.priority());
        Self {
            correlators,
            options: VtOptions::new("VtAddressCorrelator"),
        }
    }

    /// Create a new address correlator with a processor name (for hashed correlator).
    pub fn with_processor(processor: impl Into<String>) -> Self {
        let mut base = Self::new();
        base.correlators
            .push(Box::new(VtHashedFunctionAddressCorrelator::new(processor)));
        base.correlators.sort_by_key(|c| c.priority());
        base
    }

    /// Create a new address correlator with custom correlators.
    pub fn with_correlators(correlators: Vec<Box<dyn AddressCorrelator>>) -> Self {
        Self {
            correlators,
            options: VtOptions::new("VtAddressCorrelator"),
        }
    }

    /// Add a correlator.
    pub fn add_correlator(&mut self, correlator: Box<dyn AddressCorrelator>) {
        self.correlators.push(correlator);
        self.correlators.sort_by_key(|c| c.priority());
    }

    /// Get the number of registered correlators.
    pub fn correlator_count(&self) -> usize {
        self.correlators.len()
    }

    /// Correlate function addresses using the registered correlators.
    ///
    /// Tries each correlator in priority order and returns the first
    /// successful correlation.
    pub fn correlate_function_addresses(
        &self,
        source_entry: Address,
        source_bytes: &[u8],
        source_mnemonics: &[String],
        dest_entry: Address,
        dest_bytes: &[u8],
        dest_mnemonics: &[String],
    ) -> Option<AddressCorrelation> {
        for correlator in &self.correlators {
            if let Some(corr) = correlator.correlate_functions(
                source_entry,
                source_bytes,
                source_mnemonics,
                dest_entry,
                dest_bytes,
                dest_mnemonics,
            ) {
                return Some(corr);
            }
        }
        None
    }

    /// Correlate data addresses using the registered correlators.
    ///
    /// Tries each correlator in priority order and returns the first
    /// successful correlation.
    pub fn correlate_data_addresses(
        &self,
        source_entry: Address,
        source_bytes: &[u8],
        dest_entry: Address,
        dest_bytes: &[u8],
    ) -> Option<AddressCorrelation> {
        for correlator in &self.correlators {
            if let Some(corr) =
                correlator.correlate_data(source_entry, source_bytes, dest_entry, dest_bytes)
            {
                return Some(corr);
            }
        }
        None
    }

    /// Build an aggregate mapping from a set of function-level correlations.
    ///
    /// Given pairs of (source_entry, dest_entry) addresses, uses the listing
    /// data from each program to compute per-instruction address mappings and
    /// merges them into a single lookup table.
    pub fn build_aggregate_mapping(
        &self,
        source: &ghidra_core::program::Program,
        dest: &ghidra_core::program::Program,
        function_pairs: &[(Address, Address)],
    ) -> HashMap<Address, Address> {
        let mut aggregate: HashMap<Address, Address> = HashMap::new();

        for &(src_entry, dst_entry) in function_pairs {
            let src_rows = function_listing_rows(source, src_entry);
            let dst_rows = function_listing_rows(dest, dst_entry);
            let src_bytes = listing_bytes(&src_rows);
            let dst_bytes = listing_bytes(&dst_rows);
            let src_mnems = listing_mnemonics(&src_rows);
            let dst_mnems = listing_mnemonics(&dst_rows);

            if let Some(corr) = self.correlate_function_addresses(
                src_entry, &src_bytes, &src_mnems, dst_entry, &dst_bytes, &dst_mnems,
            ) {
                for mapping in &corr.mappings {
                    aggregate.insert(mapping.source, mapping.destination);
                }
            }
        }

        aggregate
    }

    /// Get the options for this correlator.
    pub fn options(&self) -> &VtOptions {
        &self.options
    }

    /// Set the options for this correlator.
    pub fn set_options(&mut self, options: VtOptions) {
        self.options = options;
    }
}

impl Default for VtAddressCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for VtAddressCorrelator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VtAddressCorrelator")
            .field("correlator_count", &self.correlators.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn test_default_correlator_count() {
        let corr = VtAddressCorrelator::new();
        // ExactMatch, StraightLine, Linear = 3
        assert_eq!(corr.correlator_count(), 3);
    }

    #[test]
    fn test_with_processor() {
        let corr = VtAddressCorrelator::with_processor("x86");
        // ExactMatch, StraightLine, Linear, Hashed = 4
        assert_eq!(corr.correlator_count(), 4);
    }

    #[test]
    fn test_correlate_function_addresses_exact() {
        let corr = VtAddressCorrelator::new();
        let bytes = &[0x55u8, 0x48, 0x89, 0xe5, 0xc3];
        let result = corr.correlate_function_addresses(
            addr(0x1000),
            bytes,
            &[],
            addr(0x2000),
            bytes,
            &[],
        );
        assert!(result.is_some());
        let c = result.unwrap();
        assert_eq!(c.mappings.len(), 5);
        assert!((c.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_correlate_function_addresses_different() {
        let corr = VtAddressCorrelator::new();
        let result = corr.correlate_function_addresses(
            addr(0x1000),
            &[0x55, 0x48],
            &[],
            addr(0x2000),
            &[0x90, 0x90],
            &[],
        );
        // Falls through to linear correlator which always returns Some
        assert!(result.is_some());
    }

    #[test]
    fn test_correlate_data_addresses_exact() {
        let corr = VtAddressCorrelator::new();
        let data = &[0x01u8, 0x02, 0x03, 0x04];
        let result =
            corr.correlate_data_addresses(addr(0x3000), data, addr(0x4000), data);
        assert!(result.is_some());
        assert!((result.unwrap().confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_correlate_data_addresses_empty() {
        let corr = VtAddressCorrelator::new();
        let result = corr.correlate_data_addresses(addr(0x3000), &[], addr(0x4000), &[]);
        // ExactMatch returns None for empty bytes; linear also returns None for empty data
        // Actually linear always returns Some for data
        assert!(result.is_some());
    }

    #[test]
    fn test_custom_correlators() {
        let corr = VtAddressCorrelator::with_correlators(vec![Box::new(
            ExactMatchAddressCorrelator::new(),
        )]);
        assert_eq!(corr.correlator_count(), 1);
    }

    #[test]
    fn test_add_correlator() {
        let mut corr = VtAddressCorrelator::with_correlators(vec![]);
        assert_eq!(corr.correlator_count(), 0);
        corr.add_correlator(Box::new(ExactMatchAddressCorrelator::new()));
        assert_eq!(corr.correlator_count(), 1);
    }

    #[test]
    fn test_options() {
        let mut corr = VtAddressCorrelator::new();
        assert_eq!(corr.options().name(), "VtAddressCorrelator");
        let opts = VtOptions::new("custom");
        corr.set_options(opts);
        assert_eq!(corr.options().name(), "custom");
    }

    #[test]
    fn test_debug_format() {
        let corr = VtAddressCorrelator::new();
        let debug = format!("{:?}", corr);
        assert!(debug.contains("VtAddressCorrelator"));
    }

    #[test]
    fn test_correlation_confidence_range() {
        let corr = VtAddressCorrelator::new();
        let src = &[0x55u8, 0x48, 0x89, 0xe5, 0xc3];
        let dst = &[0x55u8, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0xc3];
        let result = corr.correlate_function_addresses(
            addr(0x1000), src, &[], addr(0x2000), dst, &[],
        );
        assert!(result.is_some());
        let c = result.unwrap();
        assert!(c.confidence > 0.0 && c.confidence <= 1.0);
    }
}
