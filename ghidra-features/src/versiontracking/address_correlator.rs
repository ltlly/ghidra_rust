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
use std::fmt;

use ghidra_core::addr::Address;

use crate::versiontracking::correlator::address::{
    AddressCorrelation, AddressCorrelator, AddressMapping,
    ExactMatchAddressCorrelator, LinearAddressCorrelator,
    StraightLineCorrelation, VtHashedFunctionAddressCorrelator,
};
use crate::versiontracking::helpers::{function_listing_rows, listing_bytes, listing_mnemonics};
use crate::versiontracking::options::VtOptions;

// ---------------------------------------------------------------------------
// Priority constants (from Java AddressCorrelator interface)
// ---------------------------------------------------------------------------

/// The default priority for address correlators.
pub const DEFAULT_PRIORITY: i32 = 500;

/// A high priority (low number value) for correlators that should run first.
pub const EARLY_PRIORITY: i32 = 100;

/// A low priority (high number value) for correlators that should run last.
pub const LATE_CHANCE_PRIORITY: i32 = 1000;

/// A value used to raise or lower priorities.
pub const PRIORITY_OFFSET: i32 = 10;

// ---------------------------------------------------------------------------
// CachedAddressCorrelation
// ---------------------------------------------------------------------------

/// A cached address correlation that stores the forward and reverse mappings
/// for efficient lookups.
///
/// Corresponds to Ghidra's `AddressCorrelation` interface with caching.
#[derive(Debug, Clone)]
pub struct CachedAddressCorrelation {
    /// The name of the correlator that produced this correlation.
    name: String,
    /// The source function entry point.
    pub source_entry: Address,
    /// The destination function entry point.
    pub destination_entry: Address,
    /// Forward mapping: source address -> destination address.
    forward_map: HashMap<Address, Address>,
    /// Reverse mapping: destination address -> source address.
    reverse_map: HashMap<Address, Address>,
    /// All individual address mappings.
    pub mappings: Vec<AddressMapping>,
    /// The confidence score for this correlation.
    pub confidence: f64,
}

impl CachedAddressCorrelation {
    /// Create a new cached correlation from an existing `AddressCorrelation`.
    pub fn from_correlation(corr: &AddressCorrelation, name: impl Into<String>) -> Self {
        let mut forward_map = HashMap::new();
        let mut reverse_map = HashMap::new();
        for mapping in &corr.mappings {
            forward_map.insert(mapping.source, mapping.destination);
            reverse_map.insert(mapping.destination, mapping.source);
        }
        Self {
            name: name.into(),
            source_entry: corr.source_entry,
            destination_entry: corr.destination_entry,
            forward_map,
            reverse_map,
            mappings: corr.mappings.clone(),
            confidence: corr.confidence,
        }
    }

    /// Get the name of the correlator that produced this correlation.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Look up the destination address for a given source address.
    pub fn get_destination(&self, source: Address) -> Option<Address> {
        self.forward_map.get(&source).copied()
    }

    /// Look up the source address for a given destination address.
    pub fn get_source(&self, destination: Address) -> Option<Address> {
        self.reverse_map.get(&destination).copied()
    }

    /// Get the number of mappings in this correlation.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Whether this correlation has any mappings.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// Whether this correlation has a mapping for the given source address.
    pub fn contains_source(&self, source: Address) -> bool {
        self.forward_map.contains_key(&source)
    }

    /// Whether this correlation has a mapping for the given destination address.
    pub fn contains_destination(&self, destination: Address) -> bool {
        self.reverse_map.contains_key(&destination)
    }

    /// Get all source addresses in this correlation.
    pub fn source_addresses(&self) -> Vec<Address> {
        self.forward_map.keys().copied().collect()
    }

    /// Get all destination addresses in this correlation.
    pub fn destination_addresses(&self) -> Vec<Address> {
        self.reverse_map.keys().copied().collect()
    }
}

impl fmt::Display for CachedAddressCorrelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CachedAddressCorrelation[name={}, mappings={}, confidence={:.3}]",
            self.name,
            self.mappings.len(),
            self.confidence,
        )
    }
}

// ---------------------------------------------------------------------------
// VtAddressCorrelator
// ---------------------------------------------------------------------------

/// A program-level address correlator that combines multiple low-level
/// address correlators to produce mappings for a pair of programs.
pub struct VtAddressCorrelator {
    correlators: Vec<Box<dyn AddressCorrelator>>,
    options: VtOptions,
    /// Cached correlations keyed by (source_entry, dest_entry).
    cache: HashMap<(Address, Address), CachedAddressCorrelation>,
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
            cache: HashMap::new(),
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
            cache: HashMap::new(),
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

    /// Get the names of all registered correlators.
    pub fn correlator_names(&self) -> Vec<&str> {
        self.correlators.iter().map(|c| c.name()).collect()
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

    /// Correlate function addresses with caching.
    ///
    /// If a cached correlation exists for the given entry point pair, returns
    /// it immediately. Otherwise, performs the correlation and caches the result.
    pub fn correlate_function_addresses_cached(
        &mut self,
        source_entry: Address,
        source_bytes: &[u8],
        source_mnemonics: &[String],
        dest_entry: Address,
        dest_bytes: &[u8],
        dest_mnemonics: &[String],
    ) -> Option<CachedAddressCorrelation> {
        let key = (source_entry, dest_entry);
        if let Some(cached) = self.cache.get(&key) {
            return Some(cached.clone());
        }
        let corr = self.correlate_function_addresses(
            source_entry,
            source_bytes,
            source_mnemonics,
            dest_entry,
            dest_bytes,
            dest_mnemonics,
        )?;
        let name = self.correlators.iter()
            .find(|c| c.correlate_functions(source_entry, source_bytes, source_mnemonics,
                dest_entry, dest_bytes, dest_mnemonics).is_some())
            .map(|c| c.name().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let cached = CachedAddressCorrelation::from_correlation(&corr, name);
        self.cache.insert(key, cached.clone());
        Some(cached)
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

    /// Build a cached aggregate mapping from a set of function-level correlations.
    ///
    /// Like `build_aggregate_mapping` but uses the internal cache for
    /// repeated lookups.
    pub fn build_aggregate_mapping_cached(
        &mut self,
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

            if let Some(corr) = self.correlate_function_addresses_cached(
                src_entry, &src_bytes, &src_mnems, dst_entry, &dst_bytes, &dst_mnems,
            ) {
                for mapping in &corr.mappings {
                    aggregate.insert(mapping.source, mapping.destination);
                }
            }
        }

        aggregate
    }

    /// Clear the internal correlation cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get the number of cached correlations.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
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

impl fmt::Debug for VtAddressCorrelator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VtAddressCorrelator")
            .field("correlator_count", &self.correlators.len())
            .field("cache_size", &self.cache.len())
            .finish()
    }
}

impl fmt::Display for VtAddressCorrelator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VtAddressCorrelator[correlators={}, cached={}]",
            self.correlators.len(),
            self.cache.len(),
        )
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
    fn test_correlator_names() {
        let corr = VtAddressCorrelator::new();
        let names = corr.correlator_names();
        assert!(names.contains(&"ExactMatchAddressCorrelator"));
        assert!(names.contains(&"StraightLineCorrelation"));
        assert!(names.contains(&"LinearAddressCorrelator"));
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
    fn test_display_format() {
        let corr = VtAddressCorrelator::new();
        let display = format!("{}", corr);
        assert!(display.contains("VtAddressCorrelator"));
        assert!(display.contains("correlators=3"));
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

    #[test]
    fn test_cached_correlation() {
        let bytes = &[0x55u8, 0x48, 0x89, 0xe5, 0xc3];
        let corr = AddressCorrelation {
            source_entry: addr(0x1000),
            destination_entry: addr(0x2000),
            mappings: vec![
                AddressMapping { source: addr(0x1000), destination: addr(0x2000) },
                AddressMapping { source: addr(0x1001), destination: addr(0x2001) },
            ],
            confidence: 1.0,
        };
        let cached = CachedAddressCorrelation::from_correlation(&corr, "TestCorrelator");
        assert_eq!(cached.name(), "TestCorrelator");
        assert_eq!(cached.len(), 2);
        assert!(!cached.is_empty());
        assert_eq!(cached.get_destination(addr(0x1000)), Some(addr(0x2000)));
        assert_eq!(cached.get_destination(addr(0x1001)), Some(addr(0x2001)));
        assert_eq!(cached.get_source(addr(0x2000)), Some(addr(0x1000)));
        assert_eq!(cached.get_destination(addr(0x9999)), None);
        assert!(cached.contains_source(addr(0x1000)));
        assert!(!cached.contains_source(addr(0x9999)));
        assert!(cached.contains_destination(addr(0x2000)));
    }

    #[test]
    fn test_cached_correlation_display() {
        let corr = AddressCorrelation {
            source_entry: addr(0x1000),
            destination_entry: addr(0x2000),
            mappings: vec![],
            confidence: 0.5,
        };
        let cached = CachedAddressCorrelation::from_correlation(&corr, "Test");
        let display = format!("{}", cached);
        assert!(display.contains("Test"));
        assert!(display.contains("0"));
    }

    #[test]
    fn test_cache_operations() {
        let mut corr = VtAddressCorrelator::new();
        assert_eq!(corr.cache_size(), 0);
        corr.clear_cache();
        assert_eq!(corr.cache_size(), 0);
    }

    #[test]
    fn test_priority_constants() {
        assert!(EARLY_PRIORITY < DEFAULT_PRIORITY);
        assert!(DEFAULT_PRIORITY < LATE_CHANCE_PRIORITY);
        assert_eq!(PRIORITY_OFFSET, 10);
    }

    #[test]
    fn test_cached_address_correlation_source_dest_addresses() {
        let corr = AddressCorrelation {
            source_entry: addr(0x1000),
            destination_entry: addr(0x2000),
            mappings: vec![
                AddressMapping { source: addr(0x1000), destination: addr(0x2000) },
                AddressMapping { source: addr(0x1004), destination: addr(0x2008) },
            ],
            confidence: 0.9,
        };
        let cached = CachedAddressCorrelation::from_correlation(&corr, "test");
        let src_addrs = cached.source_addresses();
        assert_eq!(src_addrs.len(), 2);
        assert!(src_addrs.contains(&addr(0x1000)));
        assert!(src_addrs.contains(&addr(0x1004)));
        let dst_addrs = cached.destination_addresses();
        assert_eq!(dst_addrs.len(), 2);
        assert!(dst_addrs.contains(&addr(0x2000)));
        assert!(dst_addrs.contains(&addr(0x2008)));
    }
}
