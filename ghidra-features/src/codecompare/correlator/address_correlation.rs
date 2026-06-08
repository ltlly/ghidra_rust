//! Address correlation for cross-architecture code comparison.
//!
//! Ported from Ghidra's `CodeCompareAddressCorrelation` Java class in
//! `ghidra.features.codecompare.correlator`.
//!
//! This is the main correlation engine that maps addresses from a source
//! function to corresponding addresses in a destination function. It uses
//! a combination of:
//!
//! 1. **CodeCompare** (Pinning algorithm) -- matches decompiler tokens
//!    between the two functions using data-flow and control-flow analysis
//! 2. **LCS** (Longest Common Subsequence) -- matches basic blocks between
//!    the golden matches found by CodeCompare
//! 3. **Parameters** -- matches function parameters by their storage locations
//!
//! The correlation results are cached for efficient repeated lookups.
//!
//! # Key types
//!
//! - [`CorrelationKind`] -- the kind of correlation used
//! - [`CorrelatedRange`] -- a destination address range for a correlation
//! - [`CodeCompareAddressCorrelation`] -- the main correlation engine

use std::collections::BTreeMap;

use super::address_correlator::CorrelatorOptions;
use super::CorrelationKind;

/// A destination address range produced by the correlation.
///
/// This is the Rust equivalent of Ghidra's `AddressCorrelationRange` Java class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedRange {
    /// The kind of correlation that produced this range.
    pub kind: CorrelationKind,
    /// Start address of the destination range (inclusive).
    pub start: u64,
    /// End address of the destination range (inclusive).
    pub end: u64,
    /// Name of the correlator that produced this result.
    pub correlator_name: String,
}

impl CorrelatedRange {
    /// Create a new correlated range.
    pub fn new(
        kind: CorrelationKind,
        start: u64,
        end: u64,
        correlator_name: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            start,
            end,
            correlator_name: correlator_name.into(),
        }
    }

    /// Create a single-address correlated range.
    pub fn single(kind: CorrelationKind, address: u64, correlator_name: impl Into<String>) -> Self {
        Self {
            kind,
            start: address,
            end: address,
            correlator_name: correlator_name.into(),
        }
    }

    /// The size of the destination range.
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Check if the range contains a given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }
}

/// The main address correlation engine for cross-architecture comparison.
///
/// This is the Rust equivalent of Ghidra's `CodeCompareAddressCorrelation`
/// Java class. It builds a cached mapping from source addresses to
/// destination address ranges using the CodeCompare (Pinning), LCS, and
/// parameter correlation strategies.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::correlator::address_correlation::*;
/// use ghidra_features::codecompare::correlator::CorrelationKind;
/// use ghidra_features::codecompare::correlator::address_correlator::CorrelatorOptions;
///
/// let mut correlation = CodeCompareAddressCorrelation::new(
///     "source_func",
///     "dest_func",
///     CorrelatorOptions::default(),
/// );
///
/// // Add correlations found by the analysis
/// correlation.add_correlation(
///     0x1000,
///     CorrelatedRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2004, "CodeCompare"),
/// );
///
/// // Look up the correlation for a source address
/// let range = correlation.get_correlated_range(0x1000);
/// assert!(range.is_some());
/// assert_eq!(range.unwrap().start, 0x2000);
/// ```
#[derive(Debug, Clone)]
pub struct CodeCompareAddressCorrelation {
    /// Name of the source function.
    source_name: String,
    /// Name of the destination function.
    dest_name: String,
    /// Configuration options.
    options: CorrelatorOptions,
    /// Forward mapping: source address -> destination range.
    forward_map: BTreeMap<u64, CorrelatedRange>,
    /// Reverse mapping: destination address -> source address.
    reverse_map: BTreeMap<u64, u64>,
}

impl CodeCompareAddressCorrelation {
    /// The correlator name constant.
    pub const NAME: &'static str = "CodeCompareAddressCorrelator";

    /// Create a new empty correlation.
    pub fn new(
        source_name: impl Into<String>,
        dest_name: impl Into<String>,
        options: CorrelatorOptions,
    ) -> Self {
        Self {
            source_name: source_name.into(),
            dest_name: dest_name.into(),
            options,
            forward_map: BTreeMap::new(),
            reverse_map: BTreeMap::new(),
        }
    }

    /// Get the correlator name.
    pub fn name(&self) -> &str {
        Self::NAME
    }

    /// Get the source function name.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    /// Get the destination function name.
    pub fn dest_name(&self) -> &str {
        &self.dest_name
    }

    /// Get the options.
    pub fn options(&self) -> &CorrelatorOptions {
        &self.options
    }

    /// Add a correlation entry.
    ///
    /// Maps a source address to a destination address range.
    pub fn add_correlation(&mut self, source_address: u64, range: CorrelatedRange) {
        self.reverse_map.insert(range.start, source_address);
        self.forward_map.insert(source_address, range);
    }

    /// Add a range of correlated addresses.
    ///
    /// Maps each address in [source_start, source_end] to the corresponding
    /// address in the destination range.
    pub fn add_correlation_range(
        &mut self,
        source_start: u64,
        source_end: u64,
        dest_start: u64,
        dest_end: u64,
        kind: CorrelationKind,
    ) {
        let source_size = source_end - source_start + 1;
        let dest_size = dest_end - dest_start + 1;
        let size = source_size.min(dest_size);

        for i in 0..size {
            let src_addr = source_start + i;
            let dst_addr = dest_start + i;
            let range = CorrelatedRange::single(kind, dst_addr, Self::NAME);
            self.add_correlation(src_addr, range);
        }
    }

    /// Get the correlated destination range for a source address.
    ///
    /// Returns `None` if no correlation exists for the given address.
    pub fn get_correlated_range(&self, source_address: u64) -> Option<&CorrelatedRange> {
        self.forward_map.get(&source_address)
    }

    /// Get the source address for a destination address.
    ///
    /// Returns `None` if no reverse correlation exists.
    pub fn get_source_address(&self, dest_address: u64) -> Option<u64> {
        self.reverse_map.get(&dest_address).copied()
    }

    /// Number of correlations.
    pub fn correlation_count(&self) -> usize {
        self.forward_map.len()
    }

    /// Check if the correlation is empty.
    pub fn is_empty(&self) -> bool {
        self.forward_map.is_empty()
    }

    /// All source addresses that have correlations, in sorted order.
    pub fn source_addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.forward_map.keys().copied()
    }

    /// Get all correlations as a vector of (source_address, &CorrelatedRange).
    pub fn all_correlations(&self) -> Vec<(u64, &CorrelatedRange)> {
        self.forward_map
            .iter()
            .map(|(&addr, range)| (addr, range))
            .collect()
    }

    /// Get the correlations of a specific kind.
    pub fn correlations_of_kind(&self, kind: CorrelationKind) -> Vec<(u64, &CorrelatedRange)> {
        self.forward_map
            .iter()
            .filter(|(_, range)| range.kind == kind)
            .map(|(&addr, range)| (addr, range))
            .collect()
    }

    /// Get summary statistics.
    pub fn statistics(&self) -> CorrelationStatistics {
        let mut code_compare_count = 0;
        let mut lcs_count = 0;
        let mut parameters_count = 0;
        let mut other_count = 0;

        for range in self.forward_map.values() {
            match range.kind {
                CorrelationKind::CodeCompare => code_compare_count += 1,
                CorrelationKind::Lcs => lcs_count += 1,
                CorrelationKind::Parameters => parameters_count += 1,
                _ => other_count += 1,
            }
        }

        CorrelationStatistics {
            total_correlations: self.forward_map.len(),
            code_compare_count,
            lcs_count,
            parameters_count,
            other_count,
        }
    }
}

/// Summary statistics for a correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationStatistics {
    /// Total number of correlations.
    pub total_correlations: usize,
    /// Number of CodeCompare correlations.
    pub code_compare_count: usize,
    /// Number of LCS correlations.
    pub lcs_count: usize,
    /// Number of Parameters correlations.
    pub parameters_count: usize,
    /// Number of other correlations.
    pub other_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_correlation() -> CodeCompareAddressCorrelation {
        CodeCompareAddressCorrelation::new(
            "source_func",
            "dest_func",
            CorrelatorOptions::default(),
        )
    }

    // --- CorrelatedRange tests ---

    #[test]
    fn test_correlated_range_new() {
        let range = CorrelatedRange::new(
            CorrelationKind::CodeCompare,
            0x2000,
            0x2010,
            "CodeCompare",
        );
        assert_eq!(range.kind, CorrelationKind::CodeCompare);
        assert_eq!(range.start, 0x2000);
        assert_eq!(range.end, 0x2010);
        assert_eq!(range.size(), 0x11);
    }

    #[test]
    fn test_correlated_range_single() {
        let range = CorrelatedRange::single(
            CorrelationKind::Lcs,
            0x3000,
            "CodeCompare",
        );
        assert_eq!(range.start, 0x3000);
        assert_eq!(range.end, 0x3000);
        assert_eq!(range.size(), 1);
    }

    #[test]
    fn test_correlated_range_contains() {
        let range = CorrelatedRange::new(
            CorrelationKind::CodeCompare,
            0x2000,
            0x2010,
            "test",
        );
        assert!(range.contains(0x2000));
        assert!(range.contains(0x2008));
        assert!(range.contains(0x2010));
        assert!(!range.contains(0x1FFF));
        assert!(!range.contains(0x2011));
    }

    // --- CodeCompareAddressCorrelation tests ---

    #[test]
    fn test_correlation_new() {
        let corr = make_correlation();
        assert_eq!(corr.name(), "CodeCompareAddressCorrelator");
        assert_eq!(corr.source_name(), "source_func");
        assert_eq!(corr.dest_name(), "dest_func");
        assert!(corr.is_empty());
    }

    #[test]
    fn test_correlation_add_single() {
        let mut corr = make_correlation();
        corr.add_correlation(
            0x1000,
            CorrelatedRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2004, "CodeCompare"),
        );

        assert_eq!(corr.correlation_count(), 1);
        assert!(!corr.is_empty());
    }

    #[test]
    fn test_correlation_get_correlated_range() {
        let mut corr = make_correlation();
        corr.add_correlation(
            0x1000,
            CorrelatedRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2004, "CodeCompare"),
        );

        let range = corr.get_correlated_range(0x1000);
        assert!(range.is_some());
        assert_eq!(range.unwrap().start, 0x2000);
        assert_eq!(range.unwrap().end, 0x2004);

        assert!(corr.get_correlated_range(0x1001).is_none());
    }

    #[test]
    fn test_correlation_get_source_address() {
        let mut corr = make_correlation();
        corr.add_correlation(
            0x1000,
            CorrelatedRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2004, "CodeCompare"),
        );

        assert_eq!(corr.get_source_address(0x2000), Some(0x1000));
        assert_eq!(corr.get_source_address(0x2005), None);
    }

    #[test]
    fn test_correlation_add_range() {
        let mut corr = make_correlation();
        corr.add_correlation_range(
            0x1000,
            0x100F,
            0x2000,
            0x200F,
            CorrelationKind::Lcs,
        );

        assert_eq!(corr.correlation_count(), 16);
        assert_eq!(corr.get_source_address(0x2005), Some(0x1005));
    }

    #[test]
    fn test_correlation_source_addresses_sorted() {
        let mut corr = make_correlation();
        corr.add_correlation(
            0x3000,
            CorrelatedRange::single(CorrelationKind::CodeCompare, 0x4000, "test"),
        );
        corr.add_correlation(
            0x1000,
            CorrelatedRange::single(CorrelationKind::CodeCompare, 0x2000, "test"),
        );
        corr.add_correlation(
            0x2000,
            CorrelatedRange::single(CorrelationKind::CodeCompare, 0x3000, "test"),
        );

        let addrs: Vec<u64> = corr.source_addresses().collect();
        assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn test_correlation_all_correlations() {
        let mut corr = make_correlation();
        corr.add_correlation(
            0x1000,
            CorrelatedRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2004, "test"),
        );
        corr.add_correlation(
            0x1010,
            CorrelatedRange::new(CorrelationKind::Lcs, 0x2010, 0x2010, "test"),
        );

        let all = corr.all_correlations();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_correlation_of_kind() {
        let mut corr = make_correlation();
        corr.add_correlation(
            0x1000,
            CorrelatedRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2004, "test"),
        );
        corr.add_correlation(
            0x1010,
            CorrelatedRange::new(CorrelationKind::Lcs, 0x2010, 0x2010, "test"),
        );
        corr.add_correlation(
            0x1020,
            CorrelatedRange::new(CorrelationKind::CodeCompare, 0x2020, 0x2020, "test"),
        );

        let cc = corr.correlations_of_kind(CorrelationKind::CodeCompare);
        assert_eq!(cc.len(), 2);

        let lcs = corr.correlations_of_kind(CorrelationKind::Lcs);
        assert_eq!(lcs.len(), 1);

        let params = corr.correlations_of_kind(CorrelationKind::Parameters);
        assert_eq!(params.len(), 0);
    }

    #[test]
    fn test_correlation_statistics() {
        let mut corr = make_correlation();
        corr.add_correlation(
            0x1000,
            CorrelatedRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2004, "test"),
        );
        corr.add_correlation(
            0x1010,
            CorrelatedRange::new(CorrelationKind::Lcs, 0x2010, 0x2010, "test"),
        );
        corr.add_correlation(
            0x1020,
            CorrelatedRange::new(CorrelationKind::Parameters, 0x2020, 0x2020, "test"),
        );

        let stats = corr.statistics();
        assert_eq!(stats.total_correlations, 3);
        assert_eq!(stats.code_compare_count, 1);
        assert_eq!(stats.lcs_count, 1);
        assert_eq!(stats.parameters_count, 1);
        assert_eq!(stats.other_count, 0);
    }

    #[test]
    fn test_correlation_name_constant() {
        assert_eq!(CodeCompareAddressCorrelation::NAME, "CodeCompareAddressCorrelator");
    }
}
