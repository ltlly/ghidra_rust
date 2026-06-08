//! Cross-architecture address correlation.
//!
//! Ported from Ghidra's `ghidra.features.codecompare.correlator` Java package.
//!
//! When comparing functions from two different programs (potentially with
//! different architectures), the correlator maps addresses in the source
//! function to addresses in the destination function. This is used to
//! synchronize the two sides of a code comparison view.
//!
//! # Submodules
//!
//! - [`debug_utils`] -- debugging and visualization utilities
//!
//! # Key types
//!
//! - [`AddressCorrelator`] -- trait for address mapping implementations
//! - [`CodeCompareCorrelator`] -- the main cross-arch correlator
//! - [`CorrelationKind`] -- classification of how a correlation was determined

pub mod address_correlation;
pub mod address_correlator;
pub mod debug_utils;

use std::collections::BTreeMap;

/// The kind of correlation used to map an address pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorrelationKind {
    /// Correlation established by the Pinning algorithm (token matching).
    CodeCompare,
    /// Correlation established by longest-common-subsequence block matching.
    Lcs,
    /// Correlation established by matching function parameters.
    Parameters,
    /// Correlation established by matching basic block structure.
    BlockStructure,
    /// Correlation established by matching instruction patterns.
    InstructionPattern,
}

impl CorrelationKind {
    /// A human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::CodeCompare => "Code Compare",
            Self::Lcs => "LCS",
            Self::Parameters => "Parameters",
            Self::BlockStructure => "Block Structure",
            Self::InstructionPattern => "Instruction Pattern",
        }
    }
}

/// A correlated range mapping a source address to a destination range.
#[derive(Debug, Clone)]
pub struct CorrelationRange {
    /// The kind of correlation.
    pub kind: CorrelationKind,
    /// The destination range (start, end inclusive).
    pub dest_start: u64,
    /// The end address of the destination range (inclusive).
    pub dest_end: u64,
    /// The name of the correlator that produced this result.
    pub correlator_name: String,
}

impl CorrelationRange {
    /// Create a new correlation range.
    pub fn new(
        kind: CorrelationKind,
        dest_start: u64,
        dest_end: u64,
        correlator_name: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            dest_start,
            dest_end,
            correlator_name: correlator_name.into(),
        }
    }

    /// The size of the destination range.
    pub fn size(&self) -> u64 {
        self.dest_end - self.dest_start + 1
    }

    /// Check if the range contains a given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.dest_start && address <= self.dest_end
    }
}

/// Trait for address correlation implementations.
///
/// An address correlator maps addresses from a source function to
/// corresponding addresses in a destination function.
pub trait AddressCorrelator: Send + Sync {
    /// Get the correlated destination range for a source address.
    ///
    /// Returns `None` if no correlation exists for the given address.
    fn get_correlated_range(
        &self,
        source_address: u64,
    ) -> Option<CorrelationRange>;

    /// The name of this correlator.
    fn name(&self) -> &str;

    /// Whether this correlator is applicable for the given pair of
    /// architectures.
    ///
    /// Some correlators only work when the source and destination have
    /// the same architecture, while others (like CodeCompare) are
    /// designed for cross-architecture comparison.
    fn is_applicable(&self, source_arch: &str, dest_arch: &str) -> bool;
}

/// A simple linear offset correlator.
///
/// Maps addresses by adding a fixed offset. Useful when comparing
/// two versions of the same binary loaded at different base addresses.
#[derive(Debug, Clone)]
pub struct OffsetCorrelator {
    offset: i64,
}

impl OffsetCorrelator {
    /// Create a new offset correlator.
    pub fn new(offset: i64) -> Self {
        Self { offset }
    }
}

impl AddressCorrelator for OffsetCorrelator {
    fn get_correlated_range(&self, source_address: u64) -> Option<CorrelationRange> {
        let dest = (source_address as i64 + self.offset) as u64;
        Some(CorrelationRange::new(
            CorrelationKind::BlockStructure,
            dest,
            dest,
            "OffsetCorrelator",
        ))
    }

    fn name(&self) -> &str {
        "OffsetCorrelator"
    }

    fn is_applicable(&self, _source_arch: &str, _dest_arch: &str) -> bool {
        true
    }
}

/// A correlation table that maps source addresses to destination addresses.
///
/// This is the data structure produced by the code comparison analysis.
/// It stores all the correlations found between two functions.
#[derive(Debug, Clone)]
pub struct CodeCompareCorrelation {
    /// Name of the source function.
    pub source_name: String,
    /// Name of the destination function.
    pub dest_name: String,
    /// Maps source address -> correlation info.
    forward_map: BTreeMap<u64, CorrelationRange>,
    /// Maps destination address -> source address (reverse lookup).
    reverse_map: BTreeMap<u64, u64>,
}

impl CodeCompareCorrelation {
    /// Create a new empty correlation.
    pub fn new(
        source_name: impl Into<String>,
        dest_name: impl Into<String>,
    ) -> Self {
        Self {
            source_name: source_name.into(),
            dest_name: dest_name.into(),
            forward_map: BTreeMap::new(),
            reverse_map: BTreeMap::new(),
        }
    }

    /// Add a correlation entry.
    pub fn add_correlation(
        &mut self,
        source_address: u64,
        dest_range: CorrelationRange,
    ) {
        self.reverse_map.insert(dest_range.dest_start, source_address);
        self.forward_map.insert(source_address, dest_range);
    }

    /// Get the correlated destination range for a source address.
    pub fn get_correlated_range(&self, source_address: u64) -> Option<&CorrelationRange> {
        self.forward_map.get(&source_address)
    }

    /// Get the source address for a destination address.
    pub fn get_source_address(&self, dest_address: u64) -> Option<u64> {
        self.reverse_map.get(&dest_address).copied()
    }

    /// Number of correlations.
    pub fn correlation_count(&self) -> usize {
        self.forward_map.len()
    }

    /// All source addresses that have correlations.
    pub fn source_addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.forward_map.keys().copied()
    }

    /// Get all correlations as a vector.
    pub fn all_correlations(&self) -> Vec<(u64, &CorrelationRange)> {
        self.forward_map
            .iter()
            .map(|(&addr, range)| (addr, range))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offset_correlator() {
        let correlator = OffsetCorrelator::new(0x1000);
        let range = correlator.get_correlated_range(0x2000).unwrap();
        assert_eq!(range.dest_start, 0x3000);
        assert_eq!(range.dest_end, 0x3000);
    }

    #[test]
    fn test_offset_correlator_negative() {
        let correlator = OffsetCorrelator::new(-0x1000);
        let range = correlator.get_correlated_range(0x3000).unwrap();
        assert_eq!(range.dest_start, 0x2000);
    }

    #[test]
    fn test_correlation_range_contains() {
        let range = CorrelationRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2010, "test");
        assert!(range.contains(0x2000));
        assert!(range.contains(0x2008));
        assert!(range.contains(0x2010));
        assert!(!range.contains(0x2011));
        assert!(!range.contains(0x1FFF));
        assert_eq!(range.size(), 0x11);
    }

    #[test]
    fn test_code_compare_correlation() {
        let mut corr = CodeCompareCorrelation::new("main", "main_recompiled");
        corr.add_correlation(
            0x1000,
            CorrelationRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2004, "CodeCompare"),
        );
        corr.add_correlation(
            0x1010,
            CorrelationRange::new(CorrelationKind::Lcs, 0x2010, 0x2010, "CodeCompare"),
        );

        assert_eq!(corr.correlation_count(), 2);
        assert!(corr.get_correlated_range(0x1000).is_some());
        assert!(corr.get_correlated_range(0x1005).is_none());
        assert_eq!(corr.get_source_address(0x2000), Some(0x1000));
        assert_eq!(corr.get_source_address(0x2010), Some(0x1010));
    }

    #[test]
    fn test_correlation_kind_label() {
        assert_eq!(CorrelationKind::CodeCompare.label(), "Code Compare");
        assert_eq!(CorrelationKind::Lcs.label(), "LCS");
        assert_eq!(CorrelationKind::Parameters.label(), "Parameters");
    }

    #[test]
    fn test_code_compare_correlation_source_addresses() {
        let mut corr = CodeCompareCorrelation::new("f1", "f2");
        corr.add_correlation(
            0x1000,
            CorrelationRange::new(CorrelationKind::CodeCompare, 0x2000, 0x2000, "test"),
        );
        corr.add_correlation(
            0x1020,
            CorrelationRange::new(CorrelationKind::CodeCompare, 0x2020, 0x2020, "test"),
        );

        let addrs: Vec<u64> = corr.source_addresses().collect();
        assert_eq!(addrs, vec![0x1000, 0x1020]);
    }

    #[test]
    fn test_offset_correlator_is_applicable() {
        let c = OffsetCorrelator::new(0);
        assert!(c.is_applicable("x86", "ARM"));
    }

    #[test]
    fn test_all_correlations_sorted() {
        let mut corr = CodeCompareCorrelation::new("f1", "f2");
        for addr in [0x3000, 0x1000, 0x2000] {
            corr.add_correlation(
                addr,
                CorrelationRange::new(CorrelationKind::CodeCompare, addr + 0x100, addr + 0x100, "test"),
            );
        }
        let all = corr.all_correlations();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0, 0x1000);
        assert_eq!(all[1].0, 0x2000);
        assert_eq!(all[2].0, 0x3000);
    }
}
