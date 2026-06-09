//! Top-level address correlation utilities.
//!
//! Ported from Ghidra's `AddressCorrelation` Java interface and related
//! classes in `ghidra.features.codecompare.correlator`.
//!
//! This module provides a unified view of address correlation strategies
//! used in code comparison. It re-exports key types from the `correlator`
//! submodule and adds utility types for composing and querying correlations
//! across multiple strategies.
//!
//! # Key types
//!
//! - [`CorrelationStrategy`] -- enumeration of correlation strategy kinds
//! - [`CorrelatedAddress`] -- a single correlated address mapping
//! - [`AddressCorrelationResult`] -- the result of a correlation query
//! - [`CompositeCorrelator`] -- a correlator that tries multiple strategies in order

use super::correlator::address_correlation::{CodeCompareAddressCorrelation, CorrelatedRange};
use super::correlator::address_correlator::{CodeCompareAddressCorrelator, CorrelatorOptions, CorrelatorPriority};
use super::correlator::{AddressCorrelator, CodeCompareCorrelation, CorrelationKind, CorrelationRange as BasicCorrelationRange, OffsetCorrelator};

use std::sync::Arc;

/// Enumeration of correlation strategy kinds.
///
/// Each strategy has different strengths and is applicable in different
/// situations. The composite correlator tries them in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorrelationStrategy {
    /// Direct offset correlation (same binary, different base address).
    Offset,
    /// CodeCompare algorithm (cross-architecture, token matching).
    CodeCompare,
    /// LCS block matching.
    Lcs,
    /// Parameter matching.
    Parameters,
    /// Block structure matching.
    BlockStructure,
}

impl CorrelationStrategy {
    /// A human-readable label for this strategy.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Offset => "Offset",
            Self::CodeCompare => "CodeCompare",
            Self::Lcs => "LCS",
            Self::Parameters => "Parameters",
            Self::BlockStructure => "Block Structure",
        }
    }

    /// Whether this strategy supports cross-architecture comparison.
    pub fn supports_cross_arch(&self) -> bool {
        match self {
            Self::Offset => false,
            Self::CodeCompare => true,
            Self::Lcs => true,
            Self::Parameters => true,
            Self::BlockStructure => true,
        }
    }

    /// The priority of this strategy (lower values are tried first).
    pub fn priority(&self) -> u32 {
        match self {
            Self::Offset => 0,
            Self::CodeCompare => 100,
            Self::Parameters => 200,
            Self::Lcs => 300,
            Self::BlockStructure => 400,
        }
    }
}

/// A single correlated address mapping.
///
/// Represents the result of correlating one source address to one or
/// more destination addresses.
#[derive(Debug, Clone)]
pub struct CorrelatedAddress {
    /// The source address.
    pub source: u64,
    /// The correlated destination address (start of range).
    pub dest: u64,
    /// The end of the destination range (inclusive, for multi-address correlations).
    pub dest_end: u64,
    /// The kind of correlation.
    pub kind: CorrelationKind,
    /// The name of the correlator that produced this result.
    pub correlator_name: String,
}

impl CorrelatedAddress {
    /// Create a single-address correlation.
    pub fn single(source: u64, dest: u64, kind: CorrelationKind, name: impl Into<String>) -> Self {
        Self {
            source,
            dest,
            dest_end: dest,
            kind,
            correlator_name: name.into(),
        }
    }

    /// Create a range correlation.
    pub fn range(
        source: u64,
        dest_start: u64,
        dest_end: u64,
        kind: CorrelationKind,
        name: impl Into<String>,
    ) -> Self {
        Self {
            source,
            dest: dest_start,
            dest_end,
            kind,
            correlator_name: name.into(),
        }
    }

    /// The size of the destination range.
    pub fn dest_size(&self) -> u64 {
        self.dest_end - self.dest + 1
    }

    /// Whether the destination is a single address.
    pub fn is_single(&self) -> bool {
        self.dest == self.dest_end
    }

    /// Check if the destination range contains an address.
    pub fn dest_contains(&self, address: u64) -> bool {
        address >= self.dest && address <= self.dest_end
    }
}

/// The result of an address correlation query.
#[derive(Debug, Clone)]
pub enum AddressCorrelationResult {
    /// The source address was correlated to a destination address/range.
    Correlated(CorrelatedAddress),
    /// No correlation exists for the source address.
    NoCorrelation,
    /// The source address was outside the function body.
    OutOfRange,
}

impl AddressCorrelationResult {
    /// Check if the result is a successful correlation.
    pub fn is_correlated(&self) -> bool {
        matches!(self, Self::Correlated(_))
    }

    /// Get the correlated address, if any.
    pub fn correlated(&self) -> Option<&CorrelatedAddress> {
        match self {
            Self::Correlated(addr) => Some(addr),
            _ => None,
        }
    }

    /// Get the destination address, if correlated.
    pub fn dest_address(&self) -> Option<u64> {
        self.correlated().map(|c| c.dest)
    }
}

/// A composite correlator that tries multiple strategies in priority order.
///
/// When asked to correlate an address, it tries each strategy until one
/// produces a result. Strategies are tried in order of their priority
/// (lower priority values first).
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::address_correlation::*;
/// use ghidra_features::codecompare::correlator::*;
///
/// let mut composite = CompositeCorrelator::new("main", "main_recompiled");
///
/// // Add an offset correlator
/// composite.add_offset_correlator(0x1000);
///
/// // Try correlating an address
/// let result = composite.correlate(0x2000);
/// assert!(result.is_correlated());
/// assert_eq!(result.dest_address(), Some(0x3000));
/// ```
pub struct CompositeCorrelator {
    /// Name of the source function.
    source_name: String,
    /// Name of the destination function.
    dest_name: String,
    /// Offset correlators (simple offset-based mapping).
    offset_correlators: Vec<OffsetCorrelator>,
    /// CodeCompare correlation data (pre-computed).
    code_compare: Option<CodeCompareCorrelation>,
}

impl CompositeCorrelator {
    /// Create a new composite correlator.
    pub fn new(
        source_name: impl Into<String>,
        dest_name: impl Into<String>,
    ) -> Self {
        Self {
            source_name: source_name.into(),
            dest_name: dest_name.into(),
            offset_correlators: Vec::new(),
            code_compare: None,
        }
    }

    /// Add an offset correlator.
    pub fn add_offset_correlator(&mut self, offset: i64) {
        self.offset_correlators.push(OffsetCorrelator::new(offset));
    }

    /// Set the CodeCompare correlation data.
    pub fn set_code_compare(&mut self, correlation: CodeCompareCorrelation) {
        self.code_compare = Some(correlation);
    }

    /// Correlate a source address.
    ///
    /// Tries each strategy in priority order until one succeeds.
    pub fn correlate(&self, source_address: u64) -> AddressCorrelationResult {
        // Try CodeCompare first (highest priority for cross-arch)
        if let Some(ref cc) = self.code_compare {
            if let Some(range) = cc.get_correlated_range(source_address) {
                return AddressCorrelationResult::Correlated(CorrelatedAddress::range(
                    source_address,
                    range.dest_start,
                    range.dest_end,
                    range.kind,
                    &range.correlator_name,
                ));
            }
        }

        // Try offset correlators
        for offset_corr in &self.offset_correlators {
            if let Some(range) = offset_corr.get_correlated_range(source_address) {
                return AddressCorrelationResult::Correlated(CorrelatedAddress::single(
                    source_address,
                    range.dest_start,
                    range.kind,
                    &range.correlator_name,
                ));
            }
        }

        AddressCorrelationResult::NoCorrelation
    }

    /// Get the source function name.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    /// Get the destination function name.
    pub fn dest_name(&self) -> &str {
        &self.dest_name
    }

    /// Check if any correlators are registered.
    pub fn has_correlators(&self) -> bool {
        !self.offset_correlators.is_empty() || self.code_compare.is_some()
    }

    /// Get the number of registered strategies.
    pub fn strategy_count(&self) -> usize {
        let mut count = self.offset_correlators.len();
        if self.code_compare.is_some() {
            count += 1;
        }
        count
    }
}

impl std::fmt::Debug for CompositeCorrelator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeCorrelator")
            .field("source", &self.source_name)
            .field("dest", &self.dest_name)
            .field("strategy_count", &self.strategy_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CorrelationStrategy tests ---

    #[test]
    fn test_strategy_label() {
        assert_eq!(CorrelationStrategy::Offset.label(), "Offset");
        assert_eq!(CorrelationStrategy::CodeCompare.label(), "CodeCompare");
        assert_eq!(CorrelationStrategy::Lcs.label(), "LCS");
    }

    #[test]
    fn test_strategy_cross_arch() {
        assert!(!CorrelationStrategy::Offset.supports_cross_arch());
        assert!(CorrelationStrategy::CodeCompare.supports_cross_arch());
        assert!(CorrelationStrategy::Lcs.supports_cross_arch());
    }

    #[test]
    fn test_strategy_priority() {
        assert!(CorrelationStrategy::Offset.priority() < CorrelationStrategy::CodeCompare.priority());
        assert!(CorrelationStrategy::CodeCompare.priority() < CorrelationStrategy::Lcs.priority());
    }

    // --- CorrelatedAddress tests ---

    #[test]
    fn test_correlated_address_single() {
        let addr = CorrelatedAddress::single(
            0x1000,
            0x2000,
            CorrelationKind::CodeCompare,
            "test",
        );
        assert_eq!(addr.source, 0x1000);
        assert_eq!(addr.dest, 0x2000);
        assert_eq!(addr.dest_end, 0x2000);
        assert!(addr.is_single());
        assert_eq!(addr.dest_size(), 1);
    }

    #[test]
    fn test_correlated_address_range() {
        let addr = CorrelatedAddress::range(
            0x1000,
            0x2000,
            0x2004,
            CorrelationKind::Lcs,
            "test",
        );
        assert_eq!(addr.source, 0x1000);
        assert_eq!(addr.dest, 0x2000);
        assert_eq!(addr.dest_end, 0x2004);
        assert!(!addr.is_single());
        assert_eq!(addr.dest_size(), 5);
    }

    #[test]
    fn test_correlated_address_dest_contains() {
        let addr = CorrelatedAddress::range(
            0x1000,
            0x2000,
            0x2004,
            CorrelationKind::CodeCompare,
            "test",
        );
        assert!(addr.dest_contains(0x2000));
        assert!(addr.dest_contains(0x2002));
        assert!(addr.dest_contains(0x2004));
        assert!(!addr.dest_contains(0x1FFF));
        assert!(!addr.dest_contains(0x2005));
    }

    // --- AddressCorrelationResult tests ---

    #[test]
    fn test_result_correlated() {
        let addr = CorrelatedAddress::single(0x1000, 0x2000, CorrelationKind::CodeCompare, "test");
        let result = AddressCorrelationResult::Correlated(addr);
        assert!(result.is_correlated());
        assert_eq!(result.dest_address(), Some(0x2000));
    }

    #[test]
    fn test_result_no_correlation() {
        let result = AddressCorrelationResult::NoCorrelation;
        assert!(!result.is_correlated());
        assert!(result.correlated().is_none());
        assert!(result.dest_address().is_none());
    }

    #[test]
    fn test_result_out_of_range() {
        let result = AddressCorrelationResult::OutOfRange;
        assert!(!result.is_correlated());
    }

    // --- CompositeCorrelator tests ---

    #[test]
    fn test_composite_new() {
        let composite = CompositeCorrelator::new("main", "init");
        assert_eq!(composite.source_name(), "main");
        assert_eq!(composite.dest_name(), "init");
        assert!(!composite.has_correlators());
        assert_eq!(composite.strategy_count(), 0);
    }

    #[test]
    fn test_composite_offset_only() {
        let mut composite = CompositeCorrelator::new("main", "main_v2");
        composite.add_offset_correlator(0x1000);

        assert!(composite.has_correlators());
        assert_eq!(composite.strategy_count(), 1);

        let result = composite.correlate(0x2000);
        assert!(result.is_correlated());
        assert_eq!(result.dest_address(), Some(0x3000));
    }

    #[test]
    fn test_composite_no_correlator() {
        let composite = CompositeCorrelator::new("main", "init");
        let result = composite.correlate(0x1000);
        assert!(!result.is_correlated());
    }

    #[test]
    fn test_composite_code_compare_priority() {
        let mut composite = CompositeCorrelator::new("main", "init");
        composite.add_offset_correlator(0x1000); // maps 0x2000 -> 0x3000

        let mut cc = CodeCompareCorrelation::new("main", "init");
        cc.add_correlation(
            0x2000,
            super::super::correlator::CorrelationRange::new(
                CorrelationKind::CodeCompare,
                0x4000,
                0x4004,
                "CodeCompare",
            ),
        );
        composite.set_code_compare(cc);

        assert_eq!(composite.strategy_count(), 2);

        // CodeCompare should take priority over offset
        let result = composite.correlate(0x2000);
        assert!(result.is_correlated());
        assert_eq!(result.dest_address(), Some(0x4000));
    }

    #[test]
    fn test_composite_fallback_to_offset() {
        let mut composite = CompositeCorrelator::new("main", "init");
        composite.add_offset_correlator(0x1000);

        let cc = CodeCompareCorrelation::new("main", "init");
        // Don't add any correlations to CodeCompare
        composite.set_code_compare(cc);

        // Should fall back to offset correlator
        let result = composite.correlate(0x2000);
        assert!(result.is_correlated());
        assert_eq!(result.dest_address(), Some(0x3000));
    }

    #[test]
    fn test_composite_debug() {
        let composite = CompositeCorrelator::new("main", "init");
        let debug_str = format!("{:?}", composite);
        assert!(debug_str.contains("main"));
        assert!(debug_str.contains("init"));
    }
}
