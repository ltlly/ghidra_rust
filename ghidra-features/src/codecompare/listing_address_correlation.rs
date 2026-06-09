//! Listing-specific address correlation.
//!
//! Ported from Ghidra's `ListingAddressCorrelation` Java class and related
//! classes in `ghidra.features.base.codecompare.listing`.
//!
//! This module provides address correlation specifically for listing
//! (disassembly) comparisons. In listing comparisons, both sides typically
//! come from the same architecture (or at least have compatible address
//! spaces), so the correlation is simpler than the cross-architecture
//! correlation used by the decompiler view.
//!
//! The primary correlation strategy is linear offset correlation: addresses
//! are mapped by computing the offset from the start of one address set to
//! the start of the other. This works well for comparing two versions of the
//! same binary loaded at different base addresses.
//!
//! # Key types
//!
//! - [`ListingAddressCorrelator`] -- the main listing address correlator
//! - [`CorrelationMapping`] -- a mapping between two address ranges
//! - [`ListingCorrelationConfig`] -- configuration for listing correlation
//! - [`CorrelationQuality`] -- quality assessment of a correlation

use super::listing::{LinearAddressCorrelation, ListingSide};
use super::panel::AddressSet;

use std::collections::BTreeMap;

/// Configuration for listing address correlation.
#[derive(Debug, Clone)]
pub struct ListingCorrelationConfig {
    /// Whether to use linear offset correlation (simplest, fastest).
    pub use_linear_offset: bool,
    /// Whether to fall back to best-effort matching when addresses don't align.
    pub best_effort: bool,
    /// Maximum offset difference to consider when matching addresses.
    pub max_offset_delta: u64,
}

impl ListingCorrelationConfig {
    /// Create a configuration with default values.
    pub fn new() -> Self {
        Self {
            use_linear_offset: true,
            best_effort: true,
            max_offset_delta: 0x10000,
        }
    }

    /// Enable or disable linear offset correlation.
    pub fn with_linear_offset(mut self, enabled: bool) -> Self {
        self.use_linear_offset = enabled;
        self
    }

    /// Enable or disable best-effort matching.
    pub fn with_best_effort(mut self, enabled: bool) -> Self {
        self.best_effort = enabled;
        self
    }

    /// Set the maximum offset delta.
    pub fn with_max_offset_delta(mut self, delta: u64) -> Self {
        self.max_offset_delta = delta;
        self
    }
}

impl Default for ListingCorrelationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Quality assessment of an address correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CorrelationQuality {
    /// Exact 1:1 mapping (same addresses).
    Exact,
    /// Linear offset mapping (different base addresses, same relative offsets).
    LinearOffset,
    /// Best-effort mapping (approximate, may have mismatches).
    BestEffort,
    /// No correlation could be established.
    None,
}

impl CorrelationQuality {
    /// A human-readable label for this quality level.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Exact => "Exact",
            Self::LinearOffset => "Linear Offset",
            Self::BestEffort => "Best Effort",
            Self::None => "None",
        }
    }

    /// A numeric score (higher is better).
    pub fn score(&self) -> u32 {
        match self {
            Self::Exact => 100,
            Self::LinearOffset => 80,
            Self::BestEffort => 40,
            Self::None => 0,
        }
    }
}

/// A mapping between two address ranges.
///
/// Represents a discovered correlation between a contiguous range on
/// one side and a contiguous range on the other side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationMapping {
    /// Start address on the left side.
    pub left_start: u64,
    /// End address on the left side (inclusive).
    pub left_end: u64,
    /// Start address on the right side.
    pub right_start: u64,
    /// End address on the right side (inclusive).
    pub right_end: u64,
    /// The quality of this mapping.
    pub quality: CorrelationQuality,
}

impl CorrelationMapping {
    /// Create a new correlation mapping.
    pub fn new(
        left_start: u64,
        left_end: u64,
        right_start: u64,
        right_end: u64,
        quality: CorrelationQuality,
    ) -> Self {
        Self {
            left_start,
            left_end,
            right_start,
            right_end,
            quality,
        }
    }

    /// Create a 1:1 mapping (same size on both sides).
    pub fn one_to_one(
        left_start: u64,
        right_start: u64,
        count: u64,
        quality: CorrelationQuality,
    ) -> Self {
        Self {
            left_start,
            left_end: left_start + count - 1,
            right_start,
            right_end: right_start + count - 1,
            quality,
        }
    }

    /// The size of the left range.
    pub fn left_size(&self) -> u64 {
        self.left_end - self.left_start + 1
    }

    /// The size of the right range.
    pub fn right_size(&self) -> u64 {
        self.right_end - self.right_start + 1
    }

    /// Check if this is a 1:1 mapping (same size on both sides).
    pub fn is_one_to_one(&self) -> bool {
        self.left_size() == self.right_size()
    }

    /// Get the offset between left and right start addresses.
    pub fn offset(&self) -> i64 {
        self.right_start as i64 - self.left_start as i64
    }
}

/// The main listing address correlator.
///
/// Computes address correlations for listing comparisons. It builds a
/// set of correlation mappings between the left and right address sets
/// and provides efficient lookup in both directions.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing_address_correlation::*;
/// use ghidra_features::codecompare::panel::AddressSet;
///
/// let left = AddressSet::single(0x1000, 0x100f);
/// let right = AddressSet::single(0x2000, 0x200f);
///
/// let correlator = ListingAddressCorrelator::new(
///     left, right, ListingCorrelationConfig::default(),
/// );
///
/// assert_eq!(correlator.correlate_left(0x1000), Some(0x2000));
/// assert_eq!(correlator.correlate_left(0x1005), Some(0x2005));
/// assert_eq!(correlator.correlate_right(0x2000), Some(0x1000));
/// assert_eq!(correlator.quality(), CorrelationQuality::LinearOffset);
/// ```
pub struct ListingAddressCorrelator {
    /// Left address set.
    left_addresses: AddressSet,
    /// Right address set.
    right_addresses: AddressSet,
    /// Configuration.
    config: ListingCorrelationConfig,
    /// The underlying linear correlation engine.
    linear: Option<LinearAddressCorrelation>,
    /// Computed correlation mappings.
    mappings: Vec<CorrelationMapping>,
    /// The assessed quality of the correlation.
    quality: CorrelationQuality,
}

impl ListingAddressCorrelator {
    /// Create a new listing address correlator.
    pub fn new(
        left_addresses: AddressSet,
        right_addresses: AddressSet,
        config: ListingCorrelationConfig,
    ) -> Self {
        let (linear, mappings, quality) =
            Self::compute_correlation(&left_addresses, &right_addresses, &config);

        Self {
            left_addresses,
            right_addresses,
            config,
            linear,
            mappings,
            quality,
        }
    }

    /// Compute the correlation from the address sets.
    fn compute_correlation(
        left: &AddressSet,
        right: &AddressSet,
        config: &ListingCorrelationConfig,
    ) -> (Option<LinearAddressCorrelation>, Vec<CorrelationMapping>, CorrelationQuality) {
        if left.is_empty() || right.is_empty() {
            return (None, Vec::new(), CorrelationQuality::None);
        }

        let left_min = left.min_address().unwrap();
        let left_max = left.max_address().unwrap();
        let right_min = right.min_address().unwrap();
        let right_max = right.max_address().unwrap();

        // Check for exact match (same addresses)
        if left_min == right_min && left_max == right_max {
            let linear = LinearAddressCorrelation::new(left.clone(), right.clone());
            let mapping = CorrelationMapping::one_to_one(
                left_min,
                right_min,
                left_max - left_min + 1,
                CorrelationQuality::Exact,
            );
            return (Some(linear), vec![mapping], CorrelationQuality::Exact);
        }

        // Try linear offset
        if config.use_linear_offset {
            let linear = LinearAddressCorrelation::new(left.clone(), right.clone());
            let offset = right_min as i64 - left_min as i64;

            // Build mappings for each range pair
            let mut mappings = Vec::new();
            for left_range in left.ranges() {
                let mapped_start = (left_range.start as i64 + offset) as u64;
                let mapped_end = (left_range.end as i64 + offset) as u64;

                if right.contains(mapped_start) || right.contains(mapped_end) {
                    // Clip to actual right address range
                    let actual_start = mapped_start.max(right_min);
                    let actual_end = mapped_end.min(right_max);

                    if actual_start <= actual_end {
                        mappings.push(CorrelationMapping::new(
                            left_range.start,
                            left_range.end,
                            actual_start,
                            actual_end,
                            CorrelationQuality::LinearOffset,
                        ));
                    }
                }
            }

            if !mappings.is_empty() {
                return (Some(linear), mappings, CorrelationQuality::LinearOffset);
            }
        }

        // Best-effort: just map by position within the address sets
        if config.best_effort {
            let linear = LinearAddressCorrelation::new(left.clone(), right.clone());
            return (
                Some(linear),
                Vec::new(),
                CorrelationQuality::BestEffort,
            );
        }

        (None, Vec::new(), CorrelationQuality::None)
    }

    /// Correlate a left address to a right address.
    pub fn correlate_left(&self, left_address: u64) -> Option<u64> {
        self.linear
            .as_ref()
            .and_then(|l| l.get_correlated_address(ListingSide::Left, left_address))
    }

    /// Correlate a right address to a left address.
    pub fn correlate_right(&self, right_address: u64) -> Option<u64> {
        self.linear
            .as_ref()
            .and_then(|l| l.get_correlated_address(ListingSide::Right, right_address))
    }

    /// Correlate an address on the given side.
    pub fn correlate(&self, side: ListingSide, address: u64) -> Option<u64> {
        match side {
            ListingSide::Left => self.correlate_left(address),
            ListingSide::Right => self.correlate_right(address),
        }
    }

    /// Get the quality of the correlation.
    pub fn quality(&self) -> CorrelationQuality {
        self.quality
    }

    /// Get all computed correlation mappings.
    pub fn mappings(&self) -> &[CorrelationMapping] {
        &self.mappings
    }

    /// Get the number of correlation mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Get the left address set.
    pub fn left_addresses(&self) -> &AddressSet {
        &self.left_addresses
    }

    /// Get the right address set.
    pub fn right_addresses(&self) -> &AddressSet {
        &self.right_addresses
    }

    /// Get the configuration.
    pub fn config(&self) -> &ListingCorrelationConfig {
        &self.config
    }

    /// Get all correlated address pairs.
    pub fn all_pairs(&self) -> Vec<(u64, u64)> {
        self.linear
            .as_ref()
            .map(|l| l.get_all_correlations())
            .unwrap_or_default()
    }

    /// Get the number of correlated address pairs.
    pub fn pair_count(&self) -> usize {
        self.all_pairs().len()
    }

    /// Get the offset between left and right address sets.
    pub fn offset(&self) -> Option<i64> {
        let left_min = self.left_addresses.min_address()?;
        let right_min = self.right_addresses.min_address()?;
        Some(right_min as i64 - left_min as i64)
    }
}

impl std::fmt::Debug for ListingAddressCorrelator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListingAddressCorrelator")
            .field("quality", &self.quality)
            .field("mapping_count", &self.mappings.len())
            .field("offset", &self.offset())
            .finish()
    }
}

/// A correlator builder for constructing listing correlations incrementally.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing_address_correlation::*;
/// use ghidra_features::codecompare::panel::AddressSet;
///
/// let correlator = ListingCorrelatorBuilder::new()
///     .add_left_range(0x1000, 0x100f)
///     .add_right_range(0x2000, 0x200f)
///     .build();
///
/// assert_eq!(correlator.correlate_left(0x1000), Some(0x2000));
/// ```
pub struct ListingCorrelatorBuilder {
    left_ranges: Vec<(u64, u64)>,
    right_ranges: Vec<(u64, u64)>,
    config: ListingCorrelationConfig,
}

impl ListingCorrelatorBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            left_ranges: Vec::new(),
            right_ranges: Vec::new(),
            config: ListingCorrelationConfig::default(),
        }
    }

    /// Add a range to the left address set.
    pub fn add_left_range(mut self, start: u64, end: u64) -> Self {
        self.left_ranges.push((start, end));
        self
    }

    /// Add a range to the right address set.
    pub fn add_right_range(mut self, start: u64, end: u64) -> Self {
        self.right_ranges.push((start, end));
        self
    }

    /// Set the configuration.
    pub fn with_config(mut self, config: ListingCorrelationConfig) -> Self {
        self.config = config;
        self
    }

    /// Build the correlator.
    pub fn build(self) -> ListingAddressCorrelator {
        let mut left = AddressSet::new();
        for (start, end) in &self.left_ranges {
            left.add(*start, *end);
        }

        let mut right = AddressSet::new();
        for (start, end) in &self.right_ranges {
            right.add(*start, *end);
        }

        ListingAddressCorrelator::new(left, right, self.config)
    }
}

impl Default for ListingCorrelatorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ListingCorrelationConfig tests ---

    #[test]
    fn test_config_defaults() {
        let config = ListingCorrelationConfig::new();
        assert!(config.use_linear_offset);
        assert!(config.best_effort);
        assert_eq!(config.max_offset_delta, 0x10000);
    }

    #[test]
    fn test_config_builder() {
        let config = ListingCorrelationConfig::new()
            .with_linear_offset(false)
            .with_best_effort(false)
            .with_max_offset_delta(0x1000);
        assert!(!config.use_linear_offset);
        assert!(!config.best_effort);
        assert_eq!(config.max_offset_delta, 0x1000);
    }

    // --- CorrelationQuality tests ---

    #[test]
    fn test_quality_ordering() {
        // With derive(Ord), earlier variants are "less than" later ones.
        // But by score, Exact (100) > LinearOffset (80) > BestEffort (40) > None (0).
        assert!(CorrelationQuality::Exact.score() > CorrelationQuality::LinearOffset.score());
        assert!(CorrelationQuality::LinearOffset.score() > CorrelationQuality::BestEffort.score());
        assert!(CorrelationQuality::BestEffort.score() > CorrelationQuality::None.score());
    }

    #[test]
    fn test_quality_label() {
        assert_eq!(CorrelationQuality::Exact.label(), "Exact");
        assert_eq!(CorrelationQuality::LinearOffset.label(), "Linear Offset");
        assert_eq!(CorrelationQuality::None.label(), "None");
    }

    #[test]
    fn test_quality_score() {
        assert_eq!(CorrelationQuality::Exact.score(), 100);
        assert_eq!(CorrelationQuality::LinearOffset.score(), 80);
        assert_eq!(CorrelationQuality::BestEffort.score(), 40);
        assert_eq!(CorrelationQuality::None.score(), 0);
    }

    // --- CorrelationMapping tests ---

    #[test]
    fn test_mapping_new() {
        let mapping = CorrelationMapping::new(0x1000, 0x100f, 0x2000, 0x200f, CorrelationQuality::LinearOffset);
        assert_eq!(mapping.left_start, 0x1000);
        assert_eq!(mapping.left_end, 0x100f);
        assert_eq!(mapping.right_start, 0x2000);
        assert_eq!(mapping.right_end, 0x200f);
        assert!(mapping.is_one_to_one());
    }

    #[test]
    fn test_mapping_one_to_one() {
        let mapping = CorrelationMapping::one_to_one(0x1000, 0x2000, 16, CorrelationQuality::Exact);
        assert_eq!(mapping.left_size(), 16);
        assert_eq!(mapping.right_size(), 16);
        assert_eq!(mapping.offset(), 0x1000);
    }

    #[test]
    fn test_mapping_sizes() {
        let mapping = CorrelationMapping::new(0x1000, 0x100f, 0x2000, 0x2007, CorrelationQuality::BestEffort);
        assert_eq!(mapping.left_size(), 0x10);
        assert_eq!(mapping.right_size(), 0x08);
        assert!(!mapping.is_one_to_one());
    }

    // --- ListingAddressCorrelator tests ---

    #[test]
    fn test_correlator_exact_match() {
        let left = AddressSet::single(0x1000, 0x100f);
        let right = AddressSet::single(0x1000, 0x100f);
        let correlator = ListingAddressCorrelator::new(left, right, ListingCorrelationConfig::default());

        assert_eq!(correlator.quality(), CorrelationQuality::Exact);
        assert_eq!(correlator.correlate_left(0x1000), Some(0x1000));
        assert_eq!(correlator.correlate_right(0x1005), Some(0x1005));
    }

    #[test]
    fn test_correlator_linear_offset() {
        let left = AddressSet::single(0x1000, 0x100f);
        let right = AddressSet::single(0x2000, 0x200f);
        let correlator = ListingAddressCorrelator::new(left, right, ListingCorrelationConfig::default());

        assert_eq!(correlator.quality(), CorrelationQuality::LinearOffset);
        assert_eq!(correlator.correlate_left(0x1000), Some(0x2000));
        assert_eq!(correlator.correlate_left(0x1005), Some(0x2005));
        assert_eq!(correlator.correlate_left(0x100f), Some(0x200f));
        assert_eq!(correlator.correlate_left(0x5000), None); // out of range
    }

    #[test]
    fn test_correlator_reverse() {
        let left = AddressSet::single(0x1000, 0x100f);
        let right = AddressSet::single(0x2000, 0x200f);
        let correlator = ListingAddressCorrelator::new(left, right, ListingCorrelationConfig::default());

        assert_eq!(correlator.correlate_right(0x2000), Some(0x1000));
        assert_eq!(correlator.correlate_right(0x2005), Some(0x1005));
    }

    #[test]
    fn test_correlator_offset() {
        let left = AddressSet::single(0x1000, 0x100f);
        let right = AddressSet::single(0x2000, 0x200f);
        let correlator = ListingAddressCorrelator::new(left, right, ListingCorrelationConfig::default());

        assert_eq!(correlator.offset(), Some(0x1000));
    }

    #[test]
    fn test_correlator_empty() {
        let left = AddressSet::new();
        let right = AddressSet::new();
        let correlator = ListingAddressCorrelator::new(left, right, ListingCorrelationConfig::default());

        assert_eq!(correlator.quality(), CorrelationQuality::None);
        assert!(correlator.correlate_left(0x1000).is_none());
        assert!(correlator.offset().is_none());
    }

    #[test]
    fn test_correlator_size_mismatch() {
        let left = AddressSet::single(0x1000, 0x100f); // 16 bytes
        let right = AddressSet::single(0x2000, 0x2007); // 8 bytes
        let correlator = ListingAddressCorrelator::new(left, right, ListingCorrelationConfig::default());

        assert_eq!(correlator.quality(), CorrelationQuality::LinearOffset);
        // First 8 addresses should correlate
        assert_eq!(correlator.correlate_left(0x1000), Some(0x2000));
        assert_eq!(correlator.correlate_left(0x1007), Some(0x2007));
        // Last 8 should not (not in right set)
        assert_eq!(correlator.correlate_left(0x1008), None);
    }

    #[test]
    fn test_correlator_all_pairs() {
        let left = AddressSet::single(0x1000, 0x1003);
        let right = AddressSet::single(0x2000, 0x2003);
        let correlator = ListingAddressCorrelator::new(left, right, ListingCorrelationConfig::default());

        let pairs = correlator.all_pairs();
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0], (0x1000, 0x2000));
        assert_eq!(pairs[3], (0x1003, 0x2003));
    }

    #[test]
    fn test_correlator_pair_count() {
        let left = AddressSet::single(0x1000, 0x100f);
        let right = AddressSet::single(0x2000, 0x200f);
        let correlator = ListingAddressCorrelator::new(left, right, ListingCorrelationConfig::default());

        assert_eq!(correlator.pair_count(), 16);
    }

    #[test]
    fn test_correlator_debug() {
        let left = AddressSet::single(0x1000, 0x100f);
        let right = AddressSet::single(0x2000, 0x200f);
        let correlator = ListingAddressCorrelator::new(left, right, ListingCorrelationConfig::default());

        let debug_str = format!("{:?}", correlator);
        assert!(debug_str.contains("LinearOffset"));
    }

    // --- ListingCorrelatorBuilder tests ---

    #[test]
    fn test_builder_basic() {
        let correlator = ListingCorrelatorBuilder::new()
            .add_left_range(0x1000, 0x100f)
            .add_right_range(0x2000, 0x200f)
            .build();

        assert_eq!(correlator.correlate_left(0x1000), Some(0x2000));
        assert_eq!(correlator.quality(), CorrelationQuality::LinearOffset);
    }

    #[test]
    fn test_builder_multiple_ranges() {
        let correlator = ListingCorrelatorBuilder::new()
            .add_left_range(0x1000, 0x100f)
            .add_left_range(0x3000, 0x300f)
            .add_right_range(0x2000, 0x200f)
            .add_right_range(0x4000, 0x400f)
            .build();

        // First range should correlate
        assert_eq!(correlator.correlate_left(0x1000), Some(0x2000));
        // Second range should correlate
        assert_eq!(correlator.correlate_left(0x3000), Some(0x4000));
    }

    #[test]
    fn test_builder_with_config() {
        let config = ListingCorrelationConfig::new()
            .with_linear_offset(false)
            .with_best_effort(false);
        let correlator = ListingCorrelatorBuilder::new()
            .add_left_range(0x1000, 0x100f)
            .add_right_range(0x2000, 0x200f)
            .with_config(config)
            .build();

        // No strategies enabled -> None quality
        assert_eq!(correlator.quality(), CorrelationQuality::None);
    }

    #[test]
    fn test_builder_empty() {
        let correlator = ListingCorrelatorBuilder::new().build();
        assert_eq!(correlator.quality(), CorrelationQuality::None);
    }
}
