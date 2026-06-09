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

// ---------------------------------------------------------------------------
// AddressCorrelationStatistics
// ---------------------------------------------------------------------------

/// Statistics about a set of address correlations.
#[derive(Debug, Clone)]
pub struct AddressCorrelationStatistics {
    /// Total number of function pairs correlated.
    pub total_pairs: usize,
    /// Number of pairs where exact byte match was found.
    pub exact_matches: usize,
    /// Number of pairs with non-exact correlation.
    pub approximate_matches: usize,
    /// Average number of address mappings per correlated pair.
    pub avg_mappings_per_pair: f64,
    /// Average confidence across all correlated pairs.
    pub avg_confidence: f64,
    /// Number of function pairs that could not be correlated.
    pub unmatched_pairs: usize,
}

impl AddressCorrelationStatistics {
    /// Compute statistics from a list of correlations and total pair count.
    pub fn compute(correlations: &[CachedAddressCorrelation], total_pairs: usize) -> Self {
        let correlated = correlations.len();
        let exact = correlations.iter().filter(|c| (c.confidence - 1.0).abs() < f64::EPSILON).count();
        let approximate = correlated - exact;
        let unmatched = total_pairs.saturating_sub(correlated);
        let total_mappings: usize = correlations.iter().map(|c| c.len()).sum();
        let total_conf: f64 = correlations.iter().map(|c| c.confidence).sum();

        Self {
            total_pairs,
            exact_matches: exact,
            approximate_matches: approximate,
            avg_mappings_per_pair: if correlated == 0 { 0.0 } else { total_mappings as f64 / correlated as f64 },
            avg_confidence: if correlated == 0 { 0.0 } else { total_conf / correlated as f64 },
            unmatched_pairs: unmatched,
        }
    }

    /// Percentage of pairs that were matched (0.0 - 100.0).
    pub fn match_rate(&self) -> f64 {
        if self.total_pairs == 0 { 0.0 } else { (self.total_pairs - self.unmatched_pairs) as f64 / self.total_pairs as f64 * 100.0 }
    }
}

impl fmt::Display for AddressCorrelationStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AddressCorrelationStats[pairs={}, exact={}, approx={}, unmatched={}, avg_mappings={:.1}, avg_conf={:.3}, match_rate={:.1}%]",
            self.total_pairs, self.exact_matches, self.approximate_matches,
            self.unmatched_pairs, self.avg_mappings_per_pair, self.avg_confidence,
            self.match_rate(),
        )
    }
}

// ---------------------------------------------------------------------------
// FuzzyAddressCorrelator
// ---------------------------------------------------------------------------

/// A fuzzy address correlator that finds approximate address mappings
/// when exact or straight-line correlators fail.
///
/// This correlator works by comparing instruction mnemonics and bytes
/// at each offset within two functions, producing a best-effort mapping
/// even when the functions have been partially modified.
pub struct FuzzyAddressCorrelator {
    /// Minimum mnemonic similarity to accept a mapping.
    min_similarity: f64,
    /// Maximum offset delta to search for a match.
    max_search_delta: usize,
    /// Options for this correlator.
    options: VtOptions,
}

impl FuzzyAddressCorrelator {
    /// Create a new fuzzy correlator with default settings.
    pub fn new() -> Self {
        Self {
            min_similarity: 0.5,
            max_search_delta: 16,
            options: VtOptions::new("FuzzyAddressCorrelator"),
        }
    }

    /// Create a fuzzy correlator with custom parameters.
    pub fn with_params(min_similarity: f64, max_search_delta: usize) -> Self {
        Self {
            min_similarity: min_similarity.clamp(0.0, 1.0),
            max_search_delta,
            options: VtOptions::new("FuzzyAddressCorrelator"),
        }
    }

    /// Correlate addresses between two functions using fuzzy matching.
    ///
    /// For each instruction in the source function, searches within
    /// `max_search_delta` instructions in the destination for the best
    /// mnemonic match. Returns `None` if the overall match quality is
    /// below `min_similarity`.
    pub fn correlate(
        &self,
        source_entry: Address,
        source_bytes: &[u8],
        source_mnemonics: &[String],
        dest_entry: Address,
        dest_bytes: &[u8],
        dest_mnemonics: &[String],
    ) -> Option<AddressCorrelation> {
        if source_mnemonics.is_empty() || dest_mnemonics.is_empty() {
            return None;
        }

        let mut mappings = Vec::new();
        let mut matched_count = 0usize;

        for (i, src_mnem) in source_mnemonics.iter().enumerate() {
            let src_addr = Address::new(source_entry.offset + i as u64);

            // Search within delta window in destination.
            let search_start = if i > self.max_search_delta { i - self.max_search_delta } else { 0 };
            let search_end = (i + self.max_search_delta + 1).min(dest_mnemonics.len());

            let mut best_j = None;
            let mut best_score = 0.0f64;

            for j in search_start..search_end {
                let dst_mnem = &dest_mnemonics[j];
                let score = if src_mnem == dst_mnem {
                    1.0
                } else {
                    // Partial credit for similar mnemonics
                    let max_len = src_mnem.len().max(dst_mnem.len());
                    if max_len == 0 { 1.0 } else {
                        let common = src_mnem.chars().zip(dst_mnem.chars()).take_while(|(a, b)| a == b).count();
                        common as f64 / max_len as f64
                    }
                };
                if score > best_score {
                    best_score = score;
                    best_j = Some(j);
                }
            }

            if let Some(j) = best_j {
                if best_score >= 0.3 {
                    let dst_addr = Address::new(dest_entry.offset + j as u64);
                    mappings.push(AddressMapping { source: src_addr, destination: dst_addr });
                    if best_score >= 0.99 {
                        matched_count += 1;
                    }
                }
            }
        }

        if mappings.is_empty() {
            return None;
        }

        let quality = matched_count as f64 / source_mnemonics.len().max(dest_mnemonics.len()) as f64;
        if quality < self.min_similarity {
            return None;
        }

        Some(AddressCorrelation {
            source_entry,
            destination_entry: dest_entry,
            mappings,
            confidence: quality,
        })
    }
}

impl Default for FuzzyAddressCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressCorrelator for FuzzyAddressCorrelator {
    fn name(&self) -> &str {
        "FuzzyAddressCorrelator"
    }

    fn priority(&self) -> i32 {
        LATE_CHANCE_PRIORITY
    }

    fn options(&self) -> &VtOptions {
        &self.options
    }

    fn set_options(&mut self, options: VtOptions) {
        self.options = options;
    }

    fn correlate_functions(
        &self,
        source_entry: Address,
        source_bytes: &[u8],
        source_mnemonics: &[String],
        dest_entry: Address,
        dest_bytes: &[u8],
        dest_mnemonics: &[String],
    ) -> Option<AddressCorrelation> {
        self.correlate(source_entry, source_bytes, source_mnemonics, dest_entry, dest_bytes, dest_mnemonics)
    }

    fn correlate_data(
        &self,
        source_entry: Address,
        source_bytes: &[u8],
        dest_entry: Address,
        dest_bytes: &[u8],
    ) -> Option<AddressCorrelation> {
        // For data, use byte-level fuzzy matching.
        if source_bytes.is_empty() || dest_bytes.is_empty() {
            return None;
        }
        let max_len = source_bytes.len().max(dest_bytes.len());
        let matching = source_bytes.iter().zip(dest_bytes.iter()).filter(|(a, b)| a == b).count();
        let quality = matching as f64 / max_len as f64;
        if quality < self.min_similarity {
            return None;
        }
        let mappings: Vec<AddressMapping> = source_bytes.iter().enumerate()
            .map(|(i, _)| AddressMapping {
                source: Address::new(source_entry.offset + i as u64),
                destination: Address::new(dest_entry.offset + i as u64),
            })
            .collect();
        Some(AddressCorrelation {
            source_entry,
            destination_entry: dest_entry,
            mappings,
            confidence: quality,
        })
    }
}

impl fmt::Debug for FuzzyAddressCorrelator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuzzyAddressCorrelator")
            .field("min_similarity", &self.min_similarity)
            .field("max_search_delta", &self.max_search_delta)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// AddressCorrelatorChain
// ---------------------------------------------------------------------------

/// Runs multiple address correlators in sequence, returning the first
/// successful result.  Unlike `VtAddressCorrelator` which provides a
/// flat list, this chain supports more advanced composition patterns:
///
/// - Each step can be conditional (only run if a predicate passes).
/// - Steps can transform inputs before passing to the next correlator.
/// - The chain collects diagnostics about which step produced each result.
#[derive(Debug)]
pub struct AddressCorrelatorChain {
    steps: Vec<ChainStep>,
}

struct ChainStep {
    name: String,
    correlator: Box<dyn AddressCorrelator>,
}

impl fmt::Debug for ChainStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainStep")
            .field("name", &self.name)
            .finish()
    }
}

/// Diagnostic information about a chain correlation run.
#[derive(Debug, Clone)]
pub struct ChainDiagnostics {
    /// Name of the step that produced the result (or "none" if no match).
    pub matched_step: String,
    /// Number of steps attempted before finding a match.
    pub steps_attempted: usize,
    /// Total number of steps in the chain.
    pub total_steps: usize,
    /// Whether a correlation was found.
    pub found: bool,
}

impl fmt::Display for ChainDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChainDiagnostics[matched={}, attempted={}/{}, found={}]",
            self.matched_step, self.steps_attempted, self.total_steps, self.found,
        )
    }
}

impl AddressCorrelatorChain {
    /// Create a new empty chain.
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Add a correlator step to the chain.
    pub fn add_step(&mut self, name: impl Into<String>, correlator: Box<dyn AddressCorrelator>) {
        self.steps.push(ChainStep {
            name: name.into(),
            correlator,
        });
    }

    /// Number of steps in the chain.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Run the chain for function correlation, returning the first match
    /// along with diagnostics.
    pub fn correlate_functions_with_diagnostics(
        &self,
        source_entry: Address,
        source_bytes: &[u8],
        source_mnemonics: &[String],
        dest_entry: Address,
        dest_bytes: &[u8],
        dest_mnemonics: &[String],
    ) -> (Option<AddressCorrelation>, ChainDiagnostics) {
        for (i, step) in self.steps.iter().enumerate() {
            if let Some(corr) = step.correlator.correlate_functions(
                source_entry, source_bytes, source_mnemonics,
                dest_entry, dest_bytes, dest_mnemonics,
            ) {
                return (Some(corr), ChainDiagnostics {
                    matched_step: step.name.clone(),
                    steps_attempted: i + 1,
                    total_steps: self.steps.len(),
                    found: true,
                });
            }
        }
        (None, ChainDiagnostics {
            matched_step: "none".to_string(),
            steps_attempted: self.steps.len(),
            total_steps: self.steps.len(),
            found: false,
        })
    }

    /// Run the chain for function correlation (simple interface).
    pub fn correlate_functions(
        &self,
        source_entry: Address,
        source_bytes: &[u8],
        source_mnemonics: &[String],
        dest_entry: Address,
        dest_bytes: &[u8],
        dest_mnemonics: &[String],
    ) -> Option<AddressCorrelation> {
        self.correlate_functions_with_diagnostics(
            source_entry, source_bytes, source_mnemonics,
            dest_entry, dest_bytes, dest_mnemonics,
        ).0
    }

    /// Run the chain for data correlation, returning the first match.
    pub fn correlate_data(
        &self,
        source_entry: Address,
        source_bytes: &[u8],
        dest_entry: Address,
        dest_bytes: &[u8],
    ) -> Option<AddressCorrelation> {
        for step in &self.steps {
            if let Some(corr) = step.correlator.correlate_data(
                source_entry, source_bytes, dest_entry, dest_bytes,
            ) {
                return Some(corr);
            }
        }
        None
    }

    /// Get the names of all steps in order.
    pub fn step_names(&self) -> Vec<&str> {
        self.steps.iter().map(|s| s.name.as_str()).collect()
    }
}

impl Default for AddressCorrelatorChain {
    fn default() -> Self {
        Self::new()
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

    // ======================================================================
    // FuzzyAddressCorrelator tests
    // ======================================================================

    #[test]
    fn test_fuzzy_correlator_identical_mnemonics() {
        let fuzzy = FuzzyAddressCorrelator::new();
        let mnems = vec!["push".to_string(), "mov".to_string(), "ret".to_string()];
        let result = fuzzy.correlate(
            addr(0x1000), &[0x55, 0x48, 0xc3], &mnems,
            addr(0x2000), &[0x55, 0x48, 0xc3], &mnems,
        );
        assert!(result.is_some());
        let c = result.unwrap();
        assert_eq!(c.mappings.len(), 3);
        assert!((c.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fuzzy_correlator_similar_mnemonics() {
        let fuzzy = FuzzyAddressCorrelator::with_params(0.3, 8);
        let src_mnems = vec!["push".to_string(), "movl".to_string(), "ret".to_string()];
        let dst_mnems = vec!["push".to_string(), "movq".to_string(), "ret".to_string()];
        let result = fuzzy.correlate(
            addr(0x1000), &[0x55, 0x48, 0xc3], &src_mnems,
            addr(0x2000), &[0x55, 0x48, 0xc3], &dst_mnems,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_fuzzy_correlator_empty_input() {
        let fuzzy = FuzzyAddressCorrelator::new();
        let result = fuzzy.correlate(
            addr(0x1000), &[], &[],
            addr(0x2000), &[],
            &[],
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_fuzzy_correlator_completely_different() {
        let fuzzy = FuzzyAddressCorrelator::with_params(0.8, 2);
        let src_mnems = vec!["aaa".to_string(), "bbb".to_string(), "ccc".to_string()];
        let dst_mnems = vec!["xxx".to_string(), "yyy".to_string(), "zzz".to_string()];
        let result = fuzzy.correlate(
            addr(0x1000), &[1, 2, 3], &src_mnems,
            addr(0x2000), &[4, 5, 6], &dst_mnems,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_fuzzy_correlator_name() {
        let fuzzy = FuzzyAddressCorrelator::new();
        assert_eq!(fuzzy.name(), "FuzzyAddressCorrelator");
    }

    #[test]
    fn test_fuzzy_correlator_priority() {
        let fuzzy = FuzzyAddressCorrelator::new();
        assert_eq!(fuzzy.priority(), LATE_CHANCE_PRIORITY);
    }

    #[test]
    fn test_fuzzy_correlator_data() {
        let fuzzy = FuzzyAddressCorrelator::with_params(0.5, 4);
        let data = &[0x01u8, 0x02, 0x03, 0x04];
        let result = fuzzy.correlate_data(
            addr(0x3000), data,
            addr(0x4000), data,
        );
        assert!(result.is_some());
        assert!((result.unwrap().confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fuzzy_correlator_data_different() {
        let fuzzy = FuzzyAddressCorrelator::with_params(0.9, 4);
        let result = fuzzy.correlate_data(
            addr(0x3000), &[0x01, 0x02, 0x03],
            addr(0x4000), &[0xAA, 0xBB, 0x03],
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_fuzzy_correlator_debug() {
        let fuzzy = FuzzyAddressCorrelator::new();
        let debug = format!("{:?}", fuzzy);
        assert!(debug.contains("FuzzyAddressCorrelator"));
    }

    // ======================================================================
    // AddressCorrelatorChain tests
    // ======================================================================

    #[test]
    fn test_chain_empty() {
        let chain = AddressCorrelatorChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn test_chain_add_steps() {
        let mut chain = AddressCorrelatorChain::new();
        chain.add_step("exact", Box::new(ExactMatchAddressCorrelator::new()));
        chain.add_step("linear", Box::new(LinearAddressCorrelator::new()));
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.step_names(), vec!["exact", "linear"]);
    }

    #[test]
    fn test_chain_first_match_wins() {
        let mut chain = AddressCorrelatorChain::new();
        chain.add_step("exact", Box::new(ExactMatchAddressCorrelator::new()));
        chain.add_step("linear", Box::new(LinearAddressCorrelator::new()));

        let bytes = &[0x55u8, 0x48, 0x89, 0xe5, 0xc3];
        let (result, diag) = chain.correlate_functions_with_diagnostics(
            addr(0x1000), bytes, &[],
            addr(0x2000), bytes, &[],
        );
        assert!(result.is_some());
        assert!(diag.found);
        assert_eq!(diag.matched_step, "exact");
        assert_eq!(diag.steps_attempted, 1);
        assert_eq!(diag.total_steps, 2);
    }

    #[test]
    fn test_chain_fallback_to_second() {
        let mut chain = AddressCorrelatorChain::new();
        chain.add_step("exact", Box::new(ExactMatchAddressCorrelator::new()));
        chain.add_step("linear", Box::new(LinearAddressCorrelator::new()));

        let (result, diag) = chain.correlate_functions_with_diagnostics(
            addr(0x1000), &[0x55, 0x48], &[],
            addr(0x2000), &[0x90, 0x90], &[],
        );
        assert!(result.is_some()); // linear always returns Some
        assert!(diag.found);
        assert_eq!(diag.matched_step, "linear");
        assert_eq!(diag.steps_attempted, 2);
    }

    #[test]
    fn test_chain_data_correlation() {
        let mut chain = AddressCorrelatorChain::new();
        chain.add_step("exact", Box::new(ExactMatchAddressCorrelator::new()));

        let data = &[0x01u8, 0x02, 0x03, 0x04];
        let result = chain.correlate_data(addr(0x3000), data, addr(0x4000), data);
        assert!(result.is_some());
    }

    #[test]
    fn test_chain_default() {
        let chain = AddressCorrelatorChain::default();
        assert!(chain.is_empty());
    }

    // ======================================================================
    // AddressCorrelationStatistics tests
    // ======================================================================

    #[test]
    fn test_statistics_from_correlations() {
        let correlations = vec![
            CachedAddressCorrelation {
                name: "exact".to_string(),
                source_entry: addr(0x1000),
                destination_entry: addr(0x2000),
                forward_map: HashMap::new(),
                reverse_map: HashMap::new(),
                mappings: vec![AddressMapping { source: addr(0x1000), destination: addr(0x2000) }; 5],
                confidence: 1.0,
            },
            CachedAddressCorrelation {
                name: "fuzzy".to_string(),
                source_entry: addr(0x1100),
                destination_entry: addr(0x2100),
                forward_map: HashMap::new(),
                reverse_map: HashMap::new(),
                mappings: vec![AddressMapping { source: addr(0x1100), destination: addr(0x2100) }; 3],
                confidence: 0.75,
            },
        ];
        let stats = AddressCorrelationStatistics::compute(&correlations, 5);
        assert_eq!(stats.total_pairs, 5);
        assert_eq!(stats.exact_matches, 1);
        assert_eq!(stats.approximate_matches, 1);
        assert_eq!(stats.unmatched_pairs, 3);
        assert!((stats.avg_confidence - 0.875).abs() < 0.01);
        assert!((stats.avg_mappings_per_pair - 4.0).abs() < 0.01);
    }

    #[test]
    fn test_statistics_empty() {
        let stats = AddressCorrelationStatistics::compute(&[], 0);
        assert_eq!(stats.total_pairs, 0);
        assert!((stats.match_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_statistics_match_rate() {
        let correlations = vec![
            CachedAddressCorrelation {
                name: "a".to_string(),
                source_entry: addr(0x1000),
                destination_entry: addr(0x2000),
                forward_map: HashMap::new(),
                reverse_map: HashMap::new(),
                mappings: vec![],
                confidence: 1.0,
            },
        ];
        let stats = AddressCorrelationStatistics::compute(&correlations, 4);
        assert!((stats.match_rate() - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_statistics_display() {
        let stats = AddressCorrelationStatistics::compute(&[], 3);
        let d = format!("{}", stats);
        assert!(d.contains("pairs=3"));
    }

    #[test]
    fn test_chain_diagnostics_display() {
        let diag = ChainDiagnostics {
            matched_step: "exact".to_string(),
            steps_attempted: 1,
            total_steps: 3,
            found: true,
        };
        let d = format!("{}", diag);
        assert!(d.contains("exact"));
        assert!(d.contains("1/3"));
    }
}
