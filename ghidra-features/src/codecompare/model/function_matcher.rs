//! Function matching utilities for code comparison.
//!
//! This module provides utilities for matching functions between two programs
//! for comparison purposes. It supports multiple matching strategies:
//! exact name matching, entry point matching, and signature-based matching.
//!
//! In Ghidra's version tracking framework, function matching is a core
//! operation. This module provides the building blocks that comparison
//! models use to establish function correspondences.
//!
//! # Key types
//!
//! - [`MatchStrategy`] -- the matching strategy to use
//! - [`MatchConfidence`] -- how confident the match is
//! - [`FunctionMatch`] -- a matched pair of functions
//! - [`FunctionMatcher`] -- the main matching engine
//!
//! # Example
//!
//! ```rust
//! use ghidra_features::codecompare::model::function_matcher::*;
//! use ghidra_features::codecompare::model::FunctionInfo;
//!
//! let source_funcs = vec![
//!     FunctionInfo::new(1, "main", "/old", 0x1000),
//!     FunctionInfo::new(2, "init", "/old", 0x2000),
//! ];
//! let target_funcs = vec![
//!     FunctionInfo::new(3, "main", "/new", 0x3000),
//!     FunctionInfo::new(4, "init", "/new", 0x4000),
//! ];
//!
//! let matcher = FunctionMatcher::new(MatchStrategy::ByName);
//! let matches = matcher.find_matches(&source_funcs, &target_funcs);
//! assert_eq!(matches.len(), 2);
//! ```

use std::collections::{HashMap, HashSet};

use super::{ComparisonSide, FunctionInfo};

/// The strategy to use for matching functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchStrategy {
    /// Match by function name (case-sensitive).
    ByName,
    /// Match by function name (case-insensitive).
    ByNameIgnoreCase,
    /// Match by entry point address offset.
    ByOffset,
    /// Match by exact entry point address.
    ByExactAddress,
    /// Use multiple strategies and combine results.
    Combined,
}

impl MatchStrategy {
    /// A human-readable label for this strategy.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ByName => "By Name",
            Self::ByNameIgnoreCase => "By Name (Case Insensitive)",
            Self::ByOffset => "By Offset",
            Self::ByExactAddress => "By Exact Address",
            Self::Combined => "Combined",
        }
    }

    /// A description of this strategy.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ByName => "Match functions by exact name.",
            Self::ByNameIgnoreCase => "Match functions by name, ignoring case.",
            Self::ByOffset => "Match functions by their offset from the program's minimum address.",
            Self::ByExactAddress => "Match functions by exact entry point address.",
            Self::Combined => "Use multiple strategies and combine results.",
        }
    }
}

/// How confident a function match is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MatchConfidence {
    /// Low confidence (e.g., heuristic match).
    Low,
    /// Medium confidence (e.g., similar name).
    Medium,
    /// High confidence (e.g., same name, similar address).
    High,
    /// Exact match (e.g., same name and address).
    Exact,
}

impl MatchConfidence {
    /// A numeric score for this confidence level (higher is better).
    pub fn score(&self) -> u32 {
        match self {
            Self::Exact => 100,
            Self::High => 75,
            Self::Medium => 50,
            Self::Low => 25,
        }
    }

    /// A human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Exact => "Exact",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }
}

/// A matched pair of functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionMatch {
    /// The source function.
    pub source: FunctionInfo,
    /// The target function.
    pub target: FunctionInfo,
    /// The confidence of this match.
    pub confidence: MatchConfidence,
    /// The strategy that produced this match.
    pub strategy: MatchStrategy,
}

impl FunctionMatch {
    /// Create a new function match.
    pub fn new(
        source: FunctionInfo,
        target: FunctionInfo,
        confidence: MatchConfidence,
        strategy: MatchStrategy,
    ) -> Self {
        Self {
            source,
            target,
            confidence,
            strategy,
        }
    }

    /// Get the confidence score.
    pub fn score(&self) -> u32 {
        self.confidence.score()
    }
}

/// Statistics about a matching operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchStatistics {
    /// Number of source functions.
    pub source_count: usize,
    /// Number of target functions.
    pub target_count: usize,
    /// Number of matches found.
    pub match_count: usize,
    /// Number of source functions that were matched.
    pub matched_source_count: usize,
    /// Number of target functions that were matched.
    pub matched_target_count: usize,
    /// Number of unmatched source functions.
    pub unmatched_source_count: usize,
    /// Number of unmatched target functions.
    pub unmatched_target_count: usize,
    /// Average confidence score.
    pub average_confidence: u32,
}

/// The main function matching engine.
///
/// Finds correspondences between functions in two programs using
/// configurable matching strategies.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::model::function_matcher::*;
/// use ghidra_features::codecompare::model::FunctionInfo;
///
/// let source = vec![
///     FunctionInfo::new(1, "main", "/old", 0x1000),
///     FunctionInfo::new(2, "foo", "/old", 0x2000),
/// ];
/// let target = vec![
///     FunctionInfo::new(3, "main", "/new", 0x3000),
///     FunctionInfo::new(4, "bar", "/new", 0x4000),
/// ];
///
/// let matcher = FunctionMatcher::new(MatchStrategy::ByName);
/// let matches = matcher.find_matches(&source, &target);
/// assert_eq!(matches.len(), 1); // Only "main" matches
/// assert_eq!(matches[0].source.name, "main");
/// assert_eq!(matches[0].target.name, "main");
/// ```
pub struct FunctionMatcher {
    strategy: MatchStrategy,
    /// Minimum confidence to include a match.
    min_confidence: MatchConfidence,
}

impl FunctionMatcher {
    /// Create a new function matcher with the given strategy.
    pub fn new(strategy: MatchStrategy) -> Self {
        Self {
            strategy,
            min_confidence: MatchConfidence::Low,
        }
    }

    /// Set the minimum confidence threshold.
    pub fn with_min_confidence(mut self, confidence: MatchConfidence) -> Self {
        self.min_confidence = confidence;
        self
    }

    /// Find matches between source and target function lists.
    pub fn find_matches(
        &self,
        source: &[FunctionInfo],
        target: &[FunctionInfo],
    ) -> Vec<FunctionMatch> {
        match self.strategy {
            MatchStrategy::ByName => self.match_by_name(source, target, false),
            MatchStrategy::ByNameIgnoreCase => self.match_by_name(source, target, true),
            MatchStrategy::ByOffset => self.match_by_offset(source, target),
            MatchStrategy::ByExactAddress => self.match_by_exact_address(source, target),
            MatchStrategy::Combined => self.match_combined(source, target),
        }
    }

    /// Find matches and compute statistics.
    pub fn find_matches_with_stats(
        &self,
        source: &[FunctionInfo],
        target: &[FunctionInfo],
    ) -> (Vec<FunctionMatch>, MatchStatistics) {
        let matches = self.find_matches(source, target);
        let stats = self.compute_statistics(source, target, &matches);
        (matches, stats)
    }

    /// Match functions by name.
    fn match_by_name(
        &self,
        source: &[FunctionInfo],
        target: &[FunctionInfo],
        ignore_case: bool,
    ) -> Vec<FunctionMatch> {
        let mut matches = Vec::new();

        // Build a lookup for target functions by name
        let target_by_name: HashMap<String, &FunctionInfo> = if ignore_case {
            let mut map = HashMap::new();
            for func in target {
                map.insert(func.name.to_lowercase(), func);
            }
            map
        } else {
            let mut map = HashMap::new();
            for func in target {
                map.insert(func.name.clone(), func);
            }
            map
        };

        for src in source {
            let key = if ignore_case {
                src.name.to_lowercase()
            } else {
                src.name.clone()
            };

            if let Some(&tgt) = target_by_name.get(&key) {
                let confidence = if src.entry_point == tgt.entry_point {
                    MatchConfidence::Exact
                } else {
                    MatchConfidence::High
                };

                if confidence >= self.min_confidence {
                    matches.push(FunctionMatch::new(
                        src.clone(),
                        tgt.clone(),
                        confidence,
                        self.strategy,
                    ));
                }
            }
        }

        matches
    }

    /// Match functions by offset from minimum address.
    fn match_by_offset(
        &self,
        source: &[FunctionInfo],
        target: &[FunctionInfo],
    ) -> Vec<FunctionMatch> {
        let mut matches = Vec::new();

        if source.is_empty() || target.is_empty() {
            return matches;
        }

        let src_min = source.iter().map(|f| f.entry_point).min().unwrap_or(0);
        let tgt_min = target.iter().map(|f| f.entry_point).min().unwrap_or(0);

        // Build a lookup for target functions by offset
        let target_by_offset: HashMap<u64, &FunctionInfo> = target
            .iter()
            .map(|f| (f.entry_point - tgt_min, f))
            .collect();

        for src in source {
            let offset = src.entry_point - src_min;
            if let Some(&tgt) = target_by_offset.get(&offset) {
                let confidence = if src.name == tgt.name {
                    MatchConfidence::Exact
                } else {
                    MatchConfidence::Medium
                };

                if confidence >= self.min_confidence {
                    matches.push(FunctionMatch::new(
                        src.clone(),
                        tgt.clone(),
                        confidence,
                        self.strategy,
                    ));
                }
            }
        }

        matches
    }

    /// Match functions by exact entry point address.
    fn match_by_exact_address(
        &self,
        source: &[FunctionInfo],
        target: &[FunctionInfo],
    ) -> Vec<FunctionMatch> {
        let mut matches = Vec::new();

        // Build a lookup for target functions by address
        let target_by_addr: HashMap<u64, &FunctionInfo> = target
            .iter()
            .map(|f| (f.entry_point, f))
            .collect();

        for src in source {
            if let Some(&tgt) = target_by_addr.get(&src.entry_point) {
                let confidence = if src.name == tgt.name {
                    MatchConfidence::Exact
                } else {
                    MatchConfidence::High
                };

                if confidence >= self.min_confidence {
                    matches.push(FunctionMatch::new(
                        src.clone(),
                        tgt.clone(),
                        confidence,
                        self.strategy,
                    ));
                }
            }
        }

        matches
    }

    /// Match using multiple strategies and combine results.
    fn match_combined(
        &self,
        source: &[FunctionInfo],
        target: &[FunctionInfo],
    ) -> Vec<FunctionMatch> {
        let mut all_matches: Vec<FunctionMatch> = Vec::new();
        let mut matched_sources: HashSet<u64> = HashSet::new();
        let mut matched_targets: HashSet<u64> = HashSet::new();

        // First pass: exact name matches
        let name_matches = self.match_by_name(source, target, false);
        for m in name_matches {
            if !matched_sources.contains(&m.source.id)
                && !matched_targets.contains(&m.target.id)
            {
                matched_sources.insert(m.source.id);
                matched_targets.insert(m.target.id);
                all_matches.push(m);
            }
        }

        // Second pass: offset matches for unmatched functions
        let remaining_source: Vec<FunctionInfo> = source
            .iter()
            .filter(|f| !matched_sources.contains(&f.id))
            .cloned()
            .collect();
        let remaining_target: Vec<FunctionInfo> = target
            .iter()
            .filter(|f| !matched_targets.contains(&f.id))
            .cloned()
            .collect();

        if !remaining_source.is_empty() && !remaining_target.is_empty() {
            let offset_matches = self.match_by_offset(&remaining_source, &remaining_target);
            for m in offset_matches {
                if !matched_sources.contains(&m.source.id)
                    && !matched_targets.contains(&m.target.id)
                {
                    matched_sources.insert(m.source.id);
                    matched_targets.insert(m.target.id);
                    all_matches.push(m);
                }
            }
        }

        // Third pass: case-insensitive name matches for still-unmatched functions
        let remaining_source: Vec<FunctionInfo> = source
            .iter()
            .filter(|f| !matched_sources.contains(&f.id))
            .cloned()
            .collect();
        let remaining_target: Vec<FunctionInfo> = target
            .iter()
            .filter(|f| !matched_targets.contains(&f.id))
            .cloned()
            .collect();

        if !remaining_source.is_empty() && !remaining_target.is_empty() {
            let ci_matches = self.match_by_name(&remaining_source, &remaining_target, true);
            for m in ci_matches {
                if !matched_sources.contains(&m.source.id)
                    && !matched_targets.contains(&m.target.id)
                {
                    matched_sources.insert(m.source.id);
                    matched_targets.insert(m.target.id);
                    all_matches.push(m);
                }
            }
        }

        all_matches
    }

    /// Compute statistics about a matching operation.
    fn compute_statistics(
        &self,
        source: &[FunctionInfo],
        target: &[FunctionInfo],
        matches: &[FunctionMatch],
    ) -> MatchStatistics {
        let matched_source_count = matches
            .iter()
            .map(|m| &m.source.id)
            .collect::<HashSet<_>>()
            .len();
        let matched_target_count = matches
            .iter()
            .map(|m| &m.target.id)
            .collect::<HashSet<_>>()
            .len();

        let average_confidence = if matches.is_empty() {
            0
        } else {
            matches.iter().map(|m| m.score()).sum::<u32>() / matches.len() as u32
        };

        MatchStatistics {
            source_count: source.len(),
            target_count: target.len(),
            match_count: matches.len(),
            matched_source_count,
            matched_target_count,
            unmatched_source_count: source.len() - matched_source_count,
            unmatched_target_count: target.len() - matched_target_count,
            average_confidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(id: u64, name: &str, program: &str, entry: u64) -> FunctionInfo {
        FunctionInfo::new(id, name, program, entry)
    }

    // --- MatchStrategy tests ---

    #[test]
    fn test_strategy_label() {
        assert_eq!(MatchStrategy::ByName.label(), "By Name");
        assert_eq!(MatchStrategy::ByOffset.label(), "By Offset");
        assert_eq!(MatchStrategy::Combined.label(), "Combined");
    }

    #[test]
    fn test_strategy_description() {
        assert!(!MatchStrategy::ByName.description().is_empty());
        assert!(!MatchStrategy::ByOffset.description().is_empty());
    }

    // --- MatchConfidence tests ---

    #[test]
    fn test_confidence_score() {
        assert_eq!(MatchConfidence::Exact.score(), 100);
        assert_eq!(MatchConfidence::High.score(), 75);
        assert_eq!(MatchConfidence::Medium.score(), 50);
        assert_eq!(MatchConfidence::Low.score(), 25);
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(MatchConfidence::Exact > MatchConfidence::High);
        assert!(MatchConfidence::High > MatchConfidence::Medium);
        assert!(MatchConfidence::Medium > MatchConfidence::Low);
    }

    #[test]
    fn test_confidence_label() {
        assert_eq!(MatchConfidence::Exact.label(), "Exact");
        assert_eq!(MatchConfidence::Low.label(), "Low");
    }

    // --- FunctionMatch tests ---

    #[test]
    fn test_function_match_score() {
        let m = FunctionMatch::new(
            make_func(1, "a", "/old", 0x1000),
            make_func(2, "a", "/new", 0x2000),
            MatchConfidence::High,
            MatchStrategy::ByName,
        );
        assert_eq!(m.score(), 75);
    }

    // --- FunctionMatcher: ByName tests ---

    #[test]
    fn test_match_by_name_basic() {
        let source = vec![
            make_func(1, "main", "/old", 0x1000),
            make_func(2, "init", "/old", 0x2000),
        ];
        let target = vec![
            make_func(3, "main", "/new", 0x3000),
            make_func(4, "init", "/new", 0x4000),
        ];

        let matcher = FunctionMatcher::new(MatchStrategy::ByName);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_match_by_name_partial() {
        let source = vec![
            make_func(1, "main", "/old", 0x1000),
            make_func(2, "foo", "/old", 0x2000),
        ];
        let target = vec![
            make_func(3, "main", "/new", 0x3000),
            make_func(4, "bar", "/new", 0x4000),
        ];

        let matcher = FunctionMatcher::new(MatchStrategy::ByName);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].source.name, "main");
    }

    #[test]
    fn test_match_by_name_empty() {
        let source = vec![make_func(1, "main", "/old", 0x1000)];
        let target = vec![];

        let matcher = FunctionMatcher::new(MatchStrategy::ByName);
        let matches = matcher.find_matches(&source, &target);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_by_name_exact_confidence() {
        let source = vec![make_func(1, "main", "/old", 0x1000)];
        let target = vec![make_func(2, "main", "/new", 0x1000)]; // Same address

        let matcher = FunctionMatcher::new(MatchStrategy::ByName);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, MatchConfidence::Exact);
    }

    #[test]
    fn test_match_by_name_high_confidence() {
        let source = vec![make_func(1, "main", "/old", 0x1000)];
        let target = vec![make_func(2, "main", "/new", 0x3000)]; // Different address

        let matcher = FunctionMatcher::new(MatchStrategy::ByName);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, MatchConfidence::High);
    }

    // --- FunctionMatcher: ByNameIgnoreCase tests ---

    #[test]
    fn test_match_by_name_ignore_case() {
        let source = vec![make_func(1, "Main", "/old", 0x1000)];
        let target = vec![make_func(2, "main", "/new", 0x3000)];

        let matcher = FunctionMatcher::new(MatchStrategy::ByNameIgnoreCase);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_by_name_case_sensitive_no_match() {
        let source = vec![make_func(1, "Main", "/old", 0x1000)];
        let target = vec![make_func(2, "main", "/new", 0x3000)];

        let matcher = FunctionMatcher::new(MatchStrategy::ByName);
        let matches = matcher.find_matches(&source, &target);
        assert!(matches.is_empty());
    }

    // --- FunctionMatcher: ByOffset tests ---

    #[test]
    fn test_match_by_offset() {
        let source = vec![
            make_func(1, "aaa", "/old", 0x1000),
            make_func(2, "bbb", "/old", 0x2000),
        ];
        let target = vec![
            make_func(3, "aaa_renamed", "/new", 0x3000),
            make_func(4, "bbb_renamed", "/new", 0x4000),
        ];

        let matcher = FunctionMatcher::new(MatchStrategy::ByOffset);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 2);
        // First function at offset 0 matches first target at offset 0
        assert_eq!(matches[0].source.entry_point, 0x1000);
        assert_eq!(matches[0].target.entry_point, 0x3000);
    }

    #[test]
    fn test_match_by_offset_with_name_bonus() {
        let source = vec![make_func(1, "main", "/old", 0x1000)];
        let target = vec![make_func(2, "main", "/new", 0x3000)];

        let matcher = FunctionMatcher::new(MatchStrategy::ByOffset);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 1);
        // Same name + same offset = Exact confidence
        assert_eq!(matches[0].confidence, MatchConfidence::Exact);
    }

    // --- FunctionMatcher: ByExactAddress tests ---

    #[test]
    fn test_match_by_exact_address() {
        let source = vec![make_func(1, "main", "/old", 0x1000)];
        let target = vec![make_func(2, "main_renamed", "/new", 0x1000)];

        let matcher = FunctionMatcher::new(MatchStrategy::ByExactAddress);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_by_exact_address_no_match() {
        let source = vec![make_func(1, "main", "/old", 0x1000)];
        let target = vec![make_func(2, "main", "/new", 0x3000)];

        let matcher = FunctionMatcher::new(MatchStrategy::ByExactAddress);
        let matches = matcher.find_matches(&source, &target);
        assert!(matches.is_empty());
    }

    // --- FunctionMatcher: Combined tests ---

    #[test]
    fn test_match_combined() {
        let source = vec![
            make_func(1, "main", "/old", 0x1000),
            make_func(2, "init", "/old", 0x2000),
            make_func(3, "helper", "/old", 0x3000),
        ];
        let target = vec![
            make_func(4, "main", "/new", 0x4000),      // Name match
            make_func(5, "INIT", "/new", 0x5000),       // Case-insensitive match
            make_func(6, "other", "/new", 0x6000),      // No match
        ];

        let matcher = FunctionMatcher::new(MatchStrategy::Combined);
        let matches = matcher.find_matches(&source, &target);
        // "main" matches by name, "INIT" matches by case-insensitive name
        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_match_combined_prefers_exact_name() {
        let source = vec![make_func(1, "main", "/old", 0x1000)];
        let target = vec![
            make_func(2, "main", "/new", 0x3000),  // Name match
            make_func(3, "other", "/new", 0x1000),  // Address match
        ];

        let matcher = FunctionMatcher::new(MatchStrategy::Combined);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 1);
        // Should prefer name match
        assert_eq!(matches[0].target.name, "main");
    }

    // --- FunctionMatcher: MinConfidence tests ---

    #[test]
    fn test_match_min_confidence() {
        let source = vec![make_func(1, "main", "/old", 0x1000)];
        let target = vec![make_func(2, "main", "/new", 0x3000)];

        // With High min confidence, should still match (High confidence)
        let matcher = FunctionMatcher::new(MatchStrategy::ByName)
            .with_min_confidence(MatchConfidence::High);
        let matches = matcher.find_matches(&source, &target);
        assert_eq!(matches.len(), 1);

        // With Exact min confidence, should not match (only High confidence)
        let matcher = FunctionMatcher::new(MatchStrategy::ByName)
            .with_min_confidence(MatchConfidence::Exact);
        let matches = matcher.find_matches(&source, &target);
        assert!(matches.is_empty());
    }

    // --- MatchStatistics tests ---

    #[test]
    fn test_match_statistics() {
        let source = vec![
            make_func(1, "main", "/old", 0x1000),
            make_func(2, "foo", "/old", 0x2000),
        ];
        let target = vec![
            make_func(3, "main", "/new", 0x3000),
            make_func(4, "bar", "/new", 0x4000),
        ];

        let matcher = FunctionMatcher::new(MatchStrategy::ByName);
        let (matches, stats) = matcher.find_matches_with_stats(&source, &target);

        assert_eq!(stats.source_count, 2);
        assert_eq!(stats.target_count, 2);
        assert_eq!(stats.match_count, 1);
        assert_eq!(stats.matched_source_count, 1);
        assert_eq!(stats.matched_target_count, 1);
        assert_eq!(stats.unmatched_source_count, 1);
        assert_eq!(stats.unmatched_target_count, 1);
        assert_eq!(stats.average_confidence, 75); // High confidence
    }

    #[test]
    fn test_match_statistics_empty() {
        let matcher = FunctionMatcher::new(MatchStrategy::ByName);
        let (matches, stats) = matcher.find_matches_with_stats(&[], &[]);

        assert!(matches.is_empty());
        assert_eq!(stats.source_count, 0);
        assert_eq!(stats.target_count, 0);
        assert_eq!(stats.match_count, 0);
        assert_eq!(stats.average_confidence, 0);
    }

    #[test]
    fn test_match_statistics_all_matched() {
        let source = vec![make_func(1, "main", "/old", 0x1000)];
        let target = vec![make_func(2, "main", "/new", 0x1000)];

        let matcher = FunctionMatcher::new(MatchStrategy::ByName);
        let (matches, stats) = matcher.find_matches_with_stats(&source, &target);

        assert_eq!(stats.match_count, 1);
        assert_eq!(stats.unmatched_source_count, 0);
        assert_eq!(stats.unmatched_target_count, 0);
        assert_eq!(stats.average_confidence, 100); // Exact confidence
    }
}
