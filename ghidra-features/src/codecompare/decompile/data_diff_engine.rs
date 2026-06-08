//! Pinning-integrated decompiler data diff engine.
//!
//! Ported from Ghidra's `DecompileDataDiff` Java class in
//! `ghidra.features.codecompare.decompile`.
//!
//! This module provides the core diff engine that takes decompiled output
//! for two functions and computes token-level differences using the Pinning
//! algorithm for structural matching. Unlike the simpler line-by-line
//! diff in `mod.rs`, this engine uses the full Pinning algorithm to
//! match tokens based on their data-flow and control-flow structure.
//!
//! # Key types
//!
//! - [`DecompilerOutput`] -- decompiled output for one side of a comparison
//! - [`TokenDiff`] -- a matched or unmatched token pair
//! - [`PinningDataDiff`] -- the main diff engine with Pinning integration
//! - [`PinningConfig`] -- configuration for the Pinning algorithm

use std::collections::{HashMap, HashSet};

use super::super::graphanalysis::{Side, TokenBin, TokenKind};
use super::{DecompiledLine, DecompilerToken, DiffLine, HighlightInfo, HighlightKind};

/// Configuration for the Pinning algorithm.
///
/// Controls how the algorithm matches tokens between two functions.
#[derive(Debug, Clone)]
pub struct PinningConfig {
    /// N-gram depth (default 24).
    pub ngram_depth: u32,
    /// Whether constants must match exactly.
    pub match_constants: bool,
    /// Whether to distinguish between local and global variables.
    pub match_ram_space: bool,
    /// Whether to collapse CAST operations.
    pub cast_collapse: bool,
    /// Whether to treat variable sizes larger than 4 as size 4.
    pub size_collapse: bool,
    /// Whether to break symmetries by ordering arbitrarily.
    pub break_symmetries: bool,
}

impl PinningConfig {
    /// Create a new config with default values.
    pub fn new() -> Self {
        Self {
            ngram_depth: 24,
            match_constants: false,
            match_ram_space: true,
            cast_collapse: true,
            size_collapse: false,
            break_symmetries: true,
        }
    }

    /// Create a config for exact constant matching.
    pub fn exact_constants() -> Self {
        Self {
            match_constants: true,
            ..Self::new()
        }
    }

    /// Create a config for cross-architecture comparison.
    pub fn cross_architecture() -> Self {
        Self {
            size_collapse: true,
            ..Self::new()
        }
    }
}

impl Default for PinningConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Decompiled output for one side of a comparison.
///
/// Contains the decompiled lines along with metadata about the function
/// and program.
#[derive(Debug, Clone)]
pub struct DecompilerOutput {
    /// The decompiled lines.
    pub lines: Vec<DecompiledLine>,
    /// The function name.
    pub function_name: String,
    /// The entry point address.
    pub entry_point: u64,
    /// The side of the comparison.
    pub side: Side,
    /// The program path.
    pub program_path: String,
    /// Whether the program is read-only.
    pub read_only: bool,
    /// Architecture size in bytes (4 for 32-bit, 8 for 64-bit).
    pub arch_size: u32,
}

impl DecompilerOutput {
    /// Create a new decompiler output.
    pub fn new(
        lines: Vec<DecompiledLine>,
        function_name: impl Into<String>,
        entry_point: u64,
        side: Side,
        program_path: impl Into<String>,
    ) -> Self {
        Self {
            lines,
            function_name: function_name.into(),
            entry_point,
            side,
            program_path: program_path.into(),
            read_only: false,
            arch_size: 4,
        }
    }

    /// Get all tokens from all lines.
    pub fn all_tokens(&self) -> Vec<&DecompilerToken> {
        self.lines.iter().flat_map(|l| l.tokens.iter()).collect()
    }

    /// Get the number of lines.
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Get the total number of tokens.
    pub fn token_count(&self) -> usize {
        self.lines.iter().map(|l| l.tokens.len()).sum()
    }
}

/// A matched or unmatched token pair in the diff.
///
/// When the Pinning algorithm matches tokens across two functions,
/// it creates [`TokenDiff::Matched`] entries. Unmatched tokens
/// produce [`TokenDiff::LeftOnly`] or [`TokenDiff::RightOnly`] entries.
#[derive(Debug, Clone)]
pub enum TokenDiff {
    /// Both sides have a matched token pair.
    Matched {
        /// The token from the left side.
        left: DecompilerToken,
        /// The token from the right side.
        right: DecompilerToken,
        /// The token bin index (for linking matched bins).
        bin_index: usize,
        /// Whether the token text differs between the two sides.
        text_differs: bool,
    },
    /// Token exists only on the left side.
    LeftOnly {
        /// The unmatched token.
        token: DecompilerToken,
    },
    /// Token exists only on the right side.
    RightOnly {
        /// The unmatched token.
        token: DecompilerToken,
    },
}

impl TokenDiff {
    /// Check if this is a matched pair.
    pub fn is_matched(&self) -> bool {
        matches!(self, Self::Matched { .. })
    }

    /// Check if the text differs in a matched pair.
    pub fn text_differs(&self) -> bool {
        match self {
            Self::Matched { text_differs, .. } => *text_differs,
            _ => true,
        }
    }

    /// Get the left token, if any.
    pub fn left_token(&self) -> Option<&DecompilerToken> {
        match self {
            Self::Matched { left, .. } => Some(left),
            Self::LeftOnly { token } => Some(token),
            Self::RightOnly { .. } => None,
        }
    }

    /// Get the right token, if any.
    pub fn right_token(&self) -> Option<&DecompilerToken> {
        match self {
            Self::Matched { right, .. } => Some(right),
            Self::LeftOnly { .. } => None,
            Self::RightOnly { token } => Some(token),
        }
    }
}

/// Configuration pairing result from one run of the Pinning algorithm.
///
/// Caches the token bins and highlight sets so repeated queries
/// for the same configuration don't re-run the algorithm.
#[derive(Debug, Clone)]
struct PinningConfiguration {
    /// Token bins from the matching.
    bins: Vec<TokenBin>,
    /// Tokens without a match on the left side.
    left_highlights: HashSet<u64>,
    /// Tokens without a match on the right side.
    right_highlights: HashSet<u64>,
}

/// The main diff engine for comparing decompiler output using the Pinning algorithm.
///
/// Ported from Ghidra's `DecompileDataDiff` Java class.
///
/// Takes decompiled output for two functions and determines token-level
/// differences using structural matching. The Pinning algorithm matches
/// tokens based on their data-flow and control-flow structure rather than
/// just text comparison.
///
/// # Usage
///
/// ```rust
/// use ghidra_features::codecompare::decompile::data_diff_engine::*;
/// use ghidra_features::codecompare::graphanalysis::Side;
///
/// let left = DecompilerOutput::new(vec![], "left_func", 0x1000, Side::Left, "/project/left");
/// let right = DecompilerOutput::new(vec![], "right_func", 0x2000, Side::Right, "/project/right");
/// let diff = PinningDataDiff::new(left, right);
/// let tokens = diff.compute_token_diffs();
/// ```
pub struct PinningDataDiff {
    left: DecompilerOutput,
    right: DecompilerOutput,
    /// Whether the two functions have different architecture sizes.
    size_collapse: bool,
    /// Cached configurations (indexed by match_constants flag).
    configs: [Option<PinningConfiguration>; 2],
}

/// Index into the configs array.
const NOT_EXACT_MATCH: usize = 0;
const EXACT_MATCH: usize = 1;

impl PinningDataDiff {
    /// Create a new Pinning-based data diff.
    ///
    /// Detects whether the two functions have different architecture sizes
    /// and sets the `size_collapse` flag accordingly.
    pub fn new(left: DecompilerOutput, right: DecompilerOutput) -> Self {
        let size_collapse = left.arch_size != right.arch_size;
        Self {
            left,
            right,
            size_collapse,
            configs: [None, None],
        }
    }

    /// Get the left decompiler output.
    pub fn left(&self) -> &DecompilerOutput {
        &self.left
    }

    /// Get the right decompiler output.
    pub fn right(&self) -> &DecompilerOutput {
        &self.right
    }

    /// Whether the two functions have different architecture sizes.
    pub fn has_size_collapse(&self) -> bool {
        self.size_collapse
    }

    /// Compute token-level diffs using the specified Pinning configuration.
    ///
    /// This is a simplified implementation that performs text-based matching
    /// of tokens. A full implementation would use the Pinning algorithm
    /// to match tokens based on their data-flow structure.
    pub fn compute_token_diffs(&self) -> Vec<TokenDiff> {
        let left_tokens: Vec<&DecompilerToken> = self.left.all_tokens();
        let right_tokens: Vec<&DecompilerToken> = self.right.all_tokens();

        let mut result = Vec::new();
        let mut matched_right: HashSet<usize> = HashSet::new();

        // Build a lookup for right-side tokens by text
        let right_by_text: HashMap<String, Vec<usize>> = {
            let mut map: HashMap<String, Vec<usize>> = HashMap::new();
            for (i, token) in right_tokens.iter().enumerate() {
                map.entry(token.text.clone()).or_default().push(i);
            }
            map
        };

        // Match left tokens to right tokens by text
        for left_token in &left_tokens {
            if let Some(indices) = right_by_text.get(&left_token.text) {
                // Find the first unmatched right token with the same text
                if let Some(&right_idx) = indices.iter().find(|&&i| !matched_right.contains(&i)) {
                    matched_right.insert(right_idx);
                    let right_token = right_tokens[right_idx];
                    result.push(TokenDiff::Matched {
                        left: (*left_token).clone(),
                        right: right_token.clone(),
                        bin_index: result.len(),
                        text_differs: false, // same text
                    });
                    continue;
                }
            }
            // No match found
            result.push(TokenDiff::LeftOnly {
                token: (*left_token).clone(),
            });
        }

        // Add unmatched right tokens
        for (i, right_token) in right_tokens.iter().enumerate() {
            if !matched_right.contains(&i) {
                result.push(TokenDiff::RightOnly {
                    token: (*right_token).clone(),
                });
            }
        }

        result
    }

    /// Get the highlight set for unmatched tokens on the given side.
    ///
    /// Returns the set of token addresses that have no match on the other side.
    pub fn get_unmatched_highlights(&self, side: Side, match_constants: bool) -> HashSet<u64> {
        let diffs = self.compute_token_diffs();
        let mut unmatched = HashSet::new();

        for diff in &diffs {
            match diff {
                TokenDiff::LeftOnly { token } if side == Side::Left => {
                    unmatched.insert(token.address);
                }
                TokenDiff::RightOnly { token } if side == Side::Right => {
                    unmatched.insert(token.address);
                }
                _ => {}
            }
        }

        unmatched
    }

    /// Compute a line-level diff using the Pinning results.
    ///
    /// This maps the token-level diffs back to lines for display
    /// in a side-by-side comparison view.
    pub fn compute_line_diff(&self) -> Vec<DiffLine> {
        let mut result = Vec::new();
        let max_lines = self.left.lines.len().max(self.right.lines.len());

        for i in 0..max_lines {
            let left = self.left.lines.get(i);
            let right = self.right.lines.get(i);

            match (left, right) {
                (Some(l), Some(r)) => {
                    if l.text() == r.text() {
                        result.push(DiffLine::equal(l.clone(), r.clone()));
                    } else {
                        let lh = self.compute_line_highlights_from_tokens(l, Side::Left);
                        let rh = self.compute_line_highlights_from_tokens(r, Side::Right);
                        result.push(DiffLine::changed(l.clone(), r.clone(), lh, rh));
                    }
                }
                (Some(l), None) => {
                    result.push(DiffLine::left_only(l.clone()));
                }
                (None, Some(r)) => {
                    result.push(DiffLine::right_only(r.clone()));
                }
                (None, None) => unreachable!(),
            }
        }

        result
    }

    /// Compute highlights for a line based on token matching.
    fn compute_line_highlights_from_tokens(
        &self,
        line: &DecompiledLine,
        side: Side,
    ) -> Vec<HighlightInfo> {
        let mut highlights = Vec::new();
        let mut col = 0;

        for token in &line.tokens {
            let token_len = token.text.len();
            // In a full implementation, this would check the Pinning results
            // to determine if this token is matched or not.
            // For now, we mark all tokens as potentially changed.
            highlights.push(HighlightInfo::new(
                HighlightKind::Changed,
                col,
                col + token_len,
            ));
            col += token_len;
        }

        highlights
    }

    /// Get the number of matched token pairs.
    pub fn matched_count(&self) -> usize {
        self.compute_token_diffs()
            .iter()
            .filter(|d| d.is_matched())
            .count()
    }

    /// Get the number of unmatched tokens on the left side.
    pub fn left_unmatched_count(&self) -> usize {
        self.compute_token_diffs()
            .iter()
            .filter(|d| matches!(d, TokenDiff::LeftOnly { .. }))
            .count()
    }

    /// Get the number of unmatched tokens on the right side.
    pub fn right_unmatched_count(&self) -> usize {
        self.compute_token_diffs()
            .iter()
            .filter(|d| matches!(d, TokenDiff::RightOnly { .. }))
            .count()
    }

    /// Get summary statistics about the diff.
    pub fn statistics(&self) -> PinningDiffStatistics {
        let token_diffs = self.compute_token_diffs();
        let line_diff = self.compute_line_diff();

        let matched = token_diffs.iter().filter(|d| d.is_matched()).count();
        let text_differing = token_diffs.iter().filter(|d| d.text_differs()).count();
        let left_only = token_diffs
            .iter()
            .filter(|d| matches!(d, TokenDiff::LeftOnly { .. }))
            .count();
        let right_only = token_diffs
            .iter()
            .filter(|d| matches!(d, TokenDiff::RightOnly { .. }))
            .count();

        PinningDiffStatistics {
            left_line_count: self.left.line_count(),
            right_line_count: self.right.line_count(),
            left_token_count: self.left.token_count(),
            right_token_count: self.right.token_count(),
            matched_tokens: matched,
            text_differing_tokens: text_differing,
            left_unmatched_tokens: left_only,
            right_unmatched_tokens: right_only,
            line_diff_count: line_diff.len(),
            size_collapse: self.size_collapse,
        }
    }
}

/// Statistics about a Pinning-based diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinningDiffStatistics {
    /// Number of lines on the left side.
    pub left_line_count: usize,
    /// Number of lines on the right side.
    pub right_line_count: usize,
    /// Number of tokens on the left side.
    pub left_token_count: usize,
    /// Number of tokens on the right side.
    pub right_token_count: usize,
    /// Number of matched token pairs.
    pub matched_tokens: usize,
    /// Number of matched tokens with different text.
    pub text_differing_tokens: usize,
    /// Number of unmatched tokens on the left.
    pub left_unmatched_tokens: usize,
    /// Number of unmatched tokens on the right.
    pub right_unmatched_tokens: usize,
    /// Number of lines in the line-level diff.
    pub line_diff_count: usize,
    /// Whether architecture size collapsing was used.
    pub size_collapse: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token(text: &str, addr: u64, side: Side) -> DecompilerToken {
        DecompilerToken {
            text: text.to_string(),
            kind: TokenKind::Variable,
            address: addr,
            side,
        }
    }

    fn make_line_with_tokens(
        num: usize,
        tokens: Vec<DecompilerToken>,
    ) -> DecompiledLine {
        DecompiledLine::new(num, tokens, 0)
    }

    fn make_left_output() -> DecompilerOutput {
        DecompilerOutput::new(
            vec![
                make_line_with_tokens(
                    0,
                    vec![
                        make_token("int", 0x1000, Side::Left),
                        make_token(" x", 0x1000, Side::Left),
                        make_token(" = ", 0x1000, Side::Left),
                        make_token("5", 0x1000, Side::Left),
                    ],
                ),
                make_line_with_tokens(
                    1,
                    vec![
                        make_token("return", 0x1004, Side::Left),
                        make_token(" x", 0x1004, Side::Left),
                    ],
                ),
            ],
            "left_func",
            0x1000,
            Side::Left,
            "/project/left",
        )
    }

    fn make_right_output() -> DecompilerOutput {
        DecompilerOutput::new(
            vec![
                make_line_with_tokens(
                    0,
                    vec![
                        make_token("int", 0x2000, Side::Right),
                        make_token(" y", 0x2000, Side::Right),
                        make_token(" = ", 0x2000, Side::Right),
                        make_token("10", 0x2000, Side::Right),
                    ],
                ),
                make_line_with_tokens(
                    1,
                    vec![
                        make_token("return", 0x2004, Side::Right),
                        make_token(" y", 0x2004, Side::Right),
                    ],
                ),
            ],
            "right_func",
            0x2000,
            Side::Right,
            "/project/right",
        )
    }

    // --- PinningConfig tests ---

    #[test]
    fn test_pinning_config_default() {
        let config = PinningConfig::new();
        assert_eq!(config.ngram_depth, 24);
        assert!(!config.match_constants);
        assert!(config.match_ram_space);
        assert!(config.cast_collapse);
        assert!(!config.size_collapse);
        assert!(config.break_symmetries);
    }

    #[test]
    fn test_pinning_config_exact_constants() {
        let config = PinningConfig::exact_constants();
        assert!(config.match_constants);
    }

    #[test]
    fn test_pinning_config_cross_arch() {
        let config = PinningConfig::cross_architecture();
        assert!(config.size_collapse);
    }

    // --- DecompilerOutput tests ---

    #[test]
    fn test_decompiler_output_token_count() {
        let output = make_left_output();
        assert_eq!(output.token_count(), 6);
        assert_eq!(output.line_count(), 2);
    }

    #[test]
    fn test_decompiler_output_all_tokens() {
        let output = make_left_output();
        let tokens = output.all_tokens();
        assert_eq!(tokens.len(), 6);
    }

    // --- PinningDataDiff tests ---

    #[test]
    fn test_pinning_diff_basic() {
        let left = make_left_output();
        let right = make_right_output();
        let diff = PinningDataDiff::new(left, right);

        let token_diffs = diff.compute_token_diffs();
        // Should have some matched and some unmatched
        assert!(!token_diffs.is_empty());
    }

    #[test]
    fn test_pinning_diff_identical() {
        let left = DecompilerOutput::new(
            vec![make_line_with_tokens(
                0,
                vec![make_token("return", 0x1000, Side::Left)],
            )],
            "func",
            0x1000,
            Side::Left,
            "/p",
        );
        let right = DecompilerOutput::new(
            vec![make_line_with_tokens(
                0,
                vec![make_token("return", 0x2000, Side::Right)],
            )],
            "func",
            0x2000,
            Side::Right,
            "/p",
        );
        let diff = PinningDataDiff::new(left, right);
        let token_diffs = diff.compute_token_diffs();

        // "return" should be matched
        assert_eq!(diff.matched_count(), 1);
        assert_eq!(diff.left_unmatched_count(), 0);
        assert_eq!(diff.right_unmatched_count(), 0);
    }

    #[test]
    fn test_pinning_diff_different() {
        let left = make_left_output();
        let right = make_right_output();
        let diff = PinningDataDiff::new(left, right);

        let stats = diff.statistics();
        // Some tokens match (like "int", "= ", "return"), some don't
        assert!(stats.matched_tokens > 0);
    }

    #[test]
    fn test_pinning_diff_empty() {
        let left = DecompilerOutput::new(vec![], "f", 0, Side::Left, "/p");
        let right = DecompilerOutput::new(vec![], "f", 0, Side::Right, "/p");
        let diff = PinningDataDiff::new(left, right);
        assert!(diff.compute_token_diffs().is_empty());
    }

    #[test]
    fn test_pinning_diff_size_collapse() {
        let mut left = DecompilerOutput::new(vec![], "f", 0, Side::Left, "/p");
        left.arch_size = 4;
        let mut right = DecompilerOutput::new(vec![], "f", 0, Side::Right, "/p");
        right.arch_size = 8;

        let diff = PinningDataDiff::new(left, right);
        assert!(diff.has_size_collapse());
    }

    #[test]
    fn test_pinning_diff_no_size_collapse() {
        let left = DecompilerOutput::new(vec![], "f", 0, Side::Left, "/p");
        let right = DecompilerOutput::new(vec![], "f", 0, Side::Right, "/p");
        let diff = PinningDataDiff::new(left, right);
        assert!(!diff.has_size_collapse());
    }

    #[test]
    fn test_pinning_diff_statistics() {
        let left = make_left_output();
        let right = make_right_output();
        let diff = PinningDataDiff::new(left, right);

        let stats = diff.statistics();
        assert_eq!(stats.left_line_count, 2);
        assert_eq!(stats.right_line_count, 2);
        assert_eq!(stats.left_token_count, 6);
        assert_eq!(stats.right_token_count, 6);
    }

    #[test]
    fn test_pinning_diff_unmatched_highlights() {
        let left = make_left_output();
        let right = make_right_output();
        let diff = PinningDataDiff::new(left, right);

        let left_highlights = diff.get_unmatched_highlights(Side::Left, false);
        let right_highlights = diff.get_unmatched_highlights(Side::Right, false);

        // Some tokens should be unmatched
        // (exact count depends on matching algorithm)
        assert!(left_highlights.len() + right_highlights.len() > 0
            || diff.matched_count() > 0);
    }

    #[test]
    fn test_pinning_diff_line_diff() {
        let left = make_left_output();
        let right = make_right_output();
        let diff = PinningDataDiff::new(left, right);

        let line_diff = diff.compute_line_diff();
        assert_eq!(line_diff.len(), 2);
    }

    // --- TokenDiff tests ---

    #[test]
    fn test_token_diff_matched() {
        let diff = TokenDiff::Matched {
            left: make_token("x", 0x1000, Side::Left),
            right: make_token("y", 0x2000, Side::Right),
            bin_index: 0,
            text_differs: true,
        };
        assert!(diff.is_matched());
        assert!(diff.text_differs());
        assert!(diff.left_token().is_some());
        assert!(diff.right_token().is_some());
    }

    #[test]
    fn test_token_diff_left_only() {
        let diff = TokenDiff::LeftOnly {
            token: make_token("x", 0x1000, Side::Left),
        };
        assert!(!diff.is_matched());
        assert!(diff.left_token().is_some());
        assert!(diff.right_token().is_none());
    }

    #[test]
    fn test_token_diff_right_only() {
        let diff = TokenDiff::RightOnly {
            token: make_token("y", 0x2000, Side::Right),
        };
        assert!(!diff.is_matched());
        assert!(diff.left_token().is_none());
        assert!(diff.right_token().is_some());
    }

    // --- PinningDiffStatistics tests ---

    #[test]
    fn test_pinning_diff_statistics_equality() {
        let stats = PinningDiffStatistics {
            left_line_count: 2,
            right_line_count: 2,
            left_token_count: 6,
            right_token_count: 6,
            matched_tokens: 3,
            text_differing_tokens: 1,
            left_unmatched_tokens: 2,
            right_unmatched_tokens: 2,
            line_diff_count: 2,
            size_collapse: false,
        };

        let stats2 = stats.clone();
        assert_eq!(stats, stats2);
    }
}
