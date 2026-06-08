//! Decompiler output comparison and diff highlighting.
//!
//! Ported from Ghidra's `ghidra.features.codecompare.decompile` Java package.
//!
//! This module handles comparing the decompiled output of two functions,
//! computing token-level differences, and providing highlighting information
//! for a side-by-side code comparison view.
//!
//! # Submodules
//!
//! - [`action_context`] -- action context for the dual decompiler view
//! - [`decompiler_options`] -- configurable highlight colors for decompiler comparison
//! - [`highlight_controller`] -- diff highlight controller with token bin tracking
//! - [`scroll_coordinator`] -- synchronized scrolling between two decompiler panels
//! - [`token_pair`] -- matched token pairs from the Pinning algorithm
//!
//! # Key types
//!
//! - [`DecompileDataDiff`] -- the main diff engine for decompiler output
//! - [`DiffLine`] -- a single line in the diff
//! - [`HighlightInfo`] -- highlighting information for matched/mismatched tokens

pub mod action_context;
pub mod c_display;
pub mod callee_tokens_action;
pub mod data_diff_engine;
pub mod decompiler_comparison_view;
pub mod decompiler_options;
pub mod determine_differences_task;
pub mod find_action;
pub mod highlight_controller;
pub mod matched_tokens_action;
pub mod scroll_coordinator;
pub mod token_pair;

use super::graphanalysis::{DecompilerToken, Side};

/// A single line of decompiled code.
#[derive(Debug, Clone)]
pub struct DecompiledLine {
    /// The line number (0-based).
    pub line_number: usize,
    /// The tokens on this line.
    pub tokens: Vec<DecompilerToken>,
    /// The indentation level.
    pub indent: usize,
    /// The source address range this line corresponds to.
    pub address_range: Option<(u64, u64)>,
}

impl DecompiledLine {
    /// Create a new decompiled line.
    pub fn new(line_number: usize, tokens: Vec<DecompilerToken>, indent: usize) -> Self {
        Self {
            line_number,
            tokens,
            indent,
            address_range: None,
        }
    }

    /// Get the full text of this line.
    pub fn text(&self) -> String {
        let mut result = "  ".repeat(self.indent);
        for token in &self.tokens {
            result.push_str(&token.text);
        }
        result
    }
}

/// Highlighting information for a token in the diff view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighlightKind {
    /// No highlighting (token is unique to this side).
    None,
    /// Token is part of a matched pair (same structural role).
    Matched,
    /// Token's structural role differs from its pair.
    Changed,
    /// Token has no pair on the other side.
    Unmatched,
}

/// Highlight information for a range of text.
#[derive(Debug, Clone)]
pub struct HighlightInfo {
    /// The kind of highlighting.
    pub kind: HighlightKind,
    /// Start column (inclusive).
    pub start_col: usize,
    /// End column (exclusive).
    pub end_col: usize,
    /// Optional tooltip text.
    pub tooltip: Option<String>,
}

impl HighlightInfo {
    /// Create a highlight with no tooltip.
    pub fn new(kind: HighlightKind, start_col: usize, end_col: usize) -> Self {
        Self {
            kind,
            start_col,
            end_col,
            tooltip: None,
        }
    }

    /// Create a highlight with a tooltip.
    pub fn with_tooltip(
        kind: HighlightKind,
        start_col: usize,
        end_col: usize,
        tooltip: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            start_col,
            end_col,
            tooltip: Some(tooltip.into()),
        }
    }
}

/// A difference between the two decompiled functions.
#[derive(Debug, Clone)]
pub struct DiffLine {
    /// The line on the left side (None if line was added on right).
    pub left: Option<DecompiledLine>,
    /// The line on the right side (None if line was removed from left).
    pub right: Option<DecompiledLine>,
    /// Highlights for the left side.
    pub left_highlights: Vec<HighlightInfo>,
    /// Highlights for the right side.
    pub right_highlights: Vec<HighlightInfo>,
}

impl DiffLine {
    /// Both sides have the same line.
    pub fn equal(
        left: DecompiledLine,
        right: DecompiledLine,
    ) -> Self {
        Self {
            left: Some(left),
            right: Some(right),
            left_highlights: Vec::new(),
            right_highlights: Vec::new(),
        }
    }

    /// Both sides have lines, but they differ.
    pub fn changed(
        left: DecompiledLine,
        right: DecompiledLine,
        left_highlights: Vec<HighlightInfo>,
        right_highlights: Vec<HighlightInfo>,
    ) -> Self {
        Self {
            left: Some(left),
            right: Some(right),
            left_highlights,
            right_highlights,
        }
    }

    /// Line exists only on the left.
    pub fn left_only(left: DecompiledLine) -> Self {
        Self {
            left: Some(left),
            right: None,
            left_highlights: vec![HighlightInfo::new(HighlightKind::Unmatched, 0, 0)],
            right_highlights: Vec::new(),
        }
    }

    /// Line exists only on the right.
    pub fn right_only(right: DecompiledLine) -> Self {
        Self {
            left: None,
            right: Some(right),
            left_highlights: Vec::new(),
            right_highlights: vec![HighlightInfo::new(HighlightKind::Unmatched, 0, 0)],
        }
    }
}

/// The main diff engine for comparing decompiler output.
///
/// Takes two sets of decompiled lines and matched token bins, then
/// computes a line-by-line diff with highlighting information.
///
/// Ported from Ghidra's `DecompileDataDiff` Java class.
pub struct DecompileDataDiff {
    left_lines: Vec<DecompiledLine>,
    right_lines: Vec<DecompiledLine>,
    /// Whether the two functions have different architecture sizes.
    size_mismatch: bool,
}

impl DecompileDataDiff {
    /// Create a new diff from two sets of decompiled lines.
    pub fn new(
        left_lines: Vec<DecompiledLine>,
        right_lines: Vec<DecompiledLine>,
    ) -> Self {
        Self {
            left_lines,
            right_lines,
            size_mismatch: false,
        }
    }

    /// Set whether the two functions have different architecture sizes.
    pub fn with_size_mismatch(mut self, mismatch: bool) -> Self {
        self.size_mismatch = mismatch;
        self
    }

    /// Compute the diff between the two sets of lines.
    ///
    /// Uses a simple line-by-line comparison. Lines with the same text
    /// are considered equal; others are considered changed.
    pub fn compute_diff(&self) -> Vec<DiffLine> {
        let mut result = Vec::new();
        let max_lines = self.left_lines.len().max(self.right_lines.len());

        for i in 0..max_lines {
            let left = self.left_lines.get(i);
            let right = self.right_lines.get(i);

            match (left, right) {
                (Some(l), Some(r)) => {
                    if l.text() == r.text() {
                        result.push(DiffLine::equal(l.clone(), r.clone()));
                    } else {
                        let lh = self.compute_line_highlights(l, r, Side::Left);
                        let rh = self.compute_line_highlights(r, l, Side::Right);
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

    /// Compute highlights for a line compared to its counterpart.
    fn compute_line_highlights(
        &self,
        line: &DecompiledLine,
        other: &DecompiledLine,
        _side: Side,
    ) -> Vec<HighlightInfo> {
        let mut highlights = Vec::new();
        let line_text = line.text();
        let other_text = other.text();

        if line_text == other_text {
            return highlights;
        }

        // Find the first differing column
        let min_len = line_text.len().min(other_text.len());
        let mut diff_start = min_len;
        for i in 0..min_len {
            if line_text.as_bytes()[i] != other_text.as_bytes()[i] {
                diff_start = i;
                break;
            }
        }

        if diff_start < line_text.len() {
            highlights.push(HighlightInfo::new(
                HighlightKind::Changed,
                diff_start,
                line_text.len(),
            ));
        }

        highlights
    }

    /// Get the left lines.
    pub fn left_lines(&self) -> &[DecompiledLine] {
        &self.left_lines
    }

    /// Get the right lines.
    pub fn right_lines(&self) -> &[DecompiledLine] {
        &self.right_lines
    }

    /// Whether the two functions have different architecture sizes.
    pub fn has_size_mismatch(&self) -> bool {
        self.size_mismatch
    }

    /// Compute statistics about the diff.
    pub fn statistics(&self) -> DiffStatistics {
        let diff = self.compute_diff();
        let mut equal = 0;
        let mut changed = 0;
        let mut left_only = 0;
        let mut right_only = 0;

        for line in &diff {
            match (&line.left, &line.right) {
                (Some(_), Some(_)) => {
                    if line.left_highlights.is_empty() && line.right_highlights.is_empty() {
                        equal += 1;
                    } else {
                        changed += 1;
                    }
                }
                (Some(_), None) => left_only += 1,
                (None, Some(_)) => right_only += 1,
                (None, None) => {}
            }
        }

        DiffStatistics {
            total_lines: diff.len(),
            equal_lines: equal,
            changed_lines: changed,
            left_only_lines: left_only,
            right_only_lines: right_only,
        }
    }
}

/// Statistics about a diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffStatistics {
    /// Total number of diff lines.
    pub total_lines: usize,
    /// Number of equal lines.
    pub equal_lines: usize,
    /// Number of changed lines.
    pub changed_lines: usize,
    /// Lines only on the left.
    pub left_only_lines: usize,
    /// Lines only on the right.
    pub right_only_lines: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::graphanalysis::TokenKind;

    fn make_line(num: usize, text: &str) -> DecompiledLine {
        DecompiledLine::new(
            num,
            vec![DecompilerToken {
                text: text.to_string(),
                kind: TokenKind::Other,
                address: 0x1000 + num as u64 * 4,
                side: Side::Left,
            }],
            0,
        )
    }

    #[test]
    fn test_diff_equal_lines() {
        let left = vec![make_line(0, "int x = 5;")];
        let right = vec![make_line(0, "int x = 5;")];
        let diff_engine = DecompileDataDiff::new(left, right);
        let diff = diff_engine.compute_diff();
        assert_eq!(diff.len(), 1);
        assert!(diff[0].left_highlights.is_empty());
        assert!(diff[0].right_highlights.is_empty());
    }

    #[test]
    fn test_diff_changed_lines() {
        let left = vec![make_line(0, "int x = 5;")];
        let right = vec![make_line(0, "int x = 10;")];
        let diff_engine = DecompileDataDiff::new(left, right);
        let diff = diff_engine.compute_diff();
        assert_eq!(diff.len(), 1);
        assert!(!diff[0].left_highlights.is_empty() || !diff[0].right_highlights.is_empty());
    }

    #[test]
    fn test_diff_left_only() {
        let left = vec![make_line(0, "extra line")];
        let right = vec![];
        let diff_engine = DecompileDataDiff::new(left, right);
        let diff = diff_engine.compute_diff();
        assert_eq!(diff.len(), 1);
        assert!(diff[0].right.is_none());
    }

    #[test]
    fn test_diff_right_only() {
        let left = vec![];
        let right = vec![make_line(0, "extra line")];
        let diff_engine = DecompileDataDiff::new(left, right);
        let diff = diff_engine.compute_diff();
        assert_eq!(diff.len(), 1);
        assert!(diff[0].left.is_none());
    }

    #[test]
    fn test_diff_statistics() {
        let left = vec![
            make_line(0, "same"),
            make_line(1, "left_only"),
            make_line(2, "changed_left"),
        ];
        let right = vec![
            make_line(0, "same"),
            make_line(1, "changed_right"),
        ];
        let diff_engine = DecompileDataDiff::new(left, right);
        let stats = diff_engine.statistics();
        assert_eq!(stats.total_lines, 3);
        assert_eq!(stats.equal_lines, 1);
        assert_eq!(stats.changed_lines, 1);
        assert_eq!(stats.left_only_lines, 1);
    }

    #[test]
    fn test_decompiled_line_text() {
        let line = DecompiledLine::new(
            0,
            vec![
                DecompilerToken {
                    text: "int".to_string(),
                    kind: TokenKind::Keyword,
                    address: 0x1000,
                    side: Side::Left,
                },
                DecompilerToken {
                    text: " x".to_string(),
                    kind: TokenKind::Variable,
                    address: 0x1000,
                    side: Side::Left,
                },
            ],
            2,
        );
        assert_eq!(line.text(), "    int x");
    }

    #[test]
    fn test_highlight_info() {
        let h = HighlightInfo::with_tooltip(
            HighlightKind::Changed,
            5,
            10,
            "value changed",
        );
        assert_eq!(h.kind, HighlightKind::Changed);
        assert_eq!(h.start_col, 5);
        assert_eq!(h.end_col, 10);
        assert_eq!(h.tooltip.as_deref(), Some("value changed"));
    }

    #[test]
    fn test_size_mismatch() {
        let diff = DecompileDataDiff::new(vec![], vec![]).with_size_mismatch(true);
        assert!(diff.has_size_mismatch());
    }

    #[test]
    fn test_diff_multi_line() {
        let left = vec![
            make_line(0, "line1"),
            make_line(1, "line2"),
            make_line(2, "line3"),
        ];
        let right = vec![
            make_line(0, "line1"),
            make_line(1, "line2_modified"),
            make_line(2, "line3"),
            make_line(3, "line4_new"),
        ];
        let diff_engine = DecompileDataDiff::new(left, right);
        let diff = diff_engine.compute_diff();
        assert_eq!(diff.len(), 4);
    }
}
