//! Synchronized scrolling between two decompiler panels.
//!
//! Ported from Ghidra's `DualDecompilerScrollCoordinator` Java class in
//! `ghidra.features.codecompare.decompile`.
//!
//! When comparing two decompiled functions side-by-side, the scroll
//! coordinator ensures that corresponding lines stay visually aligned.
//! It maintains a bidirectional mapping between left and right line
//! numbers (the "line pairing") and uses it to scroll the opposite
//! panel when one panel's cursor or viewport changes.
//!
//! The line pairing is computed from matched token bins: when a token
//! bin on the left is matched with a bin on the right, the lines
//! containing those tokens are paired together.
//!
//! # Key types
//!
//! - [`ScrollCoordinator`] -- the main coordinator
//! - [`LinePairing`] -- bidirectional line number mapping
//! - [`ViewerPosition`] -- a viewport position (line index + offsets)

use std::collections::BTreeMap;

/// A viewport position in a decompiler panel.
///
/// This corresponds to Ghidra's `ViewerPosition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerPosition {
    /// The line index (0-based) at the top of the viewport.
    pub line_index: usize,
    /// Horizontal scroll offset in pixels.
    pub x_offset: i32,
    /// Vertical scroll offset in pixels.
    pub y_offset: i32,
}

impl ViewerPosition {
    /// Create a new viewer position.
    pub fn new(line_index: usize, x_offset: i32, y_offset: i32) -> Self {
        Self {
            line_index,
            x_offset,
            y_offset,
        }
    }

    /// Create a position at the beginning (line 0, no offsets).
    pub fn origin() -> Self {
        Self {
            line_index: 0,
            x_offset: 0,
            y_offset: 0,
        }
    }
}

impl Default for ViewerPosition {
    fn default() -> Self {
        Self::origin()
    }
}

/// A line of decompiled code in a panel.
///
/// Each line has a number, contains a function name token (if present),
/// and has associated matched line info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompiledPanelLine {
    /// The line number (0-based).
    pub line_number: usize,
    /// The full text of the line.
    pub text: String,
    /// Whether this line contains a function name token.
    pub has_function_name: bool,
}

impl DecompiledPanelLine {
    /// Create a new panel line.
    pub fn new(line_number: usize, text: impl Into<String>, has_function_name: bool) -> Self {
        Self {
            line_number,
            text: text.into(),
            has_function_name,
        }
    }
}

/// A pair of matched line numbers from the left and right panels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LineMatch {
    /// The left panel line number.
    pub left_line: usize,
    /// The right panel line number.
    pub right_line: usize,
}

impl LineMatch {
    /// Create a new line match.
    pub fn new(left_line: usize, right_line: usize) -> Self {
        Self {
            left_line,
            right_line,
        }
    }
}

/// Bidirectional mapping between left and right line numbers.
///
/// This data structure supports efficient lookups in both directions:
/// - Given a left line number, find the paired right line number
/// - Given a right line number, find the paired left line number
///
/// Ported from the `leftToRightLineNumberPairing` BidiMap in the Java code.
#[derive(Debug, Clone, Default)]
pub struct LinePairing {
    /// Maps left line number -> right line number.
    left_to_right: BTreeMap<usize, usize>,
    /// Maps right line number -> left line number.
    right_to_left: BTreeMap<usize, usize>,
}

impl LinePairing {
    /// Create a new empty line pairing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a line pairing.
    ///
    /// If either line number is already paired, the old pairing is replaced.
    pub fn add_pair(&mut self, left_line: usize, right_line: usize) {
        // Remove any existing pairings for these line numbers
        if let Some(old_right) = self.left_to_right.get(&left_line).copied() {
            self.right_to_left.remove(&old_right);
        }
        if let Some(old_left) = self.right_to_left.get(&right_line).copied() {
            self.left_to_right.remove(&old_left);
        }

        self.left_to_right.insert(left_line, right_line);
        self.right_to_left.insert(right_line, left_line);
    }

    /// Get the right line number paired with the given left line number.
    pub fn get_right(&self, left_line: usize) -> Option<usize> {
        self.left_to_right.get(&left_line).copied()
    }

    /// Get the left line number paired with the given right line number.
    pub fn get_left(&self, right_line: usize) -> Option<usize> {
        self.right_to_left.get(&right_line).copied()
    }

    /// Check if a left line number has a pairing.
    pub fn has_left(&self, left_line: usize) -> bool {
        self.left_to_right.contains_key(&left_line)
    }

    /// Check if a right line number has a pairing.
    pub fn has_right(&self, right_line: usize) -> bool {
        self.right_to_left.contains_key(&right_line)
    }

    /// Get the number of pairings.
    pub fn len(&self) -> usize {
        self.left_to_right.len()
    }

    /// Check if the pairing is empty.
    pub fn is_empty(&self) -> bool {
        self.left_to_right.is_empty()
    }

    /// Clear all pairings.
    pub fn clear(&mut self) {
        self.left_to_right.clear();
        self.right_to_left.clear();
    }

    /// Get all pairings as a vector of LineMatch.
    pub fn all_pairs(&self) -> Vec<LineMatch> {
        self.left_to_right
            .iter()
            .map(|(&left, &right)| LineMatch::new(left, right))
            .collect()
    }

    /// Search for the nearest paired right line to a given left line.
    ///
    /// If the given left line is not directly paired, searches nearby
    /// lines (alternating up and down) until a pairing is found.
    ///
    /// Returns the matching LineMatch if found.
    pub fn search_left_for_pair(&self, left_line: usize, max_left_line: usize) -> Option<LineMatch> {
        // Direct match
        if let Some(right) = self.get_right(left_line) {
            return Some(LineMatch::new(left_line, right));
        }

        // Search nearby lines
        let mut previous = if left_line > 0 { left_line - 1 } else { 0 };
        let mut next = left_line + 1;
        let limit = max_left_line;

        while previous > 0 || next <= limit {
            if previous > 0 {
                if let Some(right) = self.get_right(previous) {
                    return Some(LineMatch::new(previous, right));
                }
                previous -= 1;
            }
            if next <= limit {
                if let Some(right) = self.get_right(next) {
                    return Some(LineMatch::new(next, right));
                }
                next += 1;
            }
        }

        None
    }

    /// Search for the nearest paired left line to a given right line.
    ///
    /// If the given right line is not directly paired, searches nearby
    /// lines (alternating up and down) until a pairing is found.
    ///
    /// Returns the matching LineMatch if found.
    pub fn search_right_for_pair(&self, right_line: usize, max_right_line: usize) -> Option<LineMatch> {
        // Direct match
        if let Some(left) = self.get_left(right_line) {
            return Some(LineMatch::new(left, right_line));
        }

        // Search nearby lines
        let mut previous = if right_line > 0 { right_line - 1 } else { 0 };
        let mut next = right_line + 1;
        let limit = max_right_line;

        while previous > 0 || next <= limit {
            if previous > 0 {
                if let Some(left) = self.get_left(previous) {
                    return Some(LineMatch::new(left, previous));
                }
                previous -= 1;
            }
            if next <= limit {
                if let Some(left) = self.get_left(next) {
                    return Some(LineMatch::new(left, next));
                }
                next += 1;
            }
        }

        None
    }
}

/// A matched token bin used for computing line pairings.
///
/// Each bin has a match index that links it to a bin on the other side.
/// The bin's first token's line number is used for pairing.
#[derive(Debug, Clone)]
pub struct ScrollTokenBin {
    /// The side this bin belongs to.
    pub is_left: bool,
    /// The line number of the first token in this bin.
    pub line_number: usize,
    /// The index of the matched bin on the other side.
    pub match_index: Option<usize>,
}

impl ScrollTokenBin {
    /// Create a new scroll token bin.
    pub fn new(is_left: bool, line_number: usize, match_index: Option<usize>) -> Self {
        Self {
            is_left,
            line_number,
            match_index,
        }
    }

    /// Check if this bin is matched with a bin on the other side.
    pub fn is_matched(&self) -> bool {
        self.match_index.is_some()
    }
}

/// Trait for a decompiler panel that provides viewport information.
pub trait DecompilerPanelProvider: Send + Sync {
    /// Get the current viewport position.
    fn get_viewer_position(&self) -> ViewerPosition;

    /// Get the total number of lines.
    fn line_count(&self) -> usize;

    /// Get a specific line by number (0-based).
    fn get_line(&self, line_number: usize) -> Option<DecompiledPanelLine>;
}

/// The scroll coordinator for a dual decompiler comparison view.
///
/// Manages synchronized scrolling between two decompiler panels by
/// maintaining a line pairing computed from matched token bins.
///
/// Ported from Ghidra's `DualDecompilerScrollCoordinator` Java class.
///
/// Also available as [`DualDecompilerScrollCoordinator`] for compatibility
/// with the original Java class name.
pub struct ScrollCoordinator {
    /// The line pairing between left and right panels.
    line_pairing: LinePairing,
    /// The locked left line number (used for scroll synchronization).
    locked_left_line: usize,
    /// The locked right line number (used for scroll synchronization).
    locked_right_line: usize,
    /// Whether the coordinator is currently updating (to prevent recursion).
    updating: bool,
    /// Whether constant values should be matched exactly.
    match_constants_exactly: bool,
    /// The last token bins used for line pairing.
    last_bins: Vec<ScrollTokenBin>,
}

impl ScrollCoordinator {
    /// Create a new scroll coordinator.
    pub fn new() -> Self {
        Self {
            line_pairing: LinePairing::new(),
            locked_left_line: 0,
            locked_right_line: 0,
            updating: false,
            match_constants_exactly: false,
            last_bins: Vec::new(),
        }
    }

    /// Set whether constant values should be matched exactly.
    pub fn set_match_constants_exactly(&mut self, exact: bool) {
        self.match_constants_exactly = exact;
    }

    /// Get whether constant values are matched exactly.
    pub fn match_constants_exactly(&self) -> bool {
        self.match_constants_exactly
    }

    /// Compute the line pairing from a set of matched token bins.
    ///
    /// This clears any existing pairing and builds a new one based on
    /// the matched bins. For each pair of matched bins (one from the
    /// left, one from the right), the lines containing the first token
    /// of each bin are paired together.
    pub fn compute_line_pairing(&mut self, bins: &[ScrollTokenBin]) {
        self.line_pairing.clear();
        self.last_bins = bins.to_vec();

        // Group bins by match index
        let mut left_by_match: BTreeMap<usize, &ScrollTokenBin> = BTreeMap::new();
        let mut right_by_match: BTreeMap<usize, &ScrollTokenBin> = BTreeMap::new();

        for bin in bins {
            if let Some(match_idx) = bin.match_index {
                if bin.is_left {
                    left_by_match.insert(match_idx, bin);
                } else {
                    right_by_match.insert(match_idx, bin);
                }
            }
        }

        // Pair lines from matched bins
        for (&match_idx, left_bin) in &left_by_match {
            if let Some(right_bin) = right_by_match.get(&match_idx) {
                self.line_pairing
                    .add_pair(left_bin.line_number, right_bin.line_number);
            }
        }
    }

    /// Lock the function signature lines (line 0 on both sides).
    ///
    /// This is called when first displaying the comparison to establish
    /// an initial scroll anchor.
    pub fn lock_function_signature_lines(
        &mut self,
        left_lines: &[DecompiledPanelLine],
        right_lines: &[DecompiledPanelLine],
    ) {
        let left_line = self.find_function_signature_line(left_lines);
        let right_line = self.find_function_signature_line(right_lines);

        let left_num = left_line.unwrap_or(0);
        let right_num = right_line.unwrap_or(0);

        self.set_locked_line_numbers(left_num, right_num);
    }

    /// Find the line containing a function name token.
    fn find_function_signature_line(&self, lines: &[DecompiledPanelLine]) -> Option<usize> {
        lines
            .iter()
            .find(|line| line.has_function_name)
            .map(|line| line.line_number)
    }

    /// Set the locked line numbers directly.
    pub fn set_locked_line_numbers(&mut self, left_line: usize, right_line: usize) {
        self.locked_left_line = left_line;
        self.locked_right_line = right_line;
    }

    /// Get the locked left line number.
    pub fn locked_left_line(&self) -> usize {
        self.locked_left_line
    }

    /// Get the locked right line number.
    pub fn locked_right_line(&self) -> usize {
        self.locked_right_line
    }

    /// Get the current line pairing.
    pub fn line_pairing(&self) -> &LinePairing {
        &self.line_pairing
    }

    /// Handle the left panel cursor moving to a new location.
    ///
    /// Returns the new locked line numbers if a pairing was found.
    pub fn left_location_changed(
        &mut self,
        left_line_number: usize,
        max_left_line: usize,
    ) -> Option<(usize, usize)> {
        if self.updating {
            return None;
        }
        self.updating = true;

        let result = if let Some(line_match) =
            self.line_pairing.search_left_for_pair(left_line_number, max_left_line)
        {
            self.set_locked_line_numbers(line_match.left_line, line_match.right_line);
            Some((line_match.left_line, line_match.right_line))
        } else {
            None
        };

        self.updating = false;
        result
    }

    /// Handle the right panel cursor moving to a new location.
    ///
    /// Returns the new locked line numbers if a pairing was found.
    pub fn right_location_changed(
        &mut self,
        right_line_number: usize,
        max_right_line: usize,
    ) -> Option<(usize, usize)> {
        if self.updating {
            return None;
        }
        self.updating = true;

        let result = if let Some(line_match) =
            self.line_pairing.search_right_for_pair(right_line_number, max_right_line)
        {
            self.set_locked_line_numbers(line_match.left_line, line_match.right_line);
            Some((line_match.left_line, line_match.right_line))
        } else {
            None
        };

        self.updating = false;
        result
    }

    /// Replace the decompile data and recompute the line pairing.
    ///
    /// This is the main update method called when the decompiled output
    /// changes. It locks the function signature lines and recomputes
    /// the line pairing from the new token bins.
    pub fn replace_decompile_data(
        &mut self,
        left_lines: &[DecompiledPanelLine],
        right_lines: &[DecompiledPanelLine],
        bins: &[ScrollTokenBin],
    ) {
        self.lock_function_signature_lines(left_lines, right_lines);
        self.compute_line_pairing(bins);
    }

    /// Clear the line pairing.
    pub fn clear_line_pairing(&mut self) {
        self.line_pairing.clear();
    }

    /// Get the last token bins used for line pairing.
    pub fn last_bins(&self) -> &[ScrollTokenBin] {
        &self.last_bins
    }

    /// Check if the coordinator is currently updating (to prevent recursion).
    pub fn is_updating(&self) -> bool {
        self.updating
    }
}

impl Default for ScrollCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for [`ScrollCoordinator`] matching the original Java class name.
pub type DualDecompilerScrollCoordinator = ScrollCoordinator;

#[cfg(test)]
mod tests {
    use super::*;

    // --- ViewerPosition tests ---

    #[test]
    fn test_viewer_position_new() {
        let pos = ViewerPosition::new(5, 10, 20);
        assert_eq!(pos.line_index, 5);
        assert_eq!(pos.x_offset, 10);
        assert_eq!(pos.y_offset, 20);
    }

    #[test]
    fn test_viewer_position_origin() {
        let pos = ViewerPosition::origin();
        assert_eq!(pos.line_index, 0);
        assert_eq!(pos.x_offset, 0);
        assert_eq!(pos.y_offset, 0);
    }

    #[test]
    fn test_viewer_position_default() {
        let pos = ViewerPosition::default();
        assert_eq!(pos, ViewerPosition::origin());
    }

    #[test]
    fn test_viewer_position_eq() {
        let p1 = ViewerPosition::new(1, 2, 3);
        let p2 = ViewerPosition::new(1, 2, 3);
        let p3 = ViewerPosition::new(1, 2, 4);
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
    }

    // --- DecompiledPanelLine tests ---

    #[test]
    fn test_panel_line_new() {
        let line = DecompiledPanelLine::new(0, "int main() {", true);
        assert_eq!(line.line_number, 0);
        assert_eq!(line.text, "int main() {");
        assert!(line.has_function_name);
    }

    #[test]
    fn test_panel_line_no_function_name() {
        let line = DecompiledPanelLine::new(5, "  return 0;", false);
        assert!(!line.has_function_name);
    }

    // --- LineMatch tests ---

    #[test]
    fn test_line_match_new() {
        let m = LineMatch::new(3, 5);
        assert_eq!(m.left_line, 3);
        assert_eq!(m.right_line, 5);
    }

    #[test]
    fn test_line_match_eq() {
        let m1 = LineMatch::new(1, 2);
        let m2 = LineMatch::new(1, 2);
        let m3 = LineMatch::new(1, 3);
        assert_eq!(m1, m2);
        assert_ne!(m1, m3);
    }

    // --- LinePairing tests ---

    #[test]
    fn test_line_pairing_new() {
        let pairing = LinePairing::new();
        assert!(pairing.is_empty());
        assert_eq!(pairing.len(), 0);
    }

    #[test]
    fn test_line_pairing_default() {
        let pairing = LinePairing::default();
        assert!(pairing.is_empty());
    }

    #[test]
    fn test_line_pairing_add_and_get() {
        let mut pairing = LinePairing::new();
        pairing.add_pair(1, 10);
        pairing.add_pair(2, 20);

        assert_eq!(pairing.get_right(1), Some(10));
        assert_eq!(pairing.get_right(2), Some(20));
        assert_eq!(pairing.get_left(10), Some(1));
        assert_eq!(pairing.get_left(20), Some(2));
        assert_eq!(pairing.len(), 2);
    }

    #[test]
    fn test_line_pairing_get_nonexistent() {
        let pairing = LinePairing::new();
        assert_eq!(pairing.get_right(1), None);
        assert_eq!(pairing.get_left(1), None);
    }

    #[test]
    fn test_line_pairing_has() {
        let mut pairing = LinePairing::new();
        pairing.add_pair(5, 15);

        assert!(pairing.has_left(5));
        assert!(!pairing.has_left(6));
        assert!(pairing.has_right(15));
        assert!(!pairing.has_right(16));
    }

    #[test]
    fn test_line_pairing_clear() {
        let mut pairing = LinePairing::new();
        pairing.add_pair(1, 10);
        pairing.add_pair(2, 20);

        pairing.clear();
        assert!(pairing.is_empty());
        assert_eq!(pairing.len(), 0);
    }

    #[test]
    fn test_line_pairing_all_pairs() {
        let mut pairing = LinePairing::new();
        pairing.add_pair(3, 30);
        pairing.add_pair(1, 10);
        pairing.add_pair(2, 20);

        let pairs = pairing.all_pairs();
        assert_eq!(pairs.len(), 3);
        // Should be sorted by left line number (BTreeMap order)
        assert_eq!(pairs[0], LineMatch::new(1, 10));
        assert_eq!(pairs[1], LineMatch::new(2, 20));
        assert_eq!(pairs[2], LineMatch::new(3, 30));
    }

    #[test]
    fn test_line_pairing_replace_pairing() {
        let mut pairing = LinePairing::new();
        pairing.add_pair(1, 10);
        assert_eq!(pairing.get_right(1), Some(10));

        // Replace: line 1 now pairs with line 15
        pairing.add_pair(1, 15);
        assert_eq!(pairing.get_right(1), Some(15));
        assert_eq!(pairing.get_left(15), Some(1));
        // Old right-side entry should be gone
        assert_eq!(pairing.get_left(10), None);
    }

    #[test]
    fn test_line_pairing_search_left_direct() {
        let mut pairing = LinePairing::new();
        pairing.add_pair(5, 50);

        let result = pairing.search_left_for_pair(5, 10);
        assert_eq!(result, Some(LineMatch::new(5, 50)));
    }

    #[test]
    fn test_line_pairing_search_left_nearby() {
        let mut pairing = LinePairing::new();
        pairing.add_pair(3, 30);

        // Search from line 5, should find line 3
        let result = pairing.search_left_for_pair(5, 10);
        assert_eq!(result, Some(LineMatch::new(3, 30)));
    }

    #[test]
    fn test_line_pairing_search_left_no_match() {
        let pairing = LinePairing::new();
        let result = pairing.search_left_for_pair(5, 10);
        assert_eq!(result, None);
    }

    #[test]
    fn test_line_pairing_search_right_direct() {
        let mut pairing = LinePairing::new();
        pairing.add_pair(5, 50);

        let result = pairing.search_right_for_pair(50, 100);
        assert_eq!(result, Some(LineMatch::new(5, 50)));
    }

    #[test]
    fn test_line_pairing_search_right_nearby() {
        let mut pairing = LinePairing::new();
        pairing.add_pair(5, 50);

        // Search from right line 52, should find right line 50
        let result = pairing.search_right_for_pair(52, 100);
        assert_eq!(result, Some(LineMatch::new(5, 50)));
    }

    #[test]
    fn test_line_pairing_search_right_no_match() {
        let pairing = LinePairing::new();
        let result = pairing.search_right_for_pair(50, 100);
        assert_eq!(result, None);
    }

    // --- ScrollTokenBin tests ---

    #[test]
    fn test_scroll_token_bin_new() {
        let bin = ScrollTokenBin::new(true, 5, Some(0));
        assert!(bin.is_left);
        assert_eq!(bin.line_number, 5);
        assert_eq!(bin.match_index, Some(0));
        assert!(bin.is_matched());
    }

    #[test]
    fn test_scroll_token_bin_unmatched() {
        let bin = ScrollTokenBin::new(false, 10, None);
        assert!(!bin.is_left);
        assert_eq!(bin.line_number, 10);
        assert!(!bin.is_matched());
    }

    // --- ScrollCoordinator tests ---

    #[test]
    fn test_coordinator_new() {
        let coord = ScrollCoordinator::new();
        assert!(coord.line_pairing().is_empty());
        assert_eq!(coord.locked_left_line(), 0);
        assert_eq!(coord.locked_right_line(), 0);
        assert!(!coord.is_updating());
        assert!(!coord.match_constants_exactly());
    }

    #[test]
    fn test_coordinator_default() {
        let coord = ScrollCoordinator::default();
        assert!(coord.line_pairing().is_empty());
    }

    #[test]
    fn test_coordinator_set_match_constants() {
        let mut coord = ScrollCoordinator::new();
        assert!(!coord.match_constants_exactly());

        coord.set_match_constants_exactly(true);
        assert!(coord.match_constants_exactly());

        coord.set_match_constants_exactly(false);
        assert!(!coord.match_constants_exactly());
    }

    #[test]
    fn test_coordinator_compute_line_pairing() {
        let mut coord = ScrollCoordinator::new();

        let bins = vec![
            ScrollTokenBin::new(true, 2, Some(0)),
            ScrollTokenBin::new(true, 5, Some(1)),
            ScrollTokenBin::new(false, 12, Some(0)),
            ScrollTokenBin::new(false, 15, Some(1)),
        ];

        coord.compute_line_pairing(&bins);

        assert_eq!(coord.line_pairing().len(), 2);
        assert_eq!(coord.line_pairing().get_right(2), Some(12));
        assert_eq!(coord.line_pairing().get_right(5), Some(15));
        assert_eq!(coord.line_pairing().get_left(12), Some(2));
        assert_eq!(coord.line_pairing().get_left(15), Some(5));
    }

    #[test]
    fn test_coordinator_compute_line_pairing_empty() {
        let mut coord = ScrollCoordinator::new();
        coord.compute_line_pairing(&[]);
        assert!(coord.line_pairing().is_empty());
    }

    #[test]
    fn test_coordinator_compute_line_pairing_unmatched() {
        let mut coord = ScrollCoordinator::new();

        let bins = vec![
            ScrollTokenBin::new(true, 2, Some(0)),
            ScrollTokenBin::new(true, 5, None), // unmatched
            ScrollTokenBin::new(false, 12, Some(0)),
        ];

        coord.compute_line_pairing(&bins);

        // Only the matched pair should be in the pairing
        assert_eq!(coord.line_pairing().len(), 1);
        assert_eq!(coord.line_pairing().get_right(2), Some(12));
    }

    #[test]
    fn test_coordinator_set_locked_line_numbers() {
        let mut coord = ScrollCoordinator::new();
        coord.set_locked_line_numbers(3, 13);
        assert_eq!(coord.locked_left_line(), 3);
        assert_eq!(coord.locked_right_line(), 13);
    }

    #[test]
    fn test_coordinator_lock_function_signature_lines() {
        let mut coord = ScrollCoordinator::new();

        let left_lines = vec![
            DecompiledPanelLine::new(0, "int main() {", true),
            DecompiledPanelLine::new(1, "  return 0;", false),
        ];
        let right_lines = vec![
            DecompiledPanelLine::new(0, "void main() {", true),
            DecompiledPanelLine::new(1, "  return;", false),
        ];

        coord.lock_function_signature_lines(&left_lines, &right_lines);
        assert_eq!(coord.locked_left_line(), 0);
        assert_eq!(coord.locked_right_line(), 0);
    }

    #[test]
    fn test_coordinator_lock_function_signature_lines_offset() {
        let mut coord = ScrollCoordinator::new();

        let left_lines = vec![
            DecompiledPanelLine::new(0, "// comment", false),
            DecompiledPanelLine::new(1, "int main() {", true),
            DecompiledPanelLine::new(2, "  return 0;", false),
        ];
        let right_lines = vec![
            DecompiledPanelLine::new(0, "void main() {", true),
            DecompiledPanelLine::new(1, "  return;", false),
        ];

        coord.lock_function_signature_lines(&left_lines, &right_lines);
        assert_eq!(coord.locked_left_line(), 1); // line 1 has function name
        assert_eq!(coord.locked_right_line(), 0); // line 0 has function name
    }

    #[test]
    fn test_coordinator_lock_function_signature_lines_no_function() {
        let mut coord = ScrollCoordinator::new();

        let left_lines = vec![
            DecompiledPanelLine::new(0, "// comment", false),
            DecompiledPanelLine::new(1, "  return 0;", false),
        ];
        let right_lines = vec![
            DecompiledPanelLine::new(0, "  return;", false),
        ];

        // Should default to line 0 when no function name found
        coord.lock_function_signature_lines(&left_lines, &right_lines);
        assert_eq!(coord.locked_left_line(), 0);
        assert_eq!(coord.locked_right_line(), 0);
    }

    #[test]
    fn test_coordinator_lock_function_signature_lines_empty() {
        let mut coord = ScrollCoordinator::new();
        coord.lock_function_signature_lines(&[], &[]);
        assert_eq!(coord.locked_left_line(), 0);
        assert_eq!(coord.locked_right_line(), 0);
    }

    #[test]
    fn test_coordinator_left_location_changed() {
        let mut coord = ScrollCoordinator::new();

        let bins = vec![
            ScrollTokenBin::new(true, 2, Some(0)),
            ScrollTokenBin::new(true, 5, Some(1)),
            ScrollTokenBin::new(false, 12, Some(0)),
            ScrollTokenBin::new(false, 15, Some(1)),
        ];
        coord.compute_line_pairing(&bins);

        // Move to left line 5, which pairs with right line 15
        let result = coord.left_location_changed(5, 10);
        assert_eq!(result, Some((5, 15)));
        assert_eq!(coord.locked_left_line(), 5);
        assert_eq!(coord.locked_right_line(), 15);
    }

    #[test]
    fn test_coordinator_left_location_changed_no_pairing() {
        let mut coord = ScrollCoordinator::new();
        let result = coord.left_location_changed(5, 10);
        assert_eq!(result, None);
    }

    #[test]
    fn test_coordinator_right_location_changed() {
        let mut coord = ScrollCoordinator::new();

        let bins = vec![
            ScrollTokenBin::new(true, 2, Some(0)),
            ScrollTokenBin::new(false, 12, Some(0)),
        ];
        coord.compute_line_pairing(&bins);

        // Move to right line 12, which pairs with left line 2
        let result = coord.right_location_changed(12, 20);
        assert_eq!(result, Some((2, 12)));
        assert_eq!(coord.locked_left_line(), 2);
        assert_eq!(coord.locked_right_line(), 12);
    }

    #[test]
    fn test_coordinator_right_location_changed_no_pairing() {
        let mut coord = ScrollCoordinator::new();
        let result = coord.right_location_changed(12, 20);
        assert_eq!(result, None);
    }

    #[test]
    fn test_coordinator_replace_decompile_data() {
        let mut coord = ScrollCoordinator::new();

        let left_lines = vec![
            DecompiledPanelLine::new(0, "int main() {", true),
            DecompiledPanelLine::new(1, "  return 0;", false),
        ];
        let right_lines = vec![
            DecompiledPanelLine::new(0, "void main() {", true),
            DecompiledPanelLine::new(1, "  return;", false),
        ];
        let bins = vec![
            ScrollTokenBin::new(true, 0, Some(0)),
            ScrollTokenBin::new(false, 0, Some(0)),
        ];

        coord.replace_decompile_data(&left_lines, &right_lines, &bins);

        // Should have locked function signature lines and computed pairing
        assert_eq!(coord.locked_left_line(), 0);
        assert_eq!(coord.locked_right_line(), 0);
        assert_eq!(coord.line_pairing().len(), 1);
    }

    #[test]
    fn test_coordinator_clear_line_pairing() {
        let mut coord = ScrollCoordinator::new();

        let bins = vec![
            ScrollTokenBin::new(true, 2, Some(0)),
            ScrollTokenBin::new(false, 12, Some(0)),
        ];
        coord.compute_line_pairing(&bins);
        assert!(!coord.line_pairing().is_empty());

        coord.clear_line_pairing();
        assert!(coord.line_pairing().is_empty());
    }

    #[test]
    fn test_coordinator_last_bins() {
        let mut coord = ScrollCoordinator::new();
        assert!(coord.last_bins().is_empty());

        let bins = vec![
            ScrollTokenBin::new(true, 2, Some(0)),
            ScrollTokenBin::new(false, 12, Some(0)),
        ];
        coord.compute_line_pairing(&bins);
        assert_eq!(coord.last_bins().len(), 2);
    }

    #[test]
    fn test_coordinator_complex_pairing() {
        let mut coord = ScrollCoordinator::new();

        // Simulate a realistic scenario with multiple matched lines
        let bins = vec![
            // Match 0: left line 1 <-> right line 1
            ScrollTokenBin::new(true, 1, Some(0)),
            ScrollTokenBin::new(false, 1, Some(0)),
            // Match 1: left line 3 <-> right line 4
            ScrollTokenBin::new(true, 3, Some(1)),
            ScrollTokenBin::new(false, 4, Some(1)),
            // Match 2: left line 5 <-> right line 7
            ScrollTokenBin::new(true, 5, Some(2)),
            ScrollTokenBin::new(false, 7, Some(2)),
            // Match 3: left line 7 <-> right line 9
            ScrollTokenBin::new(true, 7, Some(3)),
            ScrollTokenBin::new(false, 9, Some(3)),
            // Unmatched bins
            ScrollTokenBin::new(true, 8, None),
            ScrollTokenBin::new(false, 10, None),
        ];

        coord.compute_line_pairing(&bins);
        assert_eq!(coord.line_pairing().len(), 4);

        // Verify all pairings
        assert_eq!(coord.line_pairing().get_right(1), Some(1));
        assert_eq!(coord.line_pairing().get_right(3), Some(4));
        assert_eq!(coord.line_pairing().get_right(5), Some(7));
        assert_eq!(coord.line_pairing().get_right(7), Some(9));

        assert_eq!(coord.line_pairing().get_left(1), Some(1));
        assert_eq!(coord.line_pairing().get_left(4), Some(3));
        assert_eq!(coord.line_pairing().get_left(7), Some(5));
        assert_eq!(coord.line_pairing().get_left(9), Some(7));

        // Unmatched lines should not be in pairing
        assert_eq!(coord.line_pairing().get_right(8), None);
        assert_eq!(coord.line_pairing().get_left(10), None);
    }

    #[test]
    fn test_coordinator_search_from_nearby_line() {
        let mut coord = ScrollCoordinator::new();

        let bins = vec![
            ScrollTokenBin::new(true, 3, Some(0)),
            ScrollTokenBin::new(false, 13, Some(0)),
        ];
        coord.compute_line_pairing(&bins);

        // Move to left line 6 (not paired), should find line 3
        let result = coord.left_location_changed(6, 10);
        assert_eq!(result, Some((3, 13)));
    }
}
