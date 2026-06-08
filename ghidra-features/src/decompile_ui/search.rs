//! Decompiler search -- Rust port of the search infrastructure from
//! `ghidra.app.plugin.core.decompile.actions`.
//!
//! Combines the following Java classes into a cohesive search module:
//!
//! * `DecompilerSearcher` -- the main searcher that drives Find / Find All.
//! * `DecompilerSearchResults` -- holds the results of a search.
//! * `DecompilerSearchLocation` -- a single match location.
//! * `DecompilerCursorPosition` -- a cursor position in the decompiler panel.
//!
//! The searcher operates on the textual representation of decompiled
//! lines and supports both plain-text and regex search modes.

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// DecompilerCursorPosition
// ---------------------------------------------------------------------------

/// A cursor position in the decompiler panel.
///
/// Mirrors Ghidra's `DecompilerCursorPosition`, which wraps a
/// `FieldLocation` and extends `CursorPosition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompilerCursorPosition {
    /// 0-based line index.
    pub line: usize,
    /// Column offset within the line.
    pub col: usize,
    /// Row offset within the field (for wrapped lines).
    pub row: usize,
}

impl DecompilerCursorPosition {
    /// Create a new cursor position.
    pub fn new(line: usize, col: usize, row: usize) -> Self {
        Self { line, col, row }
    }

    /// Create a cursor at the start of the document.
    pub fn start() -> Self {
        Self::new(0, 0, 0)
    }

    /// Adjust the column offset by the given delta.
    pub fn adjust_col(&mut self, delta: isize) {
        self.col = (self.col as isize + delta).max(0) as usize;
    }
}

impl PartialOrd for DecompilerCursorPosition {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DecompilerCursorPosition {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.line
            .cmp(&other.line)
            .then(self.row.cmp(&other.row))
            .then(self.col.cmp(&other.col))
    }
}

// ---------------------------------------------------------------------------
// DecompilerSearchLocation
// ---------------------------------------------------------------------------

/// A single search match in the decompiler output.
///
/// Mirrors Ghidra's `DecompilerSearchLocation`, which extends
/// `SearchLocation` and adds the `FieldLocation` and the full text
/// of the matched line.
#[derive(Debug, Clone)]
pub struct DecompilerSearchLocation {
    /// The cursor position of this match.
    pub cursor_position: DecompilerCursorPosition,
    /// The inclusive start index within the line text.
    pub start_index_inclusive: usize,
    /// The inclusive end index within the line text.
    pub end_index_inclusive: usize,
    /// The search text that was matched.
    pub search_text: String,
    /// Whether this was a forward search match.
    pub forward_direction: bool,
    /// The full text of the line where the match occurred.
    pub text_line: String,
    /// The 1-based line number.
    pub line_number: usize,
    /// Context around the match (for display in results).
    pub context_before: String,
    pub context_match: String,
    pub context_after: String,
}

impl DecompilerSearchLocation {
    /// Create a new search location.
    pub fn new(
        cursor_position: DecompilerCursorPosition,
        start_index_inclusive: usize,
        end_index_inclusive: usize,
        search_text: impl Into<String>,
        forward_direction: bool,
        text_line: impl Into<String>,
        line_number: usize,
    ) -> Self {
        let text = text_line.into();
        let st = search_text.into();
        // Build context.
        let s = start_index_inclusive.min(text.len());
        let e = (end_index_inclusive + 1).min(text.len());
        Self {
            cursor_position,
            start_index_inclusive,
            end_index_inclusive,
            search_text: st,
            forward_direction,
            text_line: text.clone(),
            line_number,
            context_before: text[..s].to_string(),
            context_match: text[s..e].to_string(),
            context_after: if e < text.len() {
                text[e..].to_string()
            } else {
                String::new()
            },
        }
    }

    /// Returns `true` if the given cursor position falls within this match.
    pub fn contains(&self, cursor: &DecompilerCursorPosition) -> bool {
        if self.line_number == 0 {
            return false;
        }
        // The line number in search results is 1-based; the cursor line is 0-based.
        let cursor_line_1based = cursor.line + 1;
        if self.line_number != cursor_line_1based {
            return false;
        }
        cursor.col >= self.start_index_inclusive && cursor.col <= self.end_index_inclusive
    }
}

// ---------------------------------------------------------------------------
// DecompilerSearchResults
// ---------------------------------------------------------------------------

/// Holds the results of a search operation in the decompiler.
///
/// Mirrors Ghidra's `DecompilerSearchResults`, which extends
/// `SearchResults`.  Stores all match locations grouped by line
/// and ordered by position for efficient next/previous navigation.
#[derive(Debug, Clone)]
pub struct DecompilerSearchResults {
    /// The search text.
    pub search_text: String,
    /// All match locations, in document order.
    locations: Vec<DecompilerSearchLocation>,
    /// Matches indexed by (line, col) for fast lookup.
    by_position: BTreeMap<(usize, usize), usize>,
    /// The currently active (highlighted) match index.
    active_index: Option<usize>,
    /// Whether the results are still valid.
    disposed: bool,
}

impl DecompilerSearchResults {
    /// Create new search results.
    pub fn new(search_text: impl Into<String>, locations: Vec<DecompilerSearchLocation>) -> Self {
        let mut by_position = BTreeMap::new();
        for (i, loc) in locations.iter().enumerate() {
            by_position.insert((loc.line_number, loc.start_index_inclusive), i);
        }
        Self {
            search_text: search_text.into(),
            locations,
            by_position,
            active_index: None,
            disposed: false,
        }
    }

    /// Returns `true` if there are no matches.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// The total number of matches.
    pub fn num_matches(&self) -> usize {
        self.locations.len()
    }

    /// Get all match locations.
    pub fn get_locations(&self) -> &[DecompilerSearchLocation] {
        &self.locations
    }

    /// Get the active (currently highlighted) location.
    pub fn get_active_location(&self) -> Option<&DecompilerSearchLocation> {
        self.active_index.and_then(|i| self.locations.get(i))
    }

    /// Set the active location by index.
    pub fn set_active_location(&mut self, index: Option<usize>) {
        self.active_index = index;
    }

    /// Set the active location by reference.
    pub fn set_active_location_by_ref(&mut self, location: &DecompilerSearchLocation) {
        self.active_index = self.locations.iter().position(|l| {
            l.line_number == location.line_number
                && l.start_index_inclusive == location.start_index_inclusive
        });
    }

    /// Set the active location by line number and column.
    pub fn set_active_location_by_line_col(&mut self, line_number: usize, col: usize) {
        self.active_index = self.by_position.get(&(line_number, col)).copied();
    }

    /// Get the next match location starting from the given cursor,
    /// searching in the specified direction.
    pub fn get_next_location(
        &self,
        cursor: &DecompilerCursorPosition,
        search_forward: bool,
    ) -> Option<&DecompilerSearchLocation> {
        let cursor_line_1based = cursor.line + 1;
        let key = (cursor_line_1based, cursor.col);

        if search_forward {
            // Find the first entry at or after the cursor position.
            self.by_position
                .range((cursor_line_1based, cursor.col)..)
                .next()
                .and_then(|(_, &idx)| self.locations.get(idx))
        } else {
            // Find the last entry strictly before the cursor.
            self.by_position
                .range(..key)
                .next_back()
                .and_then(|(_, &idx)| self.locations.get(idx))
        }
    }

    /// Get the match location that contains the given cursor position.
    pub fn get_containing_location(
        &self,
        cursor: &DecompilerCursorPosition,
        search_forward: bool,
    ) -> Option<&DecompilerSearchLocation> {
        let next = self.get_next_location(cursor, search_forward)?;
        if next.contains(cursor) {
            return Some(next);
        }
        None
    }

    /// Returns `true` if these results are invalid for the given search text.
    pub fn is_invalid(&self, other_search_text: &str) -> bool {
        self.search_text != other_search_text
    }

    /// Activate the search results (mark as valid).
    pub fn activate(&mut self) {
        self.disposed = false;
    }

    /// Deactivate the search results.
    pub fn deactivate(&mut self) {
        self.active_index = None;
    }

    /// Dispose of the search results.
    pub fn dispose(&mut self) {
        self.active_index = None;
        self.locations.clear();
        self.by_position.clear();
        self.disposed = true;
    }

    /// Get the name of the search results (for display).
    pub fn get_name(&self) -> String {
        format!("{} ({} matches)", self.search_text, self.locations.len())
    }
}

// ---------------------------------------------------------------------------
// SearchMatch (internal)
// ---------------------------------------------------------------------------

/// A regex/text match within a single line.
#[derive(Debug, Clone)]
struct SearchMatch {
    start: usize,
    end: usize,
}

// ---------------------------------------------------------------------------
// DecompilerSearcher
// ---------------------------------------------------------------------------

/// The main searcher for the decompiler panel.
///
/// Drives plain-text and regex searches across the decompiled output.
/// Maintains the current search results and supports next/previous
/// navigation.
#[derive(Debug)]
pub struct DecompilerSearcher {
    /// The lines of text to search (one per decompiled line).
    lines: Vec<String>,
    /// The current search results, if any.
    results: Option<DecompilerSearchResults>,
    /// Whether to use case-insensitive matching.
    case_insensitive: bool,
}

impl DecompilerSearcher {
    /// Create a new searcher with the given lines.
    pub fn new(lines: Vec<String>) -> Self {
        Self {
            lines,
            results: None,
            case_insensitive: true,
        }
    }

    /// Update the lines to search.
    pub fn set_lines(&mut self, lines: Vec<String>) {
        self.lines = lines;
        // Invalidate existing results.
        if let Some(ref mut r) = self.results {
            r.dispose();
        }
        self.results = None;
    }

    /// Set whether matching is case-insensitive.
    pub fn set_case_insensitive(&mut self, insensitive: bool) {
        self.case_insensitive = insensitive;
    }

    /// Get the cursor position at the start of the document.
    pub fn get_start(&self) -> DecompilerCursorPosition {
        DecompilerCursorPosition::start()
    }

    /// Get the cursor position at the end of the document.
    pub fn get_end(&self) -> DecompilerCursorPosition {
        let line = self.lines.len().saturating_sub(1);
        let col = self.lines.last().map_or(0, |l| l.len());
        DecompilerCursorPosition::new(line, col, 0)
    }

    /// Perform a search and return the results.
    ///
    /// If `use_regex` is true, the search text is treated as a regular
    /// expression.  Otherwise it is a plain-text (substring) search.
    pub fn search_all(
        &mut self,
        search_text: &str,
        use_regex: bool,
    ) -> Option<&DecompilerSearchResults> {
        let locations = if use_regex {
            self.do_regex_search(search_text)
        } else {
            self.do_text_search(search_text)
        };

        let results = DecompilerSearchResults::new(search_text, locations);
        if results.is_empty() {
            self.results = None;
            return None;
        }

        self.results = Some(results);
        self.results.as_ref()
    }

    /// Perform a search starting from the given cursor position.
    ///
    /// Returns the search results with the active location set to the
    /// next match.
    pub fn search(
        &mut self,
        search_text: &str,
        position: &DecompilerCursorPosition,
        search_forward: bool,
        use_regex: bool,
    ) -> Option<&DecompilerSearchResults> {
        // Reuse existing results if the search text hasn't changed.
        if self.results.is_none()
            || self
                .results
                .as_ref()
                .map_or(false, |r| r.is_invalid(search_text))
        {
            self.search_all(search_text, use_regex);
        }

        // Find the next location (immutable borrow) and extract the key.
        let next_key = self.results.as_ref().and_then(|r| {
            r.get_next_location(position, search_forward).map(|loc| {
                (loc.line_number, loc.start_index_inclusive)
            })
        });

        let results = self.results.as_mut()?;
        if let Some((line, col)) = next_key {
            results.set_active_location_by_line_col(line, col);
        } else {
            results.set_active_location(None);
            return None;
        }

        self.results.as_ref()
    }

    /// Get the current search results.
    pub fn get_results(&self) -> Option<&DecompilerSearchResults> {
        self.results.as_ref()
    }

    /// Dispose of the searcher.
    pub fn dispose(&mut self) {
        if let Some(ref mut r) = self.results {
            r.dispose();
        }
        self.results = None;
    }

    // -----------------------------------------------------------------------
    // Internal search methods
    // -----------------------------------------------------------------------

    /// Perform a plain-text (substring) search.
    fn do_text_search(&self, search_text: &str) -> Vec<DecompilerSearchLocation> {
        let mut locations = Vec::new();
        let pattern = if self.case_insensitive {
            search_text.to_lowercase()
        } else {
            search_text.to_string()
        };

        for (line_idx, line) in self.lines.iter().enumerate() {
            let haystack = if self.case_insensitive {
                line.to_lowercase()
            } else {
                line.clone()
            };

            let mut search_from = 0;
            while let Some(pos) = haystack[search_from..].find(&pattern) {
                let absolute_pos = search_from + pos;
                let end = absolute_pos + pattern.len() - 1;
                let line_number = line_idx + 1; // 1-based
                locations.push(DecompilerSearchLocation::new(
                    DecompilerCursorPosition::new(line_idx, absolute_pos, 0),
                    absolute_pos,
                    end,
                    search_text,
                    true,
                    line,
                    line_number,
                ));
                search_from = absolute_pos + 1;
            }
        }

        locations
    }

    /// Perform a regex search.
    fn do_regex_search(&self, pattern_str: &str) -> Vec<DecompilerSearchLocation> {
        use regex::Regex;

        let pattern = match Regex::new(pattern_str) {
            Ok(re) => re,
            Err(_) => return Vec::new(),
        };

        let mut locations = Vec::new();
        for (line_idx, line) in self.lines.iter().enumerate() {
            for mat in pattern.find_iter(line) {
                let start = mat.start();
                let end = mat.end().saturating_sub(1);
                let line_number = line_idx + 1; // 1-based
                locations.push(DecompilerSearchLocation::new(
                    DecompilerCursorPosition::new(line_idx, start, 0),
                    start,
                    end,
                    pattern_str,
                    true,
                    line,
                    line_number,
                ));
            }
        }

        locations
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lines() -> Vec<String> {
        vec![
            "void main() {".into(),
            "    int x = 42;".into(),
            "    printf(\"hello world\");".into(),
            "    return;".into(),
            "}".into(),
        ]
    }

    // --- Cursor Position ---

    #[test]
    fn test_cursor_position_new() {
        let c = DecompilerCursorPosition::new(5, 10, 0);
        assert_eq!(c.line, 5);
        assert_eq!(c.col, 10);
        assert_eq!(c.row, 0);
    }

    #[test]
    fn test_cursor_position_start() {
        let c = DecompilerCursorPosition::start();
        assert_eq!(c, DecompilerCursorPosition::new(0, 0, 0));
    }

    #[test]
    fn test_cursor_position_adjust_col() {
        let mut c = DecompilerCursorPosition::new(0, 5, 0);
        c.adjust_col(3);
        assert_eq!(c.col, 8);
        c.adjust_col(-10);
        assert_eq!(c.col, 0); // clamped to 0
    }

    #[test]
    fn test_cursor_position_ordering() {
        let a = DecompilerCursorPosition::new(1, 0, 0);
        let b = DecompilerCursorPosition::new(2, 0, 0);
        assert!(a < b);

        let c = DecompilerCursorPosition::new(1, 5, 0);
        let d = DecompilerCursorPosition::new(1, 10, 0);
        assert!(c < d);
    }

    // --- Search Location ---

    #[test]
    fn test_search_location_new() {
        let loc = DecompilerSearchLocation::new(
            DecompilerCursorPosition::new(1, 8, 0),
            8,
            8,
            "x",
            true,
            "    int x = 42;",
            2,
        );
        assert_eq!(loc.line_number, 2);
        assert_eq!(loc.start_index_inclusive, 8);
        assert_eq!(loc.end_index_inclusive, 8);
        assert!(loc.context_match.contains("x"));
    }

    #[test]
    fn test_search_location_contains() {
        let loc = DecompilerSearchLocation::new(
            DecompilerCursorPosition::new(1, 4, 0),
            4,
            5,
            "x",
            true,
            "    int x = 42;",
            2, // 1-based
        );
        // Cursor on line 1 (0-based) = line 2 (1-based), col 4 is inside.
        let cursor_in = DecompilerCursorPosition::new(1, 4, 0);
        assert!(loc.contains(&cursor_in));

        // Cursor on different line.
        let cursor_other = DecompilerCursorPosition::new(0, 4, 0);
        assert!(!loc.contains(&cursor_other));

        // Cursor at col outside match range.
        let cursor_out = DecompilerCursorPosition::new(1, 10, 0);
        assert!(!loc.contains(&cursor_out));
    }

    // --- Search Results ---

    #[test]
    fn test_search_results_empty() {
        let results = DecompilerSearchResults::new("test", vec![]);
        assert!(results.is_empty());
        assert_eq!(results.num_matches(), 0);
    }

    #[test]
    fn test_search_results_with_matches() {
        let locations = vec![
            DecompilerSearchLocation::new(
                DecompilerCursorPosition::new(1, 4, 0),
                4,
                4,
                "x",
                true,
                "int x = x;",
                2,
            ),
            DecompilerSearchLocation::new(
                DecompilerCursorPosition::new(1, 8, 0),
                8,
                8,
                "x",
                true,
                "int x = x;",
                2,
            ),
        ];
        let results = DecompilerSearchResults::new("x", locations);
        assert_eq!(results.num_matches(), 2);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_results_next_forward() {
        let locations = vec![
            DecompilerSearchLocation::new(
                DecompilerCursorPosition::new(0, 0, 0),
                0,
                3,
                "void",
                true,
                "void main() {",
                1,
            ),
            DecompilerSearchLocation::new(
                DecompilerCursorPosition::new(1, 8, 0),
                8,
                8,
                "x",
                true,
                "    int x = 42;",
                2,
            ),
        ];
        let results = DecompilerSearchResults::new("test", locations);

        // From start, forward should find the first match.
        let cursor = DecompilerCursorPosition::start();
        let next = results.get_next_location(&cursor, true);
        assert!(next.is_some());
        assert_eq!(next.unwrap().line_number, 1);
    }

    #[test]
    fn test_search_results_next_backward() {
        let locations = vec![
            DecompilerSearchLocation::new(
                DecompilerCursorPosition::new(0, 0, 0),
                0,
                3,
                "void",
                true,
                "void main() {",
                1,
            ),
            DecompilerSearchLocation::new(
                DecompilerCursorPosition::new(1, 8, 0),
                8,
                8,
                "x",
                true,
                "    int x = 42;",
                2,
            ),
        ];
        let results = DecompilerSearchResults::new("test", locations);

        // From end, backward should find the last match.
        let cursor = DecompilerCursorPosition::new(4, 0, 0);
        let prev = results.get_next_location(&cursor, false);
        assert!(prev.is_some());
        assert_eq!(prev.unwrap().line_number, 2);
    }

    #[test]
    fn test_search_results_is_invalid() {
        let results = DecompilerSearchResults::new("foo", vec![]);
        assert!(!results.is_invalid("foo"));
        assert!(results.is_invalid("bar"));
    }

    #[test]
    fn test_search_results_dispose() {
        let locations = vec![DecompilerSearchLocation::new(
            DecompilerCursorPosition::new(0, 0, 0),
            0,
            0,
            "a",
            true,
            "a",
            1,
        )];
        let mut results = DecompilerSearchResults::new("a", locations);
        results.dispose();
        assert!(results.is_empty());
        assert!(results.disposed);
    }

    // --- Searcher ---

    #[test]
    fn test_searcher_text_search() {
        let mut searcher = DecompilerSearcher::new(sample_lines());
        let results = searcher.search_all("x", false);
        assert!(results.is_some());
        let r = results.unwrap();
        assert_eq!(r.num_matches(), 1);
        assert_eq!(r.get_locations()[0].line_number, 2);
    }

    #[test]
    fn test_searcher_text_search_multiple() {
        let lines = vec!["aaa bbb aaa ccc aaa".to_string()];
        let mut searcher = DecompilerSearcher::new(lines);
        let results = searcher.search_all("aaa", false).unwrap();
        assert_eq!(results.num_matches(), 3);
    }

    #[test]
    fn test_searcher_text_search_case_insensitive() {
        let mut searcher = DecompilerSearcher::new(sample_lines());
        searcher.set_case_insensitive(true);
        let results = searcher.search_all("VOID", false).unwrap();
        assert_eq!(results.num_matches(), 1);
    }

    #[test]
    fn test_searcher_text_search_not_found() {
        let mut searcher = DecompilerSearcher::new(sample_lines());
        let results = searcher.search_all("nonexistent", false);
        assert!(results.is_none());
    }

    #[test]
    fn test_searcher_regex_search() {
        let mut searcher = DecompilerSearcher::new(sample_lines());
        let results = searcher.search_all(r"\d+", true).unwrap();
        assert_eq!(results.num_matches(), 1);
        assert_eq!(results.get_locations()[0].context_match, "42");
    }

    #[test]
    fn test_searcher_regex_search_complex() {
        let lines = vec![
            "int foo = 0x1234;".to_string(),
            "int bar = 5678;".to_string(),
        ];
        let mut searcher = DecompilerSearcher::new(lines);
        let results = searcher.search_all(r"\b\w+\b", true).unwrap();
        // foo, bar, 0x1234, 5678 -- depends on regex word boundary
        assert!(results.num_matches() >= 4);
    }

    #[test]
    fn test_searcher_search_from_position() {
        let mut searcher = DecompilerSearcher::new(sample_lines());
        let cursor = DecompilerCursorPosition::start();
        let results = searcher.search("int", &cursor, true, false);
        assert!(results.is_some());
        let r = results.unwrap();
        assert!(r.get_active_location().is_some());
    }

    #[test]
    fn test_searcher_set_lines() {
        let mut searcher = DecompilerSearcher::new(sample_lines());
        searcher.search_all("x", false).unwrap();
        assert!(searcher.get_results().is_some());

        // Replace lines -- results should be invalidated.
        searcher.set_lines(vec!["new content".to_string()]);
        assert!(searcher.get_results().is_none());
    }

    #[test]
    fn test_searcher_get_start_end() {
        let searcher = DecompilerSearcher::new(sample_lines());
        assert_eq!(searcher.get_start(), DecompilerCursorPosition::new(0, 0, 0));
        assert_eq!(searcher.get_end(), DecompilerCursorPosition::new(4, 1, 0));
    }

    #[test]
    fn test_searcher_dispose() {
        let mut searcher = DecompilerSearcher::new(sample_lines());
        searcher.search_all("void", false).unwrap();
        searcher.dispose();
        assert!(searcher.get_results().is_none());
    }

    #[test]
    fn test_search_results_get_name() {
        let results = DecompilerSearchResults::new("test", vec![]);
        assert!(results.get_name().contains("test"));
        assert!(results.get_name().contains("0 matches"));
    }
}
