//! Search location descriptor.
//!
//! Port of Ghidra's `SearchLocation` class. An object that describes a search
//! result with start/end indices, line number, and optional context.

use super::cursor_position::CursorPosition;

/// Describes the location of a search result.
///
/// In Ghidra, `SearchLocation` was used by the find dialog and search
/// subsystems to describe where a match was found. It carries start/end
/// character indices, the matched text, and optionally a line number and
/// a context identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchLocation {
    /// Inclusive start index of the match.
    start_index_inclusive: usize,
    /// Inclusive end index of the match.
    end_index_inclusive: usize,
    /// The text that was searched for (or the matched text).
    text: String,
    /// Optional line number where the match was found.
    line_number: Option<usize>,
    /// Optional context identifier (e.g., which panel or view the match is in).
    context: Option<String>,
}

impl SearchLocation {
    /// Create a basic search location with start/end indices and text.
    pub fn new(start_index_inclusive: usize, end_index_inclusive: usize, text: impl Into<String>) -> Self {
        Self {
            start_index_inclusive,
            end_index_inclusive,
            text: text.into(),
            line_number: None,
            context: None,
        }
    }

    /// Create a search location with full context information.
    pub fn with_context(
        start_index_inclusive: usize,
        end_index_inclusive: usize,
        text: impl Into<String>,
        line_number: usize,
        context: impl Into<String>,
    ) -> Self {
        Self {
            start_index_inclusive,
            end_index_inclusive,
            text: text.into(),
            line_number: Some(line_number),
            context: Some(context.into()),
        }
    }

    /// Get the start index (inclusive).
    pub fn start_index(&self) -> usize {
        self.start_index_inclusive
    }

    /// Get the end index (inclusive).
    pub fn end_index(&self) -> usize {
        self.end_index_inclusive
    }

    /// Get the matched text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Get the line number, if available.
    pub fn line_number(&self) -> Option<usize> {
        self.line_number
    }

    /// Get the context identifier, if available.
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    /// Get a `CursorPosition` for the start of this match.
    pub fn cursor_position(&self) -> CursorPosition {
        CursorPosition::new(self.start_index_inclusive)
    }

    /// Check if this location contains the given position.
    pub fn contains(&self, pos: usize) -> bool {
        self.start_index_inclusive <= pos && self.end_index_inclusive >= pos
    }

    /// Get the length of the match.
    pub fn match_length(&self) -> usize {
        self.end_index_inclusive - self.start_index_inclusive + 1
    }
}

impl std::fmt::Display for SearchLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}[line={}, start={}, end={}]",
            self.text,
            self.line_number.unwrap_or(0),
            self.start_index_inclusive,
            self.end_index_inclusive
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_search_location() {
        let loc = SearchLocation::new(5, 10, "hello");
        assert_eq!(loc.start_index(), 5);
        assert_eq!(loc.end_index(), 10);
        assert_eq!(loc.text(), "hello");
        assert_eq!(loc.line_number(), None);
        assert_eq!(loc.context(), None);
    }

    #[test]
    fn test_search_location_with_context() {
        let loc = SearchLocation::with_context(0, 4, "world", 42, "decompiler");
        assert_eq!(loc.start_index(), 0);
        assert_eq!(loc.end_index(), 4);
        assert_eq!(loc.text(), "world");
        assert_eq!(loc.line_number(), Some(42));
        assert_eq!(loc.context(), Some("decompiler"));
    }

    #[test]
    fn test_contains() {
        let loc = SearchLocation::new(5, 10, "test");
        assert!(!loc.contains(4));
        assert!(loc.contains(5));
        assert!(loc.contains(7));
        assert!(loc.contains(10));
        assert!(!loc.contains(11));
    }

    #[test]
    fn test_match_length() {
        let loc = SearchLocation::new(5, 10, "test");
        assert_eq!(loc.match_length(), 6);
    }

    #[test]
    fn test_match_length_single_char() {
        let loc = SearchLocation::new(3, 3, "x");
        assert_eq!(loc.match_length(), 1);
    }

    #[test]
    fn test_cursor_position() {
        let loc = SearchLocation::new(42, 50, "test");
        let pos = loc.cursor_position();
        assert_eq!(pos.position(), 42);
    }

    #[test]
    fn test_display() {
        let loc = SearchLocation::new(5, 10, "hello");
        assert_eq!(format!("{}", loc), "hello[line=0, start=5, end=10]");
    }

    #[test]
    fn test_display_with_line() {
        let loc = SearchLocation::with_context(0, 4, "world", 42, "ctx");
        assert_eq!(format!("{}", loc), "world[line=42, start=0, end=4]");
    }

    #[test]
    fn test_clone() {
        let loc = SearchLocation::new(1, 5, "test");
        let loc2 = loc.clone();
        assert_eq!(loc, loc2);
    }
}
