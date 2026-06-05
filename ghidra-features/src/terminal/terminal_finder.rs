//! Terminal text search (find in terminal output).
//!
//! Ported from `ghidra.app.plugin.core.terminal.TerminalFinder`,
//! `TerminalLayout`, and `TerminalLayoutModel`.

use regex::Regex;

/// Options for searching text in the terminal.
#[derive(Debug, Clone)]
pub struct TerminalFindOptions {
    /// Whether the search is case-sensitive.
    pub case_sensitive: bool,
    /// Whether to use regular expressions.
    pub use_regex: bool,
    /// Whether to wrap around when reaching the end.
    pub wrap_around: bool,
    /// Whether to search backward.
    pub search_backward: bool,
}

impl Default for TerminalFindOptions {
    fn default() -> Self {
        Self {
            case_sensitive: true,
            use_regex: false,
            wrap_around: true,
            search_backward: false,
        }
    }
}

/// A match result from a terminal text search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalFindMatch {
    /// The line index (0-based from top of scrollback).
    pub line: usize,
    /// The column offset within the line.
    pub col: usize,
    /// The length of the match in characters.
    pub length: usize,
    /// The matched text.
    pub text: String,
}

/// Text finder for plain text search in terminal output.
///
/// Ported from `TerminalFinder.TextTerminalFinder`.
#[derive(Debug, Clone)]
pub struct TextTerminalFinder {
    /// The search string.
    pattern: String,
    /// Search options.
    options: TerminalFindOptions,
    /// The lowercased pattern (for case-insensitive search).
    pattern_lower: String,
}

impl TextTerminalFinder {
    /// Create a new text finder with the given pattern and options.
    pub fn new(pattern: impl Into<String>, options: TerminalFindOptions) -> Self {
        let p = pattern.into();
        let pattern_lower = if options.case_sensitive {
            p.clone()
        } else {
            p.to_lowercase()
        };
        Self {
            pattern: p,
            options,
            pattern_lower,
        }
    }

    /// Search for the pattern in the given text lines.
    ///
    /// Returns all matches found.
    pub fn find_in_lines(&self, lines: &[String]) -> Vec<TerminalFindMatch> {
        let mut matches = Vec::new();

        for (line_idx, line) in lines.iter().enumerate() {
            let haystack = if self.options.case_sensitive {
                line.clone()
            } else {
                line.to_lowercase()
            };

            let mut start = 0;
            while let Some(pos) = haystack[start..].find(&self.pattern_lower) {
                let absolute_pos = start + pos;
                matches.push(TerminalFindMatch {
                    line: line_idx,
                    col: absolute_pos,
                    length: self.pattern.len(),
                    text: line[absolute_pos..absolute_pos + self.pattern.len()].to_string(),
                });
                start = absolute_pos + 1;
            }
        }

        matches
    }

    /// Get the search pattern.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Get the search options.
    pub fn options(&self) -> &TerminalFindOptions {
        &self.options
    }
}

/// Regex-based finder for terminal output.
///
/// Ported from `TerminalFinder.RegexTerminalFinder`.
#[derive(Debug)]
pub struct RegexTerminalFinder {
    /// The compiled regex.
    regex: Regex,
    /// Search options.
    options: TerminalFindOptions,
    /// The original pattern string.
    pattern: String,
}

impl RegexTerminalFinder {
    /// Create a new regex finder.
    ///
    /// Returns `Err` if the pattern is not a valid regex.
    pub fn new(pattern: &str, options: TerminalFindOptions) -> Result<Self, regex::Error> {
        let flags = if options.case_sensitive { "" } else { "(?i)" };
        let full_pattern = format!("{}{}", flags, pattern);
        let regex = Regex::new(&full_pattern)?;
        Ok(Self {
            regex,
            options,
            pattern: pattern.to_string(),
        })
    }

    /// Search for the pattern in the given text lines.
    pub fn find_in_lines(&self, lines: &[String]) -> Vec<TerminalFindMatch> {
        let mut matches = Vec::new();

        for (line_idx, line) in lines.iter().enumerate() {
            for mat in self.regex.find_iter(line) {
                matches.push(TerminalFindMatch {
                    line: line_idx,
                    col: mat.start(),
                    length: mat.len(),
                    text: mat.as_str().to_string(),
                });
            }
        }

        matches
    }

    /// Get the original pattern string.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Get the search options.
    pub fn options(&self) -> &TerminalFindOptions {
        &self.options
    }
}

// ---------------------------------------------------------------------------
// TerminalLayout / TerminalLayoutModel
// ---------------------------------------------------------------------------

/// Layout information for a terminal line.
///
/// Ported from `TerminalLayout` and `TerminalLayoutModel`.
#[derive(Debug, Clone)]
pub struct TerminalLayout {
    /// The width of each column in pixels.
    pub col_width: f64,
    /// The height of each row in pixels.
    pub row_height: f64,
    /// The number of visible columns.
    pub visible_cols: usize,
    /// The number of visible rows.
    pub visible_rows: usize,
    /// The horizontal scroll offset (in columns).
    pub scroll_x: usize,
    /// The vertical scroll offset (in rows from the top of scrollback).
    pub scroll_y: usize,
    /// The cursor column position.
    pub cursor_col: usize,
    /// The cursor row position.
    pub cursor_row: usize,
}

impl TerminalLayout {
    /// Create a new terminal layout with the given dimensions.
    pub fn new(visible_cols: usize, visible_rows: usize) -> Self {
        Self {
            col_width: 8.0,
            row_height: 16.0,
            visible_cols,
            visible_rows,
            scroll_x: 0,
            scroll_y: 0,
            cursor_col: 0,
            cursor_row: 0,
        }
    }

    /// Get the total pixel width of the terminal.
    pub fn pixel_width(&self) -> f64 {
        self.visible_cols as f64 * self.col_width
    }

    /// Get the total pixel height of the terminal.
    pub fn pixel_height(&self) -> f64 {
        self.visible_rows as f64 * self.row_height
    }

    /// Set the cursor position.
    pub fn set_cursor(&mut self, col: usize, row: usize) {
        self.cursor_col = col.min(self.visible_cols.saturating_sub(1));
        self.cursor_row = row.min(self.visible_rows.saturating_sub(1));
    }

    /// Scroll up by the given number of rows.
    pub fn scroll_up(&mut self, rows: usize) {
        self.scroll_y = self.scroll_y.saturating_sub(rows);
    }

    /// Scroll down by the given number of rows.
    pub fn scroll_down(&mut self, rows: usize, total_lines: usize) {
        let max_scroll = total_lines.saturating_sub(self.visible_rows);
        self.scroll_y = (self.scroll_y + rows).min(max_scroll);
    }

    /// Scroll left by the given number of columns.
    pub fn scroll_left(&mut self, cols: usize) {
        self.scroll_x = self.scroll_x.saturating_sub(cols);
    }

    /// Scroll right by the given number of columns.
    pub fn scroll_right(&mut self, cols: usize) {
        self.scroll_x += cols;
    }

    /// Reset scrolling to the top-left.
    pub fn reset_scroll(&mut self) {
        self.scroll_x = 0;
        self.scroll_y = 0;
    }

    /// Resize the terminal layout.
    pub fn resize(&mut self, cols: usize, rows: usize) {
        self.visible_cols = cols;
        self.visible_rows = rows;
        // Ensure cursor is still in bounds.
        self.cursor_col = self.cursor_col.min(cols.saturating_sub(1));
        self.cursor_row = self.cursor_row.min(rows.saturating_sub(1));
    }

    /// Get the visible line range (start..end) given total lines.
    pub fn visible_line_range(&self, total_lines: usize) -> (usize, usize) {
        let start = self.scroll_y;
        let end = (self.scroll_y + self.visible_rows).min(total_lines);
        (start, end)
    }

    /// Get the visible column range.
    pub fn visible_col_range(&self, max_cols: usize) -> (usize, usize) {
        let start = self.scroll_x;
        let end = (self.scroll_x + self.visible_cols).min(max_cols);
        (start, end)
    }
}

impl Default for TerminalLayout {
    fn default() -> Self {
        Self::new(super::DEFAULT_WIDTH, super::DEFAULT_HEIGHT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_finder_case_sensitive() {
        let options = TerminalFindOptions {
            case_sensitive: true,
            ..Default::default()
        };
        let finder = TextTerminalFinder::new("error", options);
        let lines = vec![
            "Error: something failed".to_string(),
            "error: null pointer".to_string(),
            "ERROR: fatal".to_string(),
        ];

        let matches = finder.find_in_lines(&lines);
        // Only "error" (exact case) should match.
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].line, 1);
        assert_eq!(matches[0].col, 0);
    }

    #[test]
    fn test_text_finder_case_insensitive() {
        let options = TerminalFindOptions {
            case_sensitive: false,
            ..Default::default()
        };
        let finder = TextTerminalFinder::new("error", options);
        let lines = vec![
            "Error: something failed".to_string(),
            "error: null pointer".to_string(),
            "ERROR: fatal".to_string(),
        ];

        let matches = finder.find_in_lines(&lines);
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_text_finder_multiple_matches_per_line() {
        let options = TerminalFindOptions::default();
        let finder = TextTerminalFinder::new("ab", options);
        let lines = vec!["ababab".to_string()];

        let matches = finder.find_in_lines(&lines);
        assert_eq!(matches.len(), 3); // positions 0, 2, 4 -- no, actually overlaps so 5
    }

    #[test]
    fn test_regex_finder() {
        let options = TerminalFindOptions::default();
        let finder = RegexTerminalFinder::new(r"\d+", options).unwrap();
        let lines = vec!["error 42 at line 7".to_string()];

        let matches = finder.find_in_lines(&lines);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].text, "42");
        assert_eq!(matches[1].text, "7");
    }

    #[test]
    fn test_regex_finder_case_insensitive() {
        let options = TerminalFindOptions {
            case_sensitive: false,
            ..Default::default()
        };
        let finder = RegexTerminalFinder::new(r"error", options).unwrap();
        let lines = vec!["Error and ERROR".to_string()];

        let matches = finder.find_in_lines(&lines);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_regex_finder_invalid_pattern() {
        let options = TerminalFindOptions::default();
        let result = RegexTerminalFinder::new("[invalid", options);
        assert!(result.is_err());
    }

    #[test]
    fn test_terminal_layout_basic() {
        let layout = TerminalLayout::new(80, 24);
        assert_eq!(layout.visible_cols, 80);
        assert_eq!(layout.visible_rows, 24);
        assert_eq!(layout.pixel_width(), 80.0 * 8.0);
        assert_eq!(layout.pixel_height(), 24.0 * 16.0);
    }

    #[test]
    fn test_terminal_layout_cursor() {
        let mut layout = TerminalLayout::new(80, 24);
        layout.set_cursor(10, 5);
        assert_eq!(layout.cursor_col, 10);
        assert_eq!(layout.cursor_row, 5);

        // Cursor is clamped to visible area.
        layout.set_cursor(100, 100);
        assert_eq!(layout.cursor_col, 79);
        assert_eq!(layout.cursor_row, 23);
    }

    #[test]
    fn test_terminal_layout_scroll() {
        let mut layout = TerminalLayout::new(80, 24);

        layout.scroll_down(10, 100);
        assert_eq!(layout.scroll_y, 10);

        layout.scroll_down(200, 100);
        // Max scroll = 100 - 24 = 76
        assert_eq!(layout.scroll_y, 76);

        layout.scroll_up(5);
        assert_eq!(layout.scroll_y, 71);

        layout.reset_scroll();
        assert_eq!(layout.scroll_y, 0);
        assert_eq!(layout.scroll_x, 0);
    }

    #[test]
    fn test_terminal_layout_resize() {
        let mut layout = TerminalLayout::new(80, 24);
        layout.set_cursor(70, 20);
        layout.resize(40, 12);
        assert_eq!(layout.visible_cols, 40);
        assert_eq!(layout.visible_rows, 12);
        assert_eq!(layout.cursor_col, 39);
        assert_eq!(layout.cursor_row, 11);
    }

    #[test]
    fn test_terminal_layout_visible_range() {
        let mut layout = TerminalLayout::new(80, 24);
        layout.scroll_y = 10;

        let (start, end) = layout.visible_line_range(100);
        assert_eq!(start, 10);
        assert_eq!(end, 34);

        let (start, end) = layout.visible_line_range(20);
        assert_eq!(start, 10);
        assert_eq!(end, 20);
    }

    #[test]
    fn test_find_options_default() {
        let opts = TerminalFindOptions::default();
        assert!(opts.case_sensitive);
        assert!(!opts.use_regex);
        assert!(opts.wrap_around);
        assert!(!opts.search_backward);
    }
}
