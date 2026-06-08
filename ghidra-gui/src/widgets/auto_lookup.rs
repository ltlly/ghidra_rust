//! Auto-lookup for type-ahead searching in row-based widgets.
//!
//! Port of Ghidra's `AutoLookup` class. When the user types characters in a
//! table or list, this class accumulates the typed text and searches for a
//! matching row. Supports both linear and binary search depending on whether
//! the column is sorted.
//!
//! In egui, the lookup is triggered by feeding keyboard events via
//! [`AutoLookup::process_key`].

use std::time::{Duration, Instant};

/// Default timeout between keystrokes (milliseconds).
pub const KEY_TYPING_TIMEOUT_MS: u64 = 800;

/// Maximum number of rows to search.
pub const MAX_SEARCH_ROWS: usize = 50_000;

/// State for type-ahead auto-lookup in a row-based widget.
pub struct AutoLookup {
    /// The accumulated lookup text.
    text: String,
    /// Timestamp of the last keystroke.
    last_key_time: Option<Instant>,
    /// Timeout between keystrokes.
    key_timeout: Duration,
    /// Which column to search.
    lookup_column: usize,
    /// The last matched row index.
    last_match_row: Option<usize>,
}

impl AutoLookup {
    pub fn new() -> Self {
        Self {
            text: String::new(),
            last_key_time: None,
            key_timeout: Duration::from_millis(KEY_TYPING_TIMEOUT_MS),
            lookup_column: 0,
            last_match_row: None,
        }
    }

    /// Set the timeout between keystrokes.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.key_timeout = timeout;
    }

    /// Set the column to search.
    pub fn set_column(&mut self, column: usize) {
        self.lookup_column = column;
        self.text.clear();
        self.last_match_row = None;
    }

    /// Get the current lookup column.
    pub fn column(&self) -> usize {
        self.lookup_column
    }

    /// Get the current accumulated lookup text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Get the last matched row.
    pub fn last_match_row(&self) -> Option<usize> {
        self.last_match_row
    }

    /// Process a typed character. Returns the matching row index if found.
    ///
    /// The `get_value` function should return the string value at
    /// (row, column) for the lookup column. The `row_count` is the total
    /// number of rows. The `is_sorted` flag indicates whether binary search
    /// can be used.
    pub fn process_char(
        &mut self,
        ch: char,
        row_count: usize,
        is_sorted: bool,
        ascending: bool,
        get_value: impl Fn(usize, usize) -> Option<String>,
    ) -> Option<usize> {
        if row_count == 0 {
            return None;
        }

        let now = Instant::now();

        // Check if we should start a new lookup or continue the existing one.
        if let Some(last_time) = self.last_key_time {
            if now.duration_since(last_time) > self.key_timeout {
                self.text.clear();
            }
        }

        self.last_key_time = Some(now);
        self.text.push(ch);

        let search_start = self.last_match_row.unwrap_or(0);
        let matched = if is_sorted {
            self.binary_search(row_count, ascending, &get_value)
        } else {
            self.linear_search(row_count, search_start, &get_value)
        };

        if let Some(row) = matched {
            self.last_match_row = Some(row);
        }
        matched
    }

    /// Reset the lookup state.
    pub fn reset(&mut self) {
        self.text.clear();
        self.last_key_time = None;
        self.last_match_row = None;
    }

    /// Linear search starting from `start_row`.
    fn linear_search(
        &self,
        row_count: usize,
        start_row: usize,
        get_value: &impl Fn(usize, usize) -> Option<String>,
    ) -> Option<usize> {
        let search_limit = row_count.min(MAX_SEARCH_ROWS);
        let text_lower = self.text.to_lowercase();

        // Search from start_row forward, wrapping around.
        for offset in 0..search_limit {
            let row = (start_row + offset) % search_limit;
            if let Some(val) = get_value(row, self.lookup_column) {
                if val.to_lowercase().starts_with(&text_lower) {
                    return Some(row);
                }
            }
        }
        None
    }

    /// Binary search on a sorted column.
    fn binary_search(
        &self,
        row_count: usize,
        ascending: bool,
        get_value: &impl Fn(usize, usize) -> Option<String>,
    ) -> Option<usize> {
        let text_lower = self.text.to_lowercase();
        let text_len = text_lower.len();
        let search_limit = row_count.min(MAX_SEARCH_ROWS);
        use std::cmp::Ordering;

        let mut lo = 0usize;
        let mut hi = search_limit;
        let mut result = None;

        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if let Some(val) = get_value(mid, self.lookup_column) {
                let val_lower = val.to_lowercase();
                // Compare using the prefix of val (same length as search text)
                let prefix = &val_lower[..val_lower.len().min(text_len)];
                let cmp = prefix.cmp(text_lower.as_str());

                match cmp {
                    Ordering::Equal => {
                        // Found a match — record and keep searching left
                        result = Some(mid);
                        hi = mid;
                    }
                    Ordering::Greater => {
                        if ascending {
                            // In ascending, greater prefix means we might
                            // find a match to the left
                            hi = mid;
                        } else {
                            // In descending, greater prefix means the match
                            // is to the right (smaller values)
                            lo = mid + 1;
                        }
                    }
                    Ordering::Less => {
                        if ascending {
                            // In ascending, less prefix means search right
                            lo = mid + 1;
                        } else {
                            // In descending, less prefix means search left
                            hi = mid;
                        }
                    }
                }
            } else {
                break;
            }
        }

        // Verify the result starts with the search text.
        if let Some(row) = result {
            if let Some(val) = get_value(row, self.lookup_column) {
                if val.to_lowercase().starts_with(&text_lower) {
                    return Some(row);
                }
            }
        }
        None
    }
}

impl Default for AutoLookup {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_get_value(data: Vec<String>) -> impl Fn(usize, usize) -> Option<String> {
        move |row, _col| data.get(row).cloned()
    }

    #[test]
    fn test_basic_lookup() {
        let mut lookup = AutoLookup::new();
        let data = vec![
            "apple".to_string(),
            "banana".to_string(),
            "cherry".to_string(),
        ];
        let get = make_get_value(data);

        let result = lookup.process_char('b', 3, false, true, &get);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_multi_char_lookup() {
        let mut lookup = AutoLookup::new();
        let data = vec![
            "apple".to_string(),
            "avocado".to_string(),
            "banana".to_string(),
        ];
        let get = make_get_value(data);

        lookup.process_char('a', 3, false, true, &get);
        let result = lookup.process_char('v', 3, false, true, &get);
        assert_eq!(result, Some(1)); // avocado
    }

    #[test]
    fn test_case_insensitive() {
        let mut lookup = AutoLookup::new();
        let data = vec!["Apple".to_string(), "Banana".to_string()];
        let get = make_get_value(data);

        let result = lookup.process_char('a', 2, false, true, &get);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_no_match() {
        let mut lookup = AutoLookup::new();
        let data = vec!["apple".to_string(), "banana".to_string()];
        let get = make_get_value(data);

        let result = lookup.process_char('z', 2, false, true, &get);
        assert_eq!(result, None);
    }

    #[test]
    fn test_empty_data() {
        let mut lookup = AutoLookup::new();
        let data: Vec<String> = vec![];
        let get = make_get_value(data);

        let result = lookup.process_char('a', 0, false, true, &get);
        assert_eq!(result, None);
    }

    #[test]
    fn test_set_column() {
        let mut lookup = AutoLookup::new();
        lookup.set_column(5);
        assert_eq!(lookup.column(), 5);
    }

    #[test]
    fn test_reset() {
        let mut lookup = AutoLookup::new();
        let data = vec!["apple".to_string()];
        let get = make_get_value(data);

        lookup.process_char('a', 1, false, true, &get);
        assert!(!lookup.text().is_empty());
        lookup.reset();
        assert!(lookup.text().is_empty());
        assert_eq!(lookup.last_match_row(), None);
    }

    #[test]
    fn test_binary_search_ascending() {
        let mut lookup = AutoLookup::new();
        let data = vec![
            "alpha".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
        ];
        let get = make_get_value(data);

        let result = lookup.process_char('b', 3, true, true, &get);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_binary_search_descending() {
        let mut lookup = AutoLookup::new();
        let data = vec![
            "gamma".to_string(),
            "beta".to_string(),
            "alpha".to_string(),
        ];
        let get = make_get_value(data);

        let result = lookup.process_char('b', 3, true, false, &get);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_timeout() {
        let mut lookup = AutoLookup::new();
        lookup.set_timeout(Duration::from_millis(0)); // immediate timeout

        let data = vec!["apple".to_string(), "avocado".to_string()];
        let get = make_get_value(data);

        lookup.process_char('a', 2, false, true, &get);
        // With 0ms timeout, next char starts a new lookup
        let result = lookup.process_char('a', 2, false, true, &get);
        assert_eq!(result, Some(0));
    }
}
