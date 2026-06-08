//! Table filter trait.
//!
//! Port of Ghidra's `TableFilter<ROW_OBJECT>` interface. A filter is a
//! predicate over row objects that determines which rows are visible.

/// A filter that determines whether a row object should be visible in the table.
///
/// Implementors define matching logic (text search, column filter, etc.).
pub trait TableFilter<ROW_OBJECT> {
    /// Returns `true` if the given row object passes this filter.
    fn accepts_row(&self, row_object: &ROW_OBJECT) -> bool;

    /// Returns `true` if this filter is a more specific version of the given
    /// filter. For example, a "starts with bobo" filter is a sub-filter of
    /// "starts with bob".
    ///
    /// The default implementation returns `false`.
    fn is_sub_filter_of(&self, _other: &dyn TableFilter<ROW_OBJECT>) -> bool {
        false
    }

    /// Returns `true` if there is a column-specific filter on the given column.
    fn has_column_filter(&self, _column_model_index: usize) -> bool {
        false
    }

    /// Returns `true` if this filter performs no actual filtering (e.g. an
    /// empty text filter).
    fn is_empty(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Built-in filter implementations
// ---------------------------------------------------------------------------

/// A filter that accepts all rows (no filtering).
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAllFilter;

impl<ROW_OBJECT> TableFilter<ROW_OBJECT> for AcceptAllFilter {
    fn accepts_row(&self, _row_object: &ROW_OBJECT) -> bool {
        true
    }

    fn is_empty(&self) -> bool {
        true
    }
}

/// A text-contains filter that checks if any string representation of the row
/// contains the given text (case-insensitive).
#[derive(Debug, Clone)]
pub struct TextContainsFilter {
    text: String,
}

impl TextContainsFilter {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }

    #[allow(dead_code)]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl<T: ToString> TableFilter<T> for TextContainsFilter {
    fn accepts_row(&self, row_object: &T) -> bool {
        if self.text.is_empty() {
            return true;
        }
        let row_str = row_object.to_string();
        row_str.to_lowercase().contains(&self.text.to_lowercase())
    }

    fn is_sub_filter_of(&self, _other: &dyn TableFilter<T>) -> bool {
        // If other is also a TextContainsFilter and our text starts with
        // their text, we are a sub-filter.
        // This is a simplified check — full implementation would downcast.
        false
    }

    fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

/// A combined filter that requires all sub-filters to accept the row.
#[allow(dead_code)]
pub struct CombinedFilter<T> {
    filters: Vec<Box<dyn TableFilter<T>>>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for CombinedFilter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CombinedFilter")
            .field("filter_count", &self.filters.len())
            .finish()
    }
}

impl<T> CombinedFilter<T> {
    pub fn new(filters: Vec<Box<dyn TableFilter<T>>>) -> Self {
        Self { filters }
    }
}

impl<T> TableFilter<T> for CombinedFilter<T> {
    fn accepts_row(&self, row_object: &T) -> bool {
        self.filters.iter().all(|f| f.accepts_row(row_object))
    }

    fn is_empty(&self) -> bool {
        self.filters.iter().all(|f| f.is_empty())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accept_all() {
        let filter: AcceptAllFilter = AcceptAllFilter;
        assert!(TableFilter::<String>::accepts_row(&filter, &"anything".to_string()));
        assert!(TableFilter::<String>::is_empty(&filter));
    }

    #[test]
    fn test_text_contains_filter() {
        let filter = TextContainsFilter::new("bob");
        let filter: &dyn TableFilter<String> = &filter;
        assert!(filter.accepts_row(&"bobby".to_string()));
        assert!(filter.accepts_row(&"Bob Smith".to_string()));
        assert!(!filter.accepts_row(&"alice".to_string()));
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_text_contains_filter_empty() {
        let filter = TextContainsFilter::new("");
        let filter: &dyn TableFilter<String> = &filter;
        assert!(filter.accepts_row(&"anything".to_string()));
        assert!(filter.is_empty());
    }

    #[test]
    fn test_text_contains_filter_case_insensitive() {
        let filter = TextContainsFilter::new("HELLO");
        assert!(filter.accepts_row(&"say hello world".to_string()));
    }

    #[test]
    fn test_combined_filter() {
        let f1: Box<dyn TableFilter<String>> = Box::new(TextContainsFilter::new("a"));
        let f2: Box<dyn TableFilter<String>> = Box::new(TextContainsFilter::new("b"));
        let combined = CombinedFilter::new(vec![f1, f2]);

        // Must contain both 'a' and 'b'
        assert!(combined.accepts_row(&"abc".to_string()));
        assert!(!combined.accepts_row(&"apple".to_string())); // has 'a' but no 'b'
        assert!(combined.accepts_row(&"banana".to_string())); // has both 'a' and 'b'
    }

    #[test]
    fn test_combined_filter_empty() {
        let f1: Box<dyn TableFilter<String>> = Box::new(TextContainsFilter::new(""));
        let f2: Box<dyn TableFilter<String>> = Box::new(TextContainsFilter::new(""));
        let combined = CombinedFilter::new(vec![f1, f2]);
        assert!(combined.is_empty());
    }

    #[test]
    fn test_sub_filter_default() {
        let f1 = TextContainsFilter::new("a");
        let f2 = TextContainsFilter::new("b");
        let f2: &dyn TableFilter<String> = &f2;
        assert!(!f1.is_sub_filter_of(f2));
    }
}
