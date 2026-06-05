//! BSim description types.
//!
//! Re-exports the core description types from the parent `bsim` module.
//! Additional query-specific description utilities are provided here.

pub mod description_significance;

pub use super::super::description::{
    CategoryRecord, DatabaseInformation, DescriptionManager, ExecutableRecord,
    FunctionDescription, RowKey, SignatureRecord, VectorResult, CallgraphEntry,
};

pub use description_significance::{
    DescriptionSignificance, SignificanceResult, SignificanceLevel, SignificanceConfig,
};

use serde::{Deserialize, Serialize};

/// Function tag for labeling functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTag {
    /// Tag name.
    pub name: String,
    /// Tag category.
    pub category: String,
}

impl FunctionTag {
    /// Create a new function tag.
    pub fn new(name: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category: category.into(),
        }
    }

    /// Get a display string for this tag.
    pub fn display(&self) -> String {
        format!("[{}] {}", self.category, self.name)
    }

    /// Whether this tag matches a given category.
    pub fn matches_category(&self, category: &str) -> bool {
        self.category == category
    }
}

/// Metadata for a BSim search result row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResultRow {
    /// The matched function description.
    pub function: FunctionDescription,
    /// The similarity score from the search.
    pub similarity: f64,
    /// The significance of the match.
    pub significance: f64,
    /// Rank of this result (1-based).
    pub rank: usize,
}

impl SearchResultRow {
    /// Create a new search result row.
    pub fn new(
        function: FunctionDescription,
        similarity: f64,
        significance: f64,
        rank: usize,
    ) -> Self {
        Self {
            function,
            similarity,
            significance,
            rank,
        }
    }

    /// Whether this is a high-confidence match (similarity > 0.8).
    pub fn is_high_confidence(&self) -> bool {
        self.similarity > 0.8
    }

    /// Whether this is a medium-confidence match (0.5 < similarity <= 0.8).
    pub fn is_medium_confidence(&self) -> bool {
        self.similarity > 0.5 && self.similarity <= 0.8
    }

    /// Get the score (similarity * significance).
    pub fn score(&self) -> f64 {
        self.similarity * self.significance
    }
}

/// A collection of search results from a BSim query.
#[derive(Debug, Clone, Default)]
pub struct SearchResultCollection {
    /// The rows of results.
    rows: Vec<SearchResultRow>,
    /// Total number of functions queried.
    total_queried: usize,
}

impl SearchResultCollection {
    /// Create an empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a collection with the given total queried count.
    pub fn with_total_queried(mut self, total: usize) -> Self {
        self.total_queried = total;
        self
    }

    /// Add a result row.
    pub fn add(&mut self, row: SearchResultRow) {
        self.rows.push(row);
    }

    /// Get all rows.
    pub fn rows(&self) -> &[SearchResultRow] {
        &self.rows
    }

    /// Get the number of results.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are no results.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get high-confidence results.
    pub fn high_confidence(&self) -> Vec<&SearchResultRow> {
        self.rows.iter().filter(|r| r.is_high_confidence()).collect()
    }

    /// Get the best (highest-scoring) result.
    pub fn best(&self) -> Option<&SearchResultRow> {
        self.rows
            .iter()
            .max_by(|a, b| a.score().partial_cmp(&b.score()).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Sort results by score descending.
    pub fn sort_by_score(&mut self) {
        self.rows
            .sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap_or(std::cmp::Ordering::Equal));
    }

    /// Get the match rate (matched / queried).
    pub fn match_rate(&self) -> f64 {
        if self.total_queried == 0 {
            0.0
        } else {
            self.rows.len() as f64 / self.total_queried as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_tag() {
        let tag = FunctionTag::new("library", "libc");
        assert_eq!(tag.name, "library");
        assert_eq!(tag.category, "libc");
    }

    #[test]
    fn test_re_exported_types() {
        let func = FunctionDescription::new(0, "main", Some(0x1000));
        assert_eq!(func.function_name, "main");
    }

    #[test]
    fn test_function_tag_display() {
        let tag = FunctionTag::new("libc", "stdlib");
        assert_eq!(tag.display(), "[stdlib] libc");
    }

    #[test]
    fn test_function_tag_matches_category() {
        let tag = FunctionTag::new("malloc", "stdlib");
        assert!(tag.matches_category("stdlib"));
        assert!(!tag.matches_category("math"));
    }

    #[test]
    fn test_search_result_row_high_confidence() {
        let func = FunctionDescription::new(0, "main", Some(0x1000));
        let row = SearchResultRow::new(func, 0.95, 0.9, 1);
        assert!(row.is_high_confidence());
        assert!(!row.is_medium_confidence());
        assert_eq!(row.rank, 1);
    }

    #[test]
    fn test_search_result_row_medium_confidence() {
        let func = FunctionDescription::new(0, "foo", Some(0x2000));
        let row = SearchResultRow::new(func, 0.6, 0.7, 2);
        assert!(!row.is_high_confidence());
        assert!(row.is_medium_confidence());
    }

    #[test]
    fn test_search_result_score() {
        let func = FunctionDescription::new(0, "bar", Some(0x3000));
        let row = SearchResultRow::new(func, 0.8, 0.5, 1);
        assert!((row.score() - 0.4).abs() < 1e-9);
    }

    #[test]
    fn test_search_result_collection() {
        let mut coll = SearchResultCollection::new();
        assert!(coll.is_empty());
        assert_eq!(coll.match_rate(), 0.0);

        coll.add(SearchResultRow::new(
            FunctionDescription::new(0, "main", Some(0x1000)),
            0.9, 0.8, 1,
        ));
        coll.add(SearchResultRow::new(
            FunctionDescription::new(0, "foo", Some(0x2000)),
            0.6, 0.5, 2,
        ));

        assert_eq!(coll.len(), 2);
        assert_eq!(coll.high_confidence().len(), 1);
    }

    #[test]
    fn test_search_result_collection_best() {
        let mut coll = SearchResultCollection::new();
        coll.add(SearchResultRow::new(
            FunctionDescription::new(0, "a", Some(0x1000)),
            0.5, 0.5, 1,
        ));
        coll.add(SearchResultRow::new(
            FunctionDescription::new(0, "b", Some(0x2000)),
            0.9, 0.9, 2,
        ));
        let best = coll.best().unwrap();
        assert_eq!(best.function.function_name, "b");
    }

    #[test]
    fn test_search_result_collection_sort() {
        let mut coll = SearchResultCollection::new();
        coll.add(SearchResultRow::new(
            FunctionDescription::new(0, "a", Some(0x1000)),
            0.3, 0.5, 1,
        ));
        coll.add(SearchResultRow::new(
            FunctionDescription::new(0, "b", Some(0x2000)),
            0.9, 0.9, 2,
        ));
        coll.add(SearchResultRow::new(
            FunctionDescription::new(0, "c", Some(0x3000)),
            0.7, 0.8, 3,
        ));

        coll.sort_by_score();
        assert_eq!(coll.rows()[0].function.function_name, "b");
        assert_eq!(coll.rows()[2].function.function_name, "a");
    }

    #[test]
    fn test_search_result_collection_match_rate() {
        let mut coll = SearchResultCollection::new().with_total_queried(10);
        coll.add(SearchResultRow::new(
            FunctionDescription::new(0, "a", Some(0x1000)),
            0.8, 0.7, 1,
        ));
        assert!((coll.match_rate() - 0.1).abs() < 1e-9);
    }
}
