//! BSim search results display types.
//!
//! Ports `ghidra.features.bsim.gui.search.results` from Ghidra's Java source.

/// A row in the BSim search results table.
#[derive(Debug, Clone)]
pub struct BSimResultRow {
    /// The function name.
    pub function_name: String,
    /// Entry point address.
    pub entry_point: u64,
    /// Similarity score.
    pub similarity: f64,
    /// Executable name.
    pub executable_name: String,
    /// Architecture.
    pub architecture: String,
    /// Compiler.
    pub compiler: String,
    /// Function hash.
    pub function_hash: String,
}

impl BSimResultRow {
    /// Create a new result row.
    pub fn new(
        function_name: impl Into<String>,
        entry_point: u64,
        similarity: f64,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            entry_point,
            similarity,
            executable_name: String::new(),
            architecture: String::new(),
            compiler: String::new(),
            function_hash: String::new(),
        }
    }

    /// Whether this result is a high-confidence match.
    pub fn is_high_confidence(&self) -> bool {
        self.similarity >= 0.8
    }

    /// Format the similarity as a percentage string.
    pub fn similarity_percent(&self) -> String {
        format!("{:.1}%", self.similarity * 100.0)
    }
}

/// Model for the search results table.
#[derive(Debug, Clone, Default)]
pub struct BSimSearchResultsModel {
    /// The result rows.
    pub rows: Vec<BSimResultRow>,
}

impl BSimSearchResultsModel {
    /// Create a new empty results model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of results.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Add a result.
    pub fn add_result(&mut self, row: BSimResultRow) {
        self.rows.push(row);
    }

    /// Sort results by similarity (descending).
    pub fn sort_by_similarity(&mut self) {
        self.rows.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Filter to only high-confidence results.
    pub fn high_confidence_results(&self) -> Vec<&BSimResultRow> {
        self.rows.iter().filter(|r| r.is_high_confidence()).collect()
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

/// Apply types for applying BSim results to a program.
pub mod apply {
    /// Action to take when applying a BSim match.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ApplyAction {
        /// Rename the function to match.
        Rename,
        /// Apply function signature.
        ApplySignature,
        /// Apply function tags.
        ApplyTags,
        /// Mark as known library function.
        MarkLibrary,
    }

    /// Result of applying a BSim match to a program function.
    #[derive(Debug, Clone)]
    pub struct ApplyResult {
        /// The action that was taken.
        pub action: ApplyAction,
        /// Whether the application was successful.
        pub success: bool,
        /// Error message if failed.
        pub error: Option<String>,
    }

    impl ApplyResult {
        /// Create a successful result.
        pub fn success(action: ApplyAction) -> Self {
            Self {
                action,
                success: true,
                error: None,
            }
        }

        /// Create a failed result.
        pub fn failure(action: ApplyAction, error: impl Into<String>) -> Self {
            Self {
                action,
                success: false,
                error: Some(error.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_row_new() {
        let row = BSimResultRow::new("main", 0x1000, 0.95);
        assert_eq!(row.function_name, "main");
        assert_eq!(row.entry_point, 0x1000);
        assert!((row.similarity - 0.95).abs() < f64::EPSILON);
        assert!(row.is_high_confidence());
        assert_eq!(row.similarity_percent(), "95.0%");
    }

    #[test]
    fn test_result_row_low_confidence() {
        let row = BSimResultRow::new("func", 0x2000, 0.3);
        assert!(!row.is_high_confidence());
        assert_eq!(row.similarity_percent(), "30.0%");
    }

    #[test]
    fn test_results_model() {
        let mut model = BSimSearchResultsModel::new();
        assert_eq!(model.row_count(), 0);

        model.add_result(BSimResultRow::new("f1", 0x1000, 0.9));
        model.add_result(BSimResultRow::new("f2", 0x2000, 0.3));
        model.add_result(BSimResultRow::new("f3", 0x3000, 0.85));
        assert_eq!(model.row_count(), 3);
    }

    #[test]
    fn test_results_model_sort() {
        let mut model = BSimSearchResultsModel::new();
        model.add_result(BSimResultRow::new("f1", 0x1000, 0.3));
        model.add_result(BSimResultRow::new("f2", 0x2000, 0.9));
        model.add_result(BSimResultRow::new("f3", 0x3000, 0.7));

        model.sort_by_similarity();
        assert!((model.rows[0].similarity - 0.9).abs() < f64::EPSILON);
        assert!((model.rows[1].similarity - 0.7).abs() < f64::EPSILON);
        assert!((model.rows[2].similarity - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_high_confidence_filter() {
        let mut model = BSimSearchResultsModel::new();
        model.add_result(BSimResultRow::new("f1", 0x1000, 0.9));
        model.add_result(BSimResultRow::new("f2", 0x2000, 0.3));
        model.add_result(BSimResultRow::new("f3", 0x3000, 0.85));

        let high = model.high_confidence_results();
        assert_eq!(high.len(), 2);
    }

    #[test]
    fn test_apply_result() {
        let result = apply::ApplyResult::success(apply::ApplyAction::Rename);
        assert!(result.success);
        assert!(result.error.is_none());

        let result = apply::ApplyResult::failure(
            apply::ApplyAction::ApplySignature,
            "function not found",
        );
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("function not found"));
    }
}
