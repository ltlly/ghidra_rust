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

/// Status of a BSim result after an apply attempt.
///
/// Ports `ghidra.features.bsim.gui.search.results.BSimResultStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BSimResultStatus {
    /// This result has not been applied.
    NotApplied,
    /// The name and namespace have been applied.
    NameApplied,
    /// The name, namespace and signature have been applied.
    SignatureApplied,
    /// The name already matches.
    Matches,
    /// This result has been applied, but no longer matches.
    AppliedNoLongerMatches,
    /// An error occurred while attempting to apply this result.
    Error,
    /// There is no longer a function at the result address.
    NoFunction,
    /// The result was not applied because it already matched.
    Ignored,
}

impl BSimResultStatus {
    /// Get a human-readable description of this status.
    pub fn description(&self) -> &'static str {
        match self {
            Self::NotApplied => "This result has not been applied.",
            Self::NameApplied => "The name and namespace have been applied.",
            Self::SignatureApplied => "The name, namespace and signature have been applied.",
            Self::Matches => "The name already matches.",
            Self::AppliedNoLongerMatches => {
                "This result has been applied, but no longer matches!"
            }
            Self::Error => "An error occurred while attempting to apply this result.",
            Self::NoFunction => "There is no longer a function at the result address!",
            Self::Ignored => "The result was not applied because it already matched.",
        }
    }

    /// Whether this status represents a successfully applied result.
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::NameApplied | Self::SignatureApplied)
    }

    /// Whether this status represents an error state.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error | Self::AppliedNoLongerMatches)
    }
}

impl Default for BSimResultStatus {
    fn default() -> Self {
        Self::NotApplied
    }
}

impl std::fmt::Display for BSimResultStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApplied => write!(f, "Not Applied"),
            Self::NameApplied => write!(f, "Name Applied"),
            Self::SignatureApplied => write!(f, "Signature Applied"),
            Self::Matches => write!(f, "Matches"),
            Self::AppliedNoLongerMatches => write!(f, "Applied (No Longer Matches)"),
            Self::Error => write!(f, "Error"),
            Self::NoFunction => write!(f, "No Function"),
            Self::Ignored => write!(f, "Ignored"),
        }
    }
}

/// Icon type for BSim result status display.
///
/// Ports `ghidra.features.bsim.gui.search.results.BSimStatusRenderer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BSimStatusIcon {
    /// No icon (for NotApplied).
    None,
    /// Info icon (for NameApplied).
    Info,
    /// Check icon (for SignatureApplied).
    Check,
    /// Warning icon (for AppliedNoLongerMatches).
    Warning,
    /// Error icon (for Error).
    Error,
    /// Strong warning icon (for NoFunction).
    StrongWarning,
    /// Circle icon (for Matches).
    Circle,
    /// Gray circle icon (for Ignored).
    GrayCircle,
}

impl BSimResultStatus {
    /// Get the icon type for this status.
    pub fn icon(&self) -> BSimStatusIcon {
        match self {
            Self::NotApplied => BSimStatusIcon::None,
            Self::NameApplied => BSimStatusIcon::Info,
            Self::SignatureApplied => BSimStatusIcon::Check,
            Self::Matches => BSimStatusIcon::Circle,
            Self::AppliedNoLongerMatches => BSimStatusIcon::Warning,
            Self::Error => BSimStatusIcon::Error,
            Self::NoFunction => BSimStatusIcon::StrongWarning,
            Self::Ignored => BSimStatusIcon::GrayCircle,
        }
    }
}

/// A possible BSim function match result.
///
/// Ports `ghidra.features.bsim.gui.search.results.BSimMatchResult`.
#[derive(Debug, Clone)]
pub struct BSimMatchResult {
    /// Original queried function name.
    pub original_function_name: String,
    /// Original function address.
    pub original_function_address: u64,
    /// Similar function name in the BSim database.
    pub similar_function_name: String,
    /// Similar function address.
    pub similar_function_address: u64,
    /// Executable name containing the similar function.
    pub executable_name: String,
    /// Architecture of the similar function.
    pub architecture: String,
    /// Similarity score (0.0 to 1.0).
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
    /// MD5 hash of the similar function's executable.
    pub md5: String,
    /// Apply status.
    pub status: BSimResultStatus,
}

impl BSimMatchResult {
    /// Create a new match result.
    pub fn new(
        original_function_name: impl Into<String>,
        original_function_address: u64,
        similar_function_name: impl Into<String>,
        similarity: f64,
    ) -> Self {
        Self {
            original_function_name: original_function_name.into(),
            original_function_address,
            similar_function_name: similar_function_name.into(),
            similar_function_address: 0,
            executable_name: String::new(),
            architecture: String::new(),
            similarity,
            significance: 0.0,
            md5: String::new(),
            status: BSimResultStatus::default(),
        }
    }

    /// Whether this is a high-confidence match.
    pub fn is_high_confidence(&self) -> bool {
        self.similarity >= 0.8 && self.significance >= 0.01
    }

    /// Set the status, respecting the "ignore already applied" rule.
    ///
    /// If the new status is `Ignored` and the current status is `NameApplied`
    /// or `SignatureApplied`, the status will not change.
    pub fn set_status(&mut self, status: BSimResultStatus) {
        if status == BSimResultStatus::Ignored {
            if matches!(
                self.status,
                BSimResultStatus::NameApplied | BSimResultStatus::SignatureApplied
            ) {
                return;
            }
        }
        self.status = status;
    }

    /// Format the similarity as a percentage string.
    pub fn similarity_percent(&self) -> String {
        format!("{:.1}%", self.similarity * 100.0)
    }
}

/// Model for BSim match results table.
///
/// Ports `ghidra.features.bsim.gui.search.results.BSimMatchResultsModel`.
#[derive(Debug, Clone, Default)]
pub struct BSimMatchResultsModel {
    /// The match results.
    pub results: Vec<BSimMatchResult>,
}

impl BSimMatchResultsModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of results.
    pub fn row_count(&self) -> usize {
        self.results.len()
    }

    /// Add a match result.
    pub fn add_result(&mut self, result: BSimMatchResult) {
        self.results.push(result);
    }

    /// Sort results by similarity (descending).
    pub fn sort_by_similarity(&mut self) {
        self.results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Sort results by significance (descending).
    pub fn sort_by_significance(&mut self) {
        self.results.sort_by(|a, b| {
            b.significance
                .partial_cmp(&a.significance)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Get results with a specific status.
    pub fn results_with_status(&self, status: BSimResultStatus) -> Vec<&BSimMatchResult> {
        self.results.iter().filter(|r| r.status == status).collect()
    }

    /// Get the number of applied results.
    pub fn applied_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.status.is_applied())
            .count()
    }

    /// Get the number of error results.
    pub fn error_count(&self) -> usize {
        self.results.iter().filter(|r| r.status.is_error()).count()
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.results.clear();
    }
}

/// Summary model for executables in BSim search results.
///
/// Ports `ghidra.features.bsim.gui.search.results.BSimExecutablesSummaryModel`.
#[derive(Debug, Clone, Default)]
pub struct BSimExecutablesSummaryModel {
    /// Summary entries.
    pub entries: Vec<ExecutableSummaryEntry>,
}

/// A summary entry for an executable in the BSim database.
#[derive(Debug, Clone)]
pub struct ExecutableSummaryEntry {
    /// Executable name.
    pub name: String,
    /// Architecture.
    pub architecture: String,
    /// Compiler.
    pub compiler: String,
    /// MD5 hash.
    pub md5: String,
    /// Number of matched functions from this executable.
    pub match_count: usize,
    /// Average similarity across all matched functions.
    pub average_similarity: f64,
}

impl BSimExecutablesSummaryModel {
    /// Create a new empty summary model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a summary entry.
    pub fn add_entry(&mut self, entry: ExecutableSummaryEntry) {
        self.entries.push(entry);
    }

    /// Get the number of executables.
    pub fn executable_count(&self) -> usize {
        self.entries.len()
    }

    /// Sort entries by match count (descending).
    pub fn sort_by_match_count(&mut self) {
        self.entries.sort_by(|a, b| b.match_count.cmp(&a.match_count));
    }
}

/// Settings definition for showing/hiding namespaces in BSim results.
///
/// Ports `ghidra.features.bsim.gui.search.results.ShowNamespaceSettingsDefinition`.
#[derive(Debug, Clone)]
pub struct ShowNamespaceSettingsDefinition {
    /// Whether to show namespaces in result names.
    pub show_namespace: bool,
    /// The separator between namespace and function name.
    pub separator: String,
}

impl Default for ShowNamespaceSettingsDefinition {
    fn default() -> Self {
        Self {
            show_namespace: true,
            separator: "::".to_string(),
        }
    }
}

impl ShowNamespaceSettingsDefinition {
    /// Create a new settings definition.
    pub fn new() -> Self {
        Self::default()
    }

    /// Format a function name with its namespace.
    pub fn format_function_name(&self, namespace: &str, name: &str) -> String {
        if self.show_namespace && !namespace.is_empty() {
            format!("{}{}{}", namespace, self.separator, name)
        } else {
            name.to_string()
        }
    }

    /// Strip the namespace from a fully qualified name.
    pub fn strip_namespace<'a>(&self, qualified_name: &'a str) -> &'a str {
        if let Some(pos) = qualified_name.rfind(&self.separator) {
            &qualified_name[pos + self.separator.len()..]
        } else {
            qualified_name
        }
    }
}

/// Exception for function comparison errors.
///
/// Ports `ghidra.features.bsim.gui.search.results.FunctionComparisonException`.
#[derive(Debug, Clone)]
pub struct FunctionComparisonException {
    /// Error message.
    pub message: String,
    /// The function name that caused the error.
    pub function_name: String,
}

impl FunctionComparisonException {
    /// Create a new comparison exception.
    pub fn new(message: impl Into<String>, function_name: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            function_name: function_name.into(),
        }
    }
}

impl std::fmt::Display for FunctionComparisonException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Function comparison error for '{}': {}",
            self.function_name, self.message
        )
    }
}

impl std::error::Error for FunctionComparisonException {}

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

    #[test]
    fn test_bsim_result_status_display() {
        assert_eq!(BSimResultStatus::NotApplied.to_string(), "Not Applied");
        assert_eq!(BSimResultStatus::NameApplied.to_string(), "Name Applied");
        assert_eq!(
            BSimResultStatus::SignatureApplied.to_string(),
            "Signature Applied"
        );
    }

    #[test]
    fn test_bsim_result_status_is_applied() {
        assert!(!BSimResultStatus::NotApplied.is_applied());
        assert!(BSimResultStatus::NameApplied.is_applied());
        assert!(BSimResultStatus::SignatureApplied.is_applied());
    }

    #[test]
    fn test_bsim_result_status_is_error() {
        assert!(BSimResultStatus::Error.is_error());
        assert!(BSimResultStatus::AppliedNoLongerMatches.is_error());
        assert!(!BSimResultStatus::NotApplied.is_error());
    }

    #[test]
    fn test_bsim_result_status_icon() {
        assert_eq!(BSimResultStatus::NotApplied.icon(), BSimStatusIcon::None);
        assert_eq!(BSimResultStatus::Error.icon(), BSimStatusIcon::Error);
    }

    #[test]
    fn test_bsim_result_status_description() {
        assert!(!BSimResultStatus::NotApplied.description().is_empty());
        assert!(!BSimResultStatus::Error.description().is_empty());
    }

    #[test]
    fn test_bsim_match_result_new() {
        let result = BSimMatchResult::new("main", 0x1000, "printf", 0.95);
        assert_eq!(result.original_function_name, "main");
        assert_eq!(result.similar_function_name, "printf");
        assert!((result.similarity - 0.95).abs() < f64::EPSILON);
        assert_eq!(result.status, BSimResultStatus::NotApplied);
    }

    #[test]
    fn test_bsim_match_result_high_confidence() {
        let mut result = BSimMatchResult::new("main", 0x1000, "printf", 0.95);
        result.significance = 0.05;
        assert!(result.is_high_confidence());

        result.significance = 0.001;
        assert!(!result.is_high_confidence());
    }

    #[test]
    fn test_bsim_match_result_set_status_ignore_rule() {
        let mut result = BSimMatchResult::new("main", 0x1000, "printf", 0.95);
        result.status = BSimResultStatus::NameApplied;
        result.set_status(BSimResultStatus::Ignored);
        // Should not change because NameApplied is protected from Ignored.
        assert_eq!(result.status, BSimResultStatus::NameApplied);
    }

    #[test]
    fn test_bsim_match_result_set_status_normal() {
        let mut result = BSimMatchResult::new("main", 0x1000, "printf", 0.95);
        result.set_status(BSimResultStatus::Error);
        assert_eq!(result.status, BSimResultStatus::Error);
    }

    #[test]
    fn test_bsim_match_result_similarity_percent() {
        let result = BSimMatchResult::new("main", 0x1000, "printf", 0.85);
        assert_eq!(result.similarity_percent(), "85.0%");
    }

    #[test]
    fn test_bsim_match_results_model() {
        let mut model = BSimMatchResultsModel::new();
        assert_eq!(model.row_count(), 0);

        model.add_result(BSimMatchResult::new("f1", 0x1000, "g1", 0.9));
        model.add_result(BSimMatchResult::new("f2", 0x2000, "g2", 0.3));
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_bsim_match_results_model_sort() {
        let mut model = BSimMatchResultsModel::new();
        model.add_result(BSimMatchResult::new("f1", 0x1000, "g1", 0.3));
        model.add_result(BSimMatchResult::new("f2", 0x2000, "g2", 0.9));
        model.add_result(BSimMatchResult::new("f3", 0x3000, "g3", 0.7));

        model.sort_by_similarity();
        assert!((model.results[0].similarity - 0.9).abs() < f64::EPSILON);
        assert!((model.results[1].similarity - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_bsim_match_results_model_status_filter() {
        let mut model = BSimMatchResultsModel::new();
        let mut r1 = BSimMatchResult::new("f1", 0x1000, "g1", 0.9);
        r1.status = BSimResultStatus::NameApplied;
        model.add_result(r1);
        model.add_result(BSimMatchResult::new("f2", 0x2000, "g2", 0.3));

        let applied = model.results_with_status(BSimResultStatus::NameApplied);
        assert_eq!(applied.len(), 1);
        assert_eq!(model.applied_count(), 1);
        assert_eq!(model.error_count(), 0);
    }

    #[test]
    fn test_executables_summary_model() {
        let mut model = BSimExecutablesSummaryModel::new();
        model.add_entry(ExecutableSummaryEntry {
            name: "libc.so".into(),
            architecture: "x86".into(),
            compiler: "gcc".into(),
            md5: "abc123".into(),
            match_count: 50,
            average_similarity: 0.85,
        });
        assert_eq!(model.executable_count(), 1);
    }

    #[test]
    fn test_show_namespace_settings() {
        let settings = ShowNamespaceSettingsDefinition::new();
        assert_eq!(
            settings.format_function_name("std", "printf"),
            "std::printf"
        );
        assert_eq!(settings.format_function_name("", "main"), "main");
        assert_eq!(settings.strip_namespace("std::printf"), "printf");
        assert_eq!(settings.strip_namespace("main"), "main");
    }

    #[test]
    fn test_show_namespace_disabled() {
        let settings = ShowNamespaceSettingsDefinition {
            show_namespace: false,
            ..Default::default()
        };
        assert_eq!(
            settings.format_function_name("std", "printf"),
            "printf"
        );
    }

    #[test]
    fn test_function_comparison_exception() {
        let err = FunctionComparisonException::new("not found", "main");
        assert!(err.to_string().contains("main"));
        assert!(err.to_string().contains("not found"));
    }
}
