//! BSim search result and apply result types.
//!
//! Ports `ghidra.features.bsim.gui.search.results` from Ghidra's Java source.
//!
//! Contains the data model for BSim search results, match scoring,
//! and apply operations (renaming, re-typing, etc.).

use serde::{Deserialize, Serialize};

// ============================================================================
// BSimResultStatus -- Status of a BSim result
// ============================================================================

/// Status of a BSim search or apply operation.
///
/// Ports `ghidra.features.bsim.gui.BSimResultStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BSimResultStatus {
    /// The result is a strong match (high similarity).
    StrongMatch,
    /// The result is a moderate match.
    ModerateMatch,
    /// The result is a weak match (low similarity).
    WeakMatch,
    /// The result has been applied (e.g., name copied).
    Applied,
    /// The result was skipped.
    Skipped,
    /// There was an error processing this result.
    Error,
    /// The result status is unknown.
    Unknown,
}

impl BSimResultStatus {
    /// Whether this status indicates a usable match.
    pub fn is_match(&self) -> bool {
        matches!(
            self,
            BSimResultStatus::StrongMatch
                | BSimResultStatus::ModerateMatch
                | BSimResultStatus::WeakMatch
        )
    }

    /// Get a display label for this status.
    pub fn label(&self) -> &str {
        match self {
            BSimResultStatus::StrongMatch => "Strong Match",
            BSimResultStatus::ModerateMatch => "Moderate Match",
            BSimResultStatus::WeakMatch => "Weak Match",
            BSimResultStatus::Applied => "Applied",
            BSimResultStatus::Skipped => "Skipped",
            BSimResultStatus::Error => "Error",
            BSimResultStatus::Unknown => "Unknown",
        }
    }

    /// Determine status from a similarity score.
    pub fn from_similarity(similarity: f64) -> Self {
        if similarity >= 0.9 {
            BSimResultStatus::StrongMatch
        } else if similarity >= 0.7 {
            BSimResultStatus::ModerateMatch
        } else {
            BSimResultStatus::WeakMatch
        }
    }
}

impl Default for BSimResultStatus {
    fn default() -> Self {
        BSimResultStatus::Unknown
    }
}

// ============================================================================
// BSimMatchResult -- A single match result
// ============================================================================

/// A single function match result from a BSim search.
///
/// Ports `ghidra.features.bsim.gui.BSimMatchResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimMatchResult {
    /// The query function name.
    pub query_function: String,
    /// The query function address.
    pub query_address: u64,
    /// The matched function name.
    pub match_function: String,
    /// The matched function address.
    pub match_address: u64,
    /// The executable containing the match.
    pub match_exe: String,
    /// Similarity score (0.0 to 1.0).
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
    /// The result status.
    pub status: BSimResultStatus,
    /// Whether this result has been applied.
    pub applied: bool,
    /// Notes or comments about this result.
    pub notes: Vec<String>,
}

impl BSimMatchResult {
    /// Create a new match result.
    pub fn new(
        query_function: impl Into<String>,
        query_address: u64,
        match_function: impl Into<String>,
        match_address: u64,
        match_exe: impl Into<String>,
        similarity: f64,
        significance: f64,
    ) -> Self {
        let status = BSimResultStatus::from_similarity(similarity);
        Self {
            query_function: query_function.into(),
            query_address,
            match_function: match_function.into(),
            match_address,
            match_exe: match_exe.into(),
            similarity,
            significance,
            status,
            applied: false,
            notes: Vec::new(),
        }
    }

    /// Mark this result as applied.
    pub fn mark_applied(&mut self) {
        self.applied = true;
        self.status = BSimResultStatus::Applied;
    }

    /// Add a note to this result.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Whether this is a strong match.
    pub fn is_strong_match(&self) -> bool {
        self.status == BSimResultStatus::StrongMatch
    }
}

// ============================================================================
// BSimApplyResult -- Result of applying a BSim match
// ============================================================================

/// Result of applying a BSim match (renaming, re-typing, etc.).
///
/// Ports `ghidra.features.bsim.gui.BSimApplyResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimApplyResult {
    /// The function that was modified.
    pub function_name: String,
    /// The function address.
    pub address: u64,
    /// The action that was applied.
    pub action: BSimApplyAction,
    /// Whether the application was successful.
    pub success: bool,
    /// Error message (if any).
    pub error: Option<String>,
}

/// The type of apply action performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BSimApplyAction {
    /// Copy the function name from the match.
    CopyName,
    /// Copy the function namespace from the match.
    CopyNamespace,
    /// Copy both name and namespace.
    CopyNameAndNamespace,
    /// Copy function tags.
    CopyTags,
    /// Apply function signature.
    ApplySignature,
    /// Custom action.
    Custom(String),
}

impl BSimApplyAction {
    /// Get a display label for this action.
    pub fn label(&self) -> &str {
        match self {
            BSimApplyAction::CopyName => "Copy Name",
            BSimApplyAction::CopyNamespace => "Copy Namespace",
            BSimApplyAction::CopyNameAndNamespace => "Copy Name and Namespace",
            BSimApplyAction::CopyTags => "Copy Tags",
            BSimApplyAction::ApplySignature => "Apply Signature",
            BSimApplyAction::Custom(name) => name,
        }
    }
}

impl BSimApplyResult {
    /// Create a successful apply result.
    pub fn success(
        function_name: impl Into<String>,
        address: u64,
        action: BSimApplyAction,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            address,
            action,
            success: true,
            error: None,
        }
    }

    /// Create a failed apply result.
    pub fn failure(
        function_name: impl Into<String>,
        address: u64,
        action: BSimApplyAction,
        error: impl Into<String>,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            address,
            action,
            success: false,
            error: Some(error.into()),
        }
    }
}

// ============================================================================
// BSimSearchSettings -- Settings for a BSim search
// ============================================================================

/// Configuration settings for a BSim similarity search.
///
/// Ports `ghidra.features.bsim.gui.BSimSearchSettings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimSearchSettings {
    /// Similarity threshold (0.0 to 1.0).
    pub similarity_threshold: f64,
    /// Significance threshold.
    pub significance_threshold: f64,
    /// Maximum number of results per function.
    pub max_results_per_function: usize,
    /// Maximum total results.
    pub max_total_results: usize,
    /// Whether to fill in categories.
    pub fill_categories: bool,
    /// Whether to include vector matches.
    pub include_vector_matches: bool,
    /// Maximum vector matches per function.
    pub max_vector_matches: usize,
}

impl BSimSearchSettings {
    /// Create default search settings.
    pub fn new() -> Self {
        Self {
            similarity_threshold: 0.7,
            significance_threshold: 0.0,
            max_results_per_function: 100,
            max_total_results: 1000,
            fill_categories: true,
            include_vector_matches: false,
            max_vector_matches: 0,
        }
    }

    /// Set the similarity threshold.
    pub fn with_similarity_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Set the significance threshold.
    pub fn with_significance_threshold(mut self, threshold: f64) -> Self {
        self.significance_threshold = threshold.max(0.0);
        self
    }

    /// Set the maximum results per function.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results_per_function = max;
        self
    }
}

impl Default for BSimSearchSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BSimOverviewRowObject -- A row in the BSim overview table
// ============================================================================

/// A row in the BSim overview table.
///
/// Ports `ghidra.features.bsim.gui.BSimOverviewRowObject`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimOverviewRowObject {
    /// The executable name.
    pub exe_name: String,
    /// The MD5 hash.
    pub md5: String,
    /// The architecture.
    pub arch: String,
    /// The compiler.
    pub compiler: String,
    /// The number of functions.
    pub function_count: usize,
    /// The ingest date (ISO 8601).
    pub ingest_date: Option<String>,
    /// The category.
    pub category: Option<String>,
    /// Number of matching functions (in a search context).
    pub match_count: usize,
}

impl BSimOverviewRowObject {
    /// Create a new overview row.
    pub fn new(
        exe_name: impl Into<String>,
        md5: impl Into<String>,
        arch: impl Into<String>,
        compiler: impl Into<String>,
    ) -> Self {
        Self {
            exe_name: exe_name.into(),
            md5: md5.into(),
            arch: arch.into(),
            compiler: compiler.into(),
            function_count: 0,
            ingest_date: None,
            category: None,
            match_count: 0,
        }
    }
}

// ============================================================================
// FunctionComparisonException
// ============================================================================

/// Exception for errors during function comparison.
///
/// Ports `ghidra.features.bsim.gui.FunctionComparisonException`.
#[derive(Debug, Clone)]
pub struct FunctionComparisonException {
    /// The error message.
    pub message: String,
}

impl FunctionComparisonException {
    /// Create a new exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for FunctionComparisonException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FunctionComparisonException: {}", self.message)
    }
}

impl std::error::Error for FunctionComparisonException {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_status_from_similarity() {
        assert_eq!(BSimResultStatus::from_similarity(0.95), BSimResultStatus::StrongMatch);
        assert_eq!(BSimResultStatus::from_similarity(0.8), BSimResultStatus::ModerateMatch);
        assert_eq!(BSimResultStatus::from_similarity(0.5), BSimResultStatus::WeakMatch);
    }

    #[test]
    fn test_result_status_is_match() {
        assert!(BSimResultStatus::StrongMatch.is_match());
        assert!(BSimResultStatus::ModerateMatch.is_match());
        assert!(BSimResultStatus::WeakMatch.is_match());
        assert!(!BSimResultStatus::Applied.is_match());
        assert!(!BSimResultStatus::Error.is_match());
    }

    #[test]
    fn test_result_status_label() {
        assert_eq!(BSimResultStatus::StrongMatch.label(), "Strong Match");
        assert_eq!(BSimResultStatus::Error.label(), "Error");
    }

    #[test]
    fn test_match_result_creation() {
        let result = BSimMatchResult::new("main", 0x1000, "main", 0x2000, "test.exe", 0.95, 10.0);
        assert_eq!(result.query_function, "main");
        assert_eq!(result.match_exe, "test.exe");
        assert!((result.similarity - 0.95).abs() < f64::EPSILON);
        assert_eq!(result.status, BSimResultStatus::StrongMatch);
        assert!(!result.applied);
    }

    #[test]
    fn test_match_result_mark_applied() {
        let mut result = BSimMatchResult::new("main", 0x1000, "main", 0x2000, "exe", 0.9, 5.0);
        result.mark_applied();
        assert!(result.applied);
        assert_eq!(result.status, BSimResultStatus::Applied);
    }

    #[test]
    fn test_match_result_strong() {
        let result = BSimMatchResult::new("f", 0, "f", 0, "e", 0.95, 1.0);
        assert!(result.is_strong_match());
    }

    #[test]
    fn test_apply_result_success() {
        let result = BSimApplyResult::success("func", 0x1000, BSimApplyAction::CopyName);
        assert!(result.success);
        assert!(result.error.is_none());
        assert_eq!(result.action, BSimApplyAction::CopyName);
    }

    #[test]
    fn test_apply_result_failure() {
        let result = BSimApplyResult::failure("func", 0x1000, BSimApplyAction::ApplySignature, "no function");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_apply_action_labels() {
        assert_eq!(BSimApplyAction::CopyName.label(), "Copy Name");
        assert_eq!(BSimApplyAction::Custom("my action".into()).label(), "my action");
    }

    #[test]
    fn test_search_settings_defaults() {
        let settings = BSimSearchSettings::new();
        assert!((settings.similarity_threshold - 0.7).abs() < f64::EPSILON);
        assert_eq!(settings.max_results_per_function, 100);
        assert!(settings.fill_categories);
    }

    #[test]
    fn test_search_settings_builder() {
        let settings = BSimSearchSettings::new()
            .with_similarity_threshold(0.9)
            .with_significance_threshold(5.0)
            .with_max_results(50);
        assert!((settings.similarity_threshold - 0.9).abs() < f64::EPSILON);
        assert!((settings.significance_threshold - 5.0).abs() < f64::EPSILON);
        assert_eq!(settings.max_results_per_function, 50);
    }

    #[test]
    fn test_search_settings_clamp() {
        let settings = BSimSearchSettings::new().with_similarity_threshold(1.5);
        assert!((settings.similarity_threshold - 1.0).abs() < f64::EPSILON);

        let settings = BSimSearchSettings::new().with_similarity_threshold(-0.5);
        assert!((settings.similarity_threshold - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_overview_row() {
        let row = BSimOverviewRowObject::new("test.exe", "abc123", "x86", "gcc");
        assert_eq!(row.exe_name, "test.exe");
        assert_eq!(row.arch, "x86");
        assert_eq!(row.function_count, 0);
    }

    #[test]
    fn test_comparison_exception() {
        let exc = FunctionComparisonException::new("functions not comparable");
        assert_eq!(exc.message, "functions not comparable");
        assert!(exc.to_string().contains("not comparable"));
    }

    #[test]
    fn test_match_result_serialization() {
        let result = BSimMatchResult::new("main", 0x1000, "func", 0x2000, "exe", 0.9, 5.0);
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: BSimMatchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.query_function, "main");
        assert!((deserialized.similarity - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_search_settings_serialization() {
        let settings = BSimSearchSettings::new();
        let json = serde_json::to_string(&settings).unwrap();
        let _: BSimSearchSettings = serde_json::from_str(&json).unwrap();
    }
}
