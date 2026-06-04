//! BSim search results and filter types.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.search.results` package types:
//! - [`BSimMatchResult`] -- a single function similarity match
//! - [`BSimMatchResultsModel`] -- the collection of match results
//! - [`BSimResultStatus`] -- status of a match result
//! - [`BSimSearchResultsFilter`] -- filter for search results
//! - [`BSimSearchSettings`] -- settings for a BSim search
//! - [`BSimFilterSet`] -- a set of filter criteria
//! - [`ExecutableResult`] -- result of comparing an executable
//! - [`BSimApplyResult`] -- result of applying a match to the database
//! - [`BSimApplyResults`] -- collection of apply results

use serde::{Deserialize, Serialize};

use super::description::{ExecutableRecord, FunctionDescription, RowKey};

// ============================================================================
// BSimResultStatus
// ============================================================================

/// Status of a BSim match result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BSimResultStatus {
    /// No status assigned yet.
    None,
    /// The match has been accepted by the user.
    Accepted,
    /// The match has been rejected by the user.
    Rejected,
    /// The match is pending review.
    Pending,
    /// The match was automatically applied.
    AutoApplied,
    /// The match has an error.
    Error,
}

impl Default for BSimResultStatus {
    fn default() -> Self {
        Self::None
    }
}

impl BSimResultStatus {
    /// Whether this status represents a finalized decision.
    pub fn is_finalized(&self) -> bool {
        matches!(self, Self::Accepted | Self::Rejected | Self::AutoApplied)
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Accepted => "Accepted",
            Self::Rejected => "Rejected",
            Self::Pending => "Pending",
            Self::AutoApplied => "Auto-Applied",
            Self::Error => "Error",
        }
    }
}

// ============================================================================
// BSimMatchResult
// ============================================================================

/// A single function similarity match result.
///
/// Contains the source function (from the query), the matched function
/// (from the database), and their similarity scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimMatchResult {
    /// The source function from the query.
    pub source_function: FunctionDescription,
    /// The matched function from the database.
    pub matched_function: FunctionDescription,
    /// The MD5 of the matched executable.
    pub matched_exe_md5: String,
    /// Cosine similarity score (0.0 - 1.0).
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
    /// Status of this result.
    pub status: BSimResultStatus,
    /// The vector-id of the matched signature.
    pub vector_id: u64,
    /// Additional notes from the comparison.
    pub notes: Vec<String>,
    /// Whether this result has children (callgraph) matches.
    pub has_children: bool,
    /// Children similarity (if has_children is true).
    pub children_similarity: f64,
}

impl BSimMatchResult {
    /// Create a new match result.
    pub fn new(
        source: FunctionDescription,
        matched: FunctionDescription,
        matched_exe_md5: impl Into<String>,
        similarity: f64,
        significance: f64,
    ) -> Self {
        Self {
            source_function: source,
            matched_function: matched,
            matched_exe_md5: matched_exe_md5.into(),
            similarity,
            significance,
            status: BSimResultStatus::default(),
            vector_id: 0,
            notes: Vec::new(),
            has_children: false,
            children_similarity: 0.0,
        }
    }

    /// The source function name.
    pub fn source_name(&self) -> &str {
        &self.source_function.function_name
    }

    /// The matched function name.
    pub fn matched_name(&self) -> &str {
        &self.matched_function.function_name
    }

    /// The source function address.
    pub fn source_address(&self) -> Option<u64> {
        self.source_function.address
    }

    /// The matched function address.
    pub fn matched_address(&self) -> Option<u64> {
        self.matched_function.address
    }

    /// Set the status of this result.
    pub fn set_status(&mut self, status: BSimResultStatus) {
        self.status = status;
    }

    /// Add a note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
}

// ============================================================================
// BSimMatchResultsModel
// ============================================================================

/// The collection of all match results from a BSim search.
///
/// Manages the full set of match results, including sorting, filtering,
/// and aggregate statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BSimMatchResultsModel {
    /// All match results.
    results: Vec<BSimMatchResult>,
    /// Total number of functions queried.
    pub total_queried: u32,
    /// Number of functions with at least one match.
    pub functions_matched: u32,
    /// The executable record from the query.
    pub query_exe: Option<ExecutableRecord>,
    /// The database name.
    pub database_name: String,
}

impl BSimMatchResultsModel {
    /// Create a new empty results model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a match result.
    pub fn add_result(&mut self, result: BSimMatchResult) {
        self.results.push(result);
    }

    /// Get a result by index.
    pub fn get(&self, index: usize) -> Option<&BSimMatchResult> {
        self.results.get(index)
    }

    /// Get a result by index, mutably.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut BSimMatchResult> {
        self.results.get_mut(index)
    }

    /// Number of results.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether there are no results.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// All results.
    pub fn results(&self) -> &[BSimMatchResult] {
        &self.results
    }

    /// All results, mutably.
    pub fn results_mut(&mut self) -> &mut Vec<BSimMatchResult> {
        &mut self.results
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

    /// Get results filtered by status.
    pub fn filter_by_status(&self, status: BSimResultStatus) -> Vec<&BSimMatchResult> {
        self.results.iter().filter(|r| r.status == status).collect()
    }

    /// Get results with similarity above a threshold.
    pub fn filter_by_similarity(&self, threshold: f64) -> Vec<&BSimMatchResult> {
        self.results
            .iter()
            .filter(|r| r.similarity >= threshold)
            .collect()
    }

    /// The number of accepted results.
    pub fn accepted_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.status == BSimResultStatus::Accepted)
            .count()
    }

    /// The number of rejected results.
    pub fn rejected_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.status == BSimResultStatus::Rejected)
            .count()
    }

    /// Get unique matched executable MD5s.
    pub fn unique_matched_exes(&self) -> Vec<&str> {
        let mut md5s: Vec<&str> = self
            .results
            .iter()
            .map(|r| r.matched_exe_md5.as_str())
            .collect();
        md5s.sort();
        md5s.dedup();
        md5s
    }
}

// ============================================================================
// BSimSearchSettings
// ============================================================================

/// Settings for a BSim search operation.
///
/// Configures the thresholds, limits, and filters for a search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimSearchSettings {
    /// Minimum similarity threshold (0.0 - 1.0).
    pub similarity_threshold: f64,
    /// Minimum significance threshold.
    pub significance_threshold: f64,
    /// Maximum number of results per function.
    pub max_results_per_function: u32,
    /// Maximum total results.
    pub max_total_results: u32,
    /// Whether to query for children (callgraph) matches.
    pub query_children: bool,
    /// Whether to fill in categories of matched executables.
    pub fill_categories: bool,
    /// The BSim filter to apply.
    pub filter: Option<BSimFilterSet>,
    /// The database server URL.
    pub server_url: String,
    /// The database name.
    pub database_name: String,
}

impl Default for BSimSearchSettings {
    fn default() -> Self {
        Self {
            similarity_threshold: 0.7,
            significance_threshold: 0.0,
            max_results_per_function: 100,
            max_total_results: 10000,
            query_children: false,
            fill_categories: true,
            filter: None,
            server_url: String::new(),
            database_name: String::new(),
        }
    }
}

impl BSimSearchSettings {
    /// Create new search settings with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the similarity threshold.
    pub fn with_similarity(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold;
        self
    }

    /// Set the significance threshold.
    pub fn with_significance(mut self, threshold: f64) -> Self {
        self.significance_threshold = threshold;
        self
    }

    /// Set the maximum results per function.
    pub fn with_max_results(mut self, max: u32) -> Self {
        self.max_results_per_function = max;
        self
    }
}

// ============================================================================
// BSimFilterSet
// ============================================================================

/// A set of filter criteria for BSim search results.
///
/// Groups multiple filter types that can be applied to narrow down
/// search results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BSimFilterSet {
    /// Include only executables matching these names.
    pub executable_names: Vec<String>,
    /// Exclude executables matching these names.
    pub exclude_executable_names: Vec<String>,
    /// Include only executables with these architectures.
    pub architectures: Vec<String>,
    /// Exclude executables with these architectures.
    pub exclude_architectures: Vec<String>,
    /// Include only executables with these compilers.
    pub compilers: Vec<String>,
    /// Include only executables with these MD5s.
    pub md5_hashes: Vec<String>,
    /// Include only executables with these categories.
    pub categories: Vec<String>,
    /// Minimum similarity score for inclusion.
    pub min_similarity: Option<f64>,
    /// Maximum date (ISO-8601 string) for inclusion.
    pub max_date: Option<String>,
    /// Minimum date for inclusion.
    pub min_date: Option<String>,
    /// Path prefix filter.
    pub path_prefix: Option<String>,
}

impl BSimFilterSet {
    /// Create a new empty filter set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this filter set has any criteria.
    pub fn has_criteria(&self) -> bool {
        !self.executable_names.is_empty()
            || !self.exclude_executable_names.is_empty()
            || !self.architectures.is_empty()
            || !self.exclude_architectures.is_empty()
            || !self.compilers.is_empty()
            || !self.md5_hashes.is_empty()
            || !self.categories.is_empty()
            || self.min_similarity.is_some()
            || self.max_date.is_some()
            || self.min_date.is_some()
            || self.path_prefix.is_some()
    }

    /// Test whether an executable record passes this filter.
    pub fn passes(&self, exe: &ExecutableRecord) -> bool {
        // Check executable name inclusion
        if !self.executable_names.is_empty()
            && !self.executable_names.contains(&exe.executable_name)
        {
            return false;
        }
        // Check executable name exclusion
        if self.exclude_executable_names.contains(&exe.executable_name) {
            return false;
        }
        // Check architecture inclusion
        if !self.architectures.is_empty() && !self.architectures.contains(&exe.architecture) {
            return false;
        }
        // Check architecture exclusion
        if self.exclude_architectures.contains(&exe.architecture) {
            return false;
        }
        // Check compiler
        if !self.compilers.is_empty() && !self.compilers.contains(&exe.compiler_name) {
            return false;
        }
        // Check MD5
        if !self.md5_hashes.is_empty() && !self.md5_hashes.contains(&exe.md5) {
            return false;
        }
        true
    }
}

// ============================================================================
// BSimSearchResultsFilter
// ============================================================================

/// A filter that can be applied to `BSimMatchResult` entries to produce
/// a filtered subset.
#[derive(Debug, Clone)]
pub struct BSimSearchResultsFilter {
    /// Minimum similarity (0.0 - 1.0).
    pub min_similarity: f64,
    /// Minimum significance.
    pub min_significance: f64,
    /// Status filter (empty = show all).
    pub status_filter: Vec<BSimResultStatus>,
    /// Exe name filter (empty = show all).
    pub exe_name_filter: Vec<String>,
}

impl Default for BSimSearchResultsFilter {
    fn default() -> Self {
        Self {
            min_similarity: 0.0,
            min_significance: 0.0,
            status_filter: Vec::new(),
            exe_name_filter: Vec::new(),
        }
    }
}

impl BSimSearchResultsFilter {
    /// Create a new filter with default (no-op) settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a match result passes this filter.
    pub fn passes(&self, result: &BSimMatchResult) -> bool {
        if result.similarity < self.min_similarity {
            return false;
        }
        if result.significance < self.min_significance {
            return false;
        }
        if !self.status_filter.is_empty() && !self.status_filter.contains(&result.status) {
            return false;
        }
        if !self.exe_name_filter.is_empty()
            && !self
                .exe_name_filter
                .iter()
                .any(|n| result.matched_exe_md5.contains(n.as_str()))
        {
            return false;
        }
        true
    }

    /// Apply this filter to a results model, returning matching indices.
    pub fn apply(&self, model: &BSimMatchResultsModel) -> Vec<usize> {
        model
            .results()
            .iter()
            .enumerate()
            .filter(|(_, r)| self.passes(r))
            .map(|(i, _)| i)
            .collect()
    }
}

// ============================================================================
// ExecutableResult
// ============================================================================

/// Result of comparing an entire executable against the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableResult {
    /// The executable record.
    pub exe: ExecutableRecord,
    /// Total number of functions compared.
    pub total_functions: u32,
    /// Number of functions with matches.
    pub matched_functions: u32,
    /// Average similarity of matched functions.
    pub average_similarity: f64,
    /// Total significance score.
    pub total_significance: f64,
    /// Match results for individual functions.
    pub function_results: Vec<BSimMatchResult>,
}

impl ExecutableResult {
    /// Create a new executable result.
    pub fn new(exe: ExecutableRecord) -> Self {
        Self {
            exe,
            total_functions: 0,
            matched_functions: 0,
            average_similarity: 0.0,
            total_significance: 0.0,
            function_results: Vec::new(),
        }
    }

    /// Add a function match result.
    pub fn add_function_result(&mut self, result: BSimMatchResult) {
        self.total_functions += 1;
        if result.similarity > 0.0 {
            self.matched_functions += 1;
            self.total_significance += result.significance;
            // Running average
            let n = self.matched_functions as f64;
            self.average_similarity =
                self.average_similarity * (n - 1.0) / n + result.similarity / n;
        }
        self.function_results.push(result);
    }

    /// Match rate (0.0 - 1.0).
    pub fn match_rate(&self) -> f64 {
        if self.total_functions == 0 {
            0.0
        } else {
            self.matched_functions as f64 / self.total_functions as f64
        }
    }
}

// ============================================================================
// BSimApplyResult
// ============================================================================

/// Result of applying a BSim match to a program.
///
/// Describes what was applied (function name, signature, etc.)
/// and whether it succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimApplyResult {
    /// The function that was modified.
    pub function_name: String,
    /// The address of the function.
    pub function_address: Option<u64>,
    /// The type of change applied.
    pub apply_type: BSimApplyType,
    /// Whether the application was successful.
    pub success: bool,
    /// Error message if the application failed.
    pub error_message: Option<String>,
}

/// The type of change applied by a BSim match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BSimApplyType {
    /// No change applied.
    None,
    /// The function name was changed.
    NameChange,
    /// The function namespace was changed.
    NamespaceChange,
    /// The function signature was applied.
    Signature,
    /// Function tags were applied.
    Tags,
    /// Data types were applied.
    DataTypes,
}

impl BSimApplyResult {
    /// Create a new apply result.
    pub fn new(
        function_name: impl Into<String>,
        apply_type: BSimApplyType,
        success: bool,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            function_address: None,
            apply_type,
            success,
            error_message: None,
        }
    }

    /// Create a successful result.
    pub fn success(function_name: impl Into<String>, apply_type: BSimApplyType) -> Self {
        Self::new(function_name, apply_type, true)
    }

    /// Create a failed result.
    pub fn failure(
        function_name: impl Into<String>,
        apply_type: BSimApplyType,
        error: impl Into<String>,
    ) -> Self {
        let mut r = Self::new(function_name, apply_type, false);
        r.error_message = Some(error.into());
        r
    }
}

// ============================================================================
// BSimApplyResults
// ============================================================================

/// Collection of BSim apply results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BSimApplyResults {
    /// All apply results.
    results: Vec<BSimApplyResult>,
}

impl BSimApplyResults {
    /// Create new empty apply results.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an apply result.
    pub fn add(&mut self, result: BSimApplyResult) {
        self.results.push(result);
    }

    /// All results.
    pub fn results(&self) -> &[BSimApplyResult] {
        &self.results
    }

    /// Number of results.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether there are no results.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Number of successful applications.
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|r| r.success).count()
    }

    /// Number of failed applications.
    pub fn failure_count(&self) -> usize {
        self.results.iter().filter(|r| !r.success).count()
    }

    /// Get failed results.
    pub fn failures(&self) -> Vec<&BSimApplyResult> {
        self.results.iter().filter(|r| !r.success).collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsim::description::FunctionDescription;

    fn make_match_result(similarity: f64, significance: f64) -> BSimMatchResult {
        BSimMatchResult::new(
            FunctionDescription::new(0, "source_fn", Some(0x1000)),
            FunctionDescription::new(0, "matched_fn", Some(0x2000)),
            "abc123",
            similarity,
            significance,
        )
    }

    #[test]
    fn result_status_label() {
        assert_eq!(BSimResultStatus::Accepted.label(), "Accepted");
        assert_eq!(BSimResultStatus::None.label(), "None");
    }

    #[test]
    fn result_status_is_finalized() {
        assert!(BSimResultStatus::Accepted.is_finalized());
        assert!(BSimResultStatus::Rejected.is_finalized());
        assert!(!BSimResultStatus::Pending.is_finalized());
        assert!(!BSimResultStatus::None.is_finalized());
    }

    #[test]
    fn match_result_creation() {
        let r = make_match_result(0.95, 5.0);
        assert_eq!(r.source_name(), "source_fn");
        assert_eq!(r.matched_name(), "matched_fn");
        assert!((r.similarity - 0.95).abs() < 1e-9);
        assert_eq!(r.status, BSimResultStatus::None);
    }

    #[test]
    fn match_result_set_status() {
        let mut r = make_match_result(0.9, 4.0);
        r.set_status(BSimResultStatus::Accepted);
        assert_eq!(r.status, BSimResultStatus::Accepted);
    }

    #[test]
    fn match_results_model_basics() {
        let mut model = BSimMatchResultsModel::new();
        assert!(model.is_empty());

        model.add_result(make_match_result(0.9, 5.0));
        model.add_result(make_match_result(0.5, 2.0));
        assert_eq!(model.len(), 2);
    }

    #[test]
    fn match_results_model_sort_by_similarity() {
        let mut model = BSimMatchResultsModel::new();
        model.add_result(make_match_result(0.5, 2.0));
        model.add_result(make_match_result(0.9, 5.0));
        model.add_result(make_match_result(0.7, 3.0));

        model.sort_by_similarity();
        assert!((model.get(0).unwrap().similarity - 0.9).abs() < 1e-9);
        assert!((model.get(1).unwrap().similarity - 0.7).abs() < 1e-9);
        assert!((model.get(2).unwrap().similarity - 0.5).abs() < 1e-9);
    }

    #[test]
    fn match_results_model_filter_by_status() {
        let mut model = BSimMatchResultsModel::new();
        let mut r1 = make_match_result(0.9, 5.0);
        r1.set_status(BSimResultStatus::Accepted);
        model.add_result(r1);
        model.add_result(make_match_result(0.5, 2.0));

        let accepted = model.filter_by_status(BSimResultStatus::Accepted);
        assert_eq!(accepted.len(), 1);
        assert_eq!(model.accepted_count(), 1);
    }

    #[test]
    fn match_results_model_filter_by_similarity() {
        let mut model = BSimMatchResultsModel::new();
        model.add_result(make_match_result(0.9, 5.0));
        model.add_result(make_match_result(0.3, 1.0));

        let above = model.filter_by_similarity(0.5);
        assert_eq!(above.len(), 1);
    }

    #[test]
    fn search_settings_defaults() {
        let s = BSimSearchSettings::new();
        assert!((s.similarity_threshold - 0.7).abs() < 1e-9);
        assert_eq!(s.max_results_per_function, 100);
    }

    #[test]
    fn search_settings_builder() {
        let s = BSimSearchSettings::new()
            .with_similarity(0.9)
            .with_max_results(50);
        assert!((s.similarity_threshold - 0.9).abs() < 1e-9);
        assert_eq!(s.max_results_per_function, 50);
    }

    #[test]
    fn filter_set_has_criteria() {
        let fs = BSimFilterSet::new();
        assert!(!fs.has_criteria());

        let mut fs2 = BSimFilterSet::new();
        fs2.architectures.push("x86".to_string());
        assert!(fs2.has_criteria());
    }

    #[test]
    fn filter_set_passes() {
        let mut fs = BSimFilterSet::new();
        fs.architectures.push("x86".to_string());

        let exe_pass = ExecutableRecord::new("abc", "prog", "x86", "gcc");
        let exe_fail = ExecutableRecord::new("def", "prog", "arm", "gcc");

        assert!(fs.passes(&exe_pass));
        assert!(!fs.passes(&exe_fail));
    }

    #[test]
    fn search_results_filter_passes() {
        let filter = BSimSearchResultsFilter {
            min_similarity: 0.8,
            ..Default::default()
        };
        let high = make_match_result(0.9, 5.0);
        let low = make_match_result(0.5, 5.0);

        assert!(filter.passes(&high));
        assert!(!filter.passes(&low));
    }

    #[test]
    fn executable_result_match_rate() {
        let exe = ExecutableRecord::new("abc", "prog", "x86", "gcc");
        let mut er = ExecutableResult::new(exe);
        assert!((er.match_rate() - 0.0).abs() < 1e-9);

        er.add_function_result(make_match_result(0.9, 5.0));
        er.add_function_result(make_match_result(0.0, 0.0));
        assert!((er.match_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn apply_result_success() {
        let r = BSimApplyResult::success("main", BSimApplyType::NameChange);
        assert!(r.success);
        assert!(r.error_message.is_none());
    }

    #[test]
    fn apply_result_failure() {
        let r = BSimApplyResult::failure("main", BSimApplyType::Signature, "timeout");
        assert!(!r.success);
        assert_eq!(r.error_message.as_deref(), Some("timeout"));
    }

    #[test]
    fn apply_results_counts() {
        let mut results = BSimApplyResults::new();
        results.add(BSimApplyResult::success("a", BSimApplyType::NameChange));
        results.add(BSimApplyResult::failure("b", BSimApplyType::Signature, "err"));
        results.add(BSimApplyResult::success("c", BSimApplyType::NamespaceChange));

        assert_eq!(results.len(), 3);
        assert_eq!(results.success_count(), 2);
        assert_eq!(results.failure_count(), 1);
        assert_eq!(results.failures().len(), 1);
    }

    #[test]
    fn unique_matched_exes() {
        let mut model = BSimMatchResultsModel::new();
        model.add_result(make_match_result(0.9, 5.0));
        model.add_result(make_match_result(0.8, 4.0));
        // Both have the same md5 "abc123"
        let md5s = model.unique_matched_exes();
        assert_eq!(md5s.len(), 1);
        assert_eq!(md5s[0], "abc123");
    }
}
