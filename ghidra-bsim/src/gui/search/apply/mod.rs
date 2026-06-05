//! BSim search result apply actions.
//!
//! Ports `ghidra.features.bsim.gui.search.results.apply`:
//! - [`AbstractBSimApplyTask`]: base for tasks that apply BSim results to a program
//! - [`NameAndNamespaceBSimApplyTask`]: apply function names and namespaces from matches
//! - [`SignatureBSimApplyTask`]: apply function signatures from matches

use serde::{Deserialize, Serialize};

/// The type of application action to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BSimApplyAction {
    /// Apply the matched function's name.
    ApplyName,
    /// Apply the matched function's namespace.
    ApplyNamespace,
    /// Apply the matched function's calling convention.
    ApplyCallingConvention,
    /// Apply the matched function's signature (return type + params).
    ApplySignature,
    /// Apply all available metadata from the match.
    ApplyAll,
}

/// Status of an individual apply operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BSimApplyStatus {
    /// Apply succeeded.
    Success,
    /// Apply was skipped (e.g., function already has this info).
    Skipped(String),
    /// Apply failed.
    Failed(String),
}

/// Result of applying a single BSim match to a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimApplyResult {
    /// The address of the function being modified.
    pub function_address: u64,
    /// The name of the function being modified.
    pub function_name: String,
    /// The action that was performed.
    pub action: BSimApplyAction,
    /// The status of the operation.
    pub status: BSimApplyStatus,
    /// Description of what was applied.
    pub description: String,
}

impl BSimApplyResult {
    /// Create a successful apply result.
    pub fn success(
        function_address: u64,
        function_name: impl Into<String>,
        action: BSimApplyAction,
        description: impl Into<String>,
    ) -> Self {
        Self {
            function_address,
            function_name: function_name.into(),
            action,
            status: BSimApplyStatus::Success,
            description: description.into(),
        }
    }

    /// Create a skipped apply result.
    pub fn skipped(
        function_address: u64,
        function_name: impl Into<String>,
        action: BSimApplyAction,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            function_address,
            function_name: function_name.into(),
            action,
            status: BSimApplyStatus::Skipped(reason.into()),
            description: String::new(),
        }
    }

    /// Create a failed apply result.
    pub fn failed(
        function_address: u64,
        function_name: impl Into<String>,
        action: BSimApplyAction,
        error: impl Into<String>,
    ) -> Self {
        Self {
            function_address,
            function_name: function_name.into(),
            action,
            status: BSimApplyStatus::Failed(error.into()),
            description: String::new(),
        }
    }

    /// Whether the apply was successful.
    pub fn is_success(&self) -> bool {
        matches!(self.status, BSimApplyStatus::Success)
    }
}

/// Configuration for an apply task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimApplyConfig {
    /// Whether to apply function names.
    pub apply_names: bool,
    /// Whether to apply namespaces.
    pub apply_namespaces: bool,
    /// Whether to apply calling conventions.
    pub apply_calling_conventions: bool,
    /// Whether to apply full signatures.
    pub apply_signatures: bool,
    /// Whether to overwrite existing values (vs. only fill blanks).
    pub overwrite_existing: bool,
    /// Minimum similarity threshold for applying results (0.0-1.0).
    pub min_similarity: f64,
}

impl Default for BSimApplyConfig {
    fn default() -> Self {
        Self {
            apply_names: true,
            apply_namespaces: true,
            apply_calling_conventions: false,
            apply_signatures: false,
            overwrite_existing: false,
            min_similarity: 0.9,
        }
    }
}

/// Abstract base for BSim apply tasks.
///
/// Manages the overall apply workflow: collecting matches, filtering by
/// config, applying changes, and collecting results.
#[derive(Debug)]
pub struct AbstractBSimApplyTask {
    /// Configuration for this apply task.
    pub config: BSimApplyConfig,
    /// Results from the apply operations.
    results: Vec<BSimApplyResult>,
    /// Total number of matches considered.
    pub matches_considered: usize,
    /// Total number of functions modified.
    pub functions_modified: usize,
}

impl AbstractBSimApplyTask {
    /// Create a new apply task with the given config.
    pub fn new(config: BSimApplyConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
            matches_considered: 0,
            functions_modified: 0,
        }
    }

    /// Add a result from an apply operation.
    pub fn add_result(&mut self, result: BSimApplyResult) {
        if result.is_success() {
            self.functions_modified += 1;
        }
        self.results.push(result);
    }

    /// Get all results.
    pub fn results(&self) -> &[BSimApplyResult] {
        &self.results
    }

    /// Get only successful results.
    pub fn successful_results(&self) -> Vec<&BSimApplyResult> {
        self.results.iter().filter(|r| r.is_success()).collect()
    }

    /// Get only failed results.
    pub fn failed_results(&self) -> Vec<&BSimApplyResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.status, BSimApplyStatus::Failed(_)))
            .collect()
    }

    /// Get the number of results.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Clear all results.
    pub fn clear_results(&mut self) {
        self.results.clear();
        self.matches_considered = 0;
        self.functions_modified = 0;
    }
}

/// Task that applies function names and namespaces from BSim matches.
///
/// Port of `ghidra.features.bsim.gui.search.results.apply.NameAndNamespaceBSimApplyTask`.
#[derive(Debug)]
pub struct NameAndNamespaceBSimApplyTask {
    /// The base apply task.
    pub base: AbstractBSimApplyTask,
}

impl NameAndNamespaceBSimApplyTask {
    /// Create a new name-and-namespace apply task.
    pub fn new() -> Self {
        let config = BSimApplyConfig {
            apply_names: true,
            apply_namespaces: true,
            apply_calling_conventions: false,
            apply_signatures: false,
            ..Default::default()
        };
        Self {
            base: AbstractBSimApplyTask::new(config),
        }
    }

    /// Apply a matched name to a function.
    pub fn apply_name(
        &mut self,
        function_address: u64,
        current_name: &str,
        matched_name: &str,
    ) {
        self.base.matches_considered += 1;
        if current_name.starts_with("FUN_") || self.base.config.overwrite_existing {
            self.base.add_result(BSimApplyResult::success(
                function_address,
                current_name,
                BSimApplyAction::ApplyName,
                format!("Renamed to '{}'", matched_name),
            ));
        } else {
            self.base.add_result(BSimApplyResult::skipped(
                function_address,
                current_name,
                BSimApplyAction::ApplyName,
                "Function already has a non-default name",
            ));
        }
    }

    /// Apply a matched namespace to a function.
    pub fn apply_namespace(
        &mut self,
        function_address: u64,
        current_name: &str,
        namespace: &str,
    ) {
        self.base.matches_considered += 1;
        self.base.add_result(BSimApplyResult::success(
            function_address,
            current_name,
            BSimApplyAction::ApplyNamespace,
            format!("Set namespace to '{}'", namespace),
        ));
    }
}

impl Default for NameAndNamespaceBSimApplyTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Task that applies function signatures from BSim matches.
///
/// Port of `ghidra.features.bsim.gui.search.results.apply.SignatureBSimApplyTask`.
#[derive(Debug)]
pub struct SignatureBSimApplyTask {
    /// The base apply task.
    pub base: AbstractBSimApplyTask,
}

impl SignatureBSimApplyTask {
    /// Create a new signature apply task.
    pub fn new() -> Self {
        let config = BSimApplyConfig {
            apply_names: true,
            apply_namespaces: true,
            apply_calling_conventions: true,
            apply_signatures: true,
            ..Default::default()
        };
        Self {
            base: AbstractBSimApplyTask::new(config),
        }
    }

    /// Apply a full signature (return type, calling convention, parameter types)
    /// from a BSim match to a local function.
    pub fn apply_signature(
        &mut self,
        function_address: u64,
        current_name: &str,
        return_type: &str,
        calling_convention: &str,
        param_types: &[String],
    ) {
        self.base.matches_considered += 1;
        self.base.add_result(BSimApplyResult::success(
            function_address,
            current_name,
            BSimApplyAction::ApplySignature,
            format!(
                "Applied signature: {} ({}) -> {}",
                calling_convention,
                param_types.join(", "),
                return_type
            ),
        ));
    }
}

impl Default for SignatureBSimApplyTask {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_result_success() {
        let result = BSimApplyResult::success(
            0x1000,
            "FUN_1000",
            BSimApplyAction::ApplyName,
            "Renamed to main",
        );
        assert!(result.is_success());
        assert_eq!(result.function_address, 0x1000);
    }

    #[test]
    fn test_apply_result_skipped() {
        let result = BSimApplyResult::skipped(
            0x2000,
            "myFunc",
            BSimApplyAction::ApplyName,
            "already named",
        );
        assert!(!result.is_success());
        assert!(matches!(result.status, BSimApplyStatus::Skipped(_)));
    }

    #[test]
    fn test_apply_result_failed() {
        let result = BSimApplyResult::failed(
            0x3000,
            "unknown",
            BSimApplyAction::ApplySignature,
            "type mismatch",
        );
        assert!(!result.is_success());
        assert!(matches!(result.status, BSimApplyStatus::Failed(_)));
    }

    #[test]
    fn test_apply_config_default() {
        let config = BSimApplyConfig::default();
        assert!(config.apply_names);
        assert!(config.apply_namespaces);
        assert!(!config.apply_signatures);
        assert!((config.min_similarity - 0.9).abs() < 1e-6);
    }

    #[test]
    fn test_abstract_apply_task() {
        let mut task = AbstractBSimApplyTask::new(BSimApplyConfig::default());
        assert_eq!(task.result_count(), 0);

        task.add_result(BSimApplyResult::success(
            0x1000,
            "f1",
            BSimApplyAction::ApplyName,
            "ok",
        ));
        task.add_result(BSimApplyResult::failed(
            0x2000,
            "f2",
            BSimApplyAction::ApplyName,
            "err",
        ));

        assert_eq!(task.result_count(), 2);
        assert_eq!(task.functions_modified, 1);
        assert_eq!(task.successful_results().len(), 1);
        assert_eq!(task.failed_results().len(), 1);

        task.clear_results();
        assert_eq!(task.result_count(), 0);
    }

    #[test]
    fn test_name_and_namespace_apply() {
        let mut task = NameAndNamespaceBSimApplyTask::new();
        assert!(task.base.config.apply_names);
        assert!(task.base.config.apply_namespaces);
        assert!(!task.base.config.apply_signatures);

        // FUN_ prefix should be renamed
        task.apply_name(0x1000, "FUN_1000", "main");
        assert_eq!(task.base.functions_modified, 1);
        assert!(task.base.results()[0].is_success());

        // Non-default name should be skipped (without overwrite)
        task.apply_name(0x2000, "myFunc", "other");
        assert_eq!(task.base.results().len(), 2);
        assert!(!task.base.results()[1].is_success());
    }

    #[test]
    fn test_name_and_namespace_apply_with_overwrite() {
        let mut task = NameAndNamespaceBSimApplyTask::new();
        task.base.config.overwrite_existing = true;

        task.apply_name(0x1000, "myFunc", "main");
        assert_eq!(task.base.functions_modified, 1);
        assert!(task.base.results()[0].is_success());
    }

    #[test]
    fn test_namespace_apply() {
        let mut task = NameAndNamespaceBSimApplyTask::new();
        task.apply_namespace(0x1000, "myFunc", "libc");
        assert_eq!(task.base.functions_modified, 1);
    }

    #[test]
    fn test_signature_apply_task() {
        let mut task = SignatureBSimApplyTask::new();
        assert!(task.base.config.apply_signatures);
        assert!(task.base.config.apply_calling_conventions);

        task.apply_signature(
            0x1000,
            "FUN_1000",
            "int",
            "cdecl",
            &["int".to_string(), "char*".to_string()],
        );
        assert_eq!(task.base.functions_modified, 1);
        assert!(task.base.results()[0].is_success());
    }
}
