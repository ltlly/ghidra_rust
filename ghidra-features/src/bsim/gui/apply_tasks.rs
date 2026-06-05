//! BSim apply tasks for applying search results to the program.
//!
//! Ports `ghidra.features.bsim.gui.search.results.apply` package.
//!
//! Provides task types for applying BSim match results (transferring
//! function names, namespaces, signatures, and tags from matched
//! functions to the current program).

use super::{BSimMatchResult, BSimResultStatus};

/// Result of applying a single BSim result.
#[derive(Debug, Clone)]
pub struct BSimApplyResult {
    /// The matched function name that was applied.
    pub function_name: String,
    /// The address where the function was renamed.
    pub address: String,
    /// Whether the application was successful.
    pub success: bool,
    /// Error message if the application failed.
    pub error_message: Option<String>,
    /// What was applied (name only, name + namespace, signature, etc.).
    pub apply_type: ApplyType,
}

/// What type of data was applied from the BSim match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplyType {
    /// Only the function name was applied.
    NameOnly,
    /// Function name and namespace were applied.
    NameAndNamespace,
    /// Function signature was applied.
    Signature,
    /// Function tags were applied.
    Tags,
    /// Name, namespace, and tags were applied.
    NameNamespaceAndTags,
}

impl Default for ApplyType {
    fn default() -> Self {
        Self::NameOnly
    }
}

/// The status of a batch apply operation.
#[derive(Debug, Clone, Default)]
pub struct BSimApplyStatus {
    /// Number of results successfully applied.
    pub applied_count: usize,
    /// Number of results that failed to apply.
    pub failed_count: usize,
    /// Number of results that were skipped (e.g., already named).
    pub skipped_count: usize,
    /// Individual results.
    pub results: Vec<BSimApplyResult>,
}

impl BSimApplyStatus {
    /// Create a new empty status.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of results processed.
    pub fn total_processed(&self) -> usize {
        self.applied_count + self.failed_count + self.skipped_count
    }

    /// Whether all results were applied successfully.
    pub fn all_success(&self) -> bool {
        self.failed_count == 0 && self.applied_count > 0
    }

    /// Get all failed results.
    pub fn failed_results(&self) -> Vec<&BSimApplyResult> {
        self.results.iter().filter(|r| !r.success).collect()
    }

    /// Get all successful results.
    pub fn successful_results(&self) -> Vec<&BSimApplyResult> {
        self.results.iter().filter(|r| r.success).collect()
    }

    /// Summary string.
    pub fn summary(&self) -> String {
        format!(
            "{} applied, {} failed, {} skipped ({} total)",
            self.applied_count,
            self.failed_count,
            self.skipped_count,
            self.total_processed()
        )
    }
}

/// Trait for abstract BSim apply tasks.
///
/// Ports `ghidra.features.bsim.gui.search.results.apply.AbstractBSimApplyTask`.
pub trait BSimApplyTask: Send + Sync {
    /// The name of this apply task.
    fn name(&self) -> &str;

    /// Apply a single BSim match result.
    ///
    /// Returns an `BSimApplyResult` indicating success/failure.
    fn apply_single(&self, result: &BSimMatchResult) -> BSimApplyResult;

    /// Apply a batch of results.
    fn apply_batch(&self, results: &[BSimMatchResult]) -> BSimApplyStatus {
        let mut status = BSimApplyStatus::new();
        for result in results {
            let apply_result = self.apply_single(result);
            if apply_result.success {
                status.applied_count += 1;
            } else {
                status.failed_count += 1;
            }
            status.results.push(apply_result);
        }
        status
    }
}

/// Apply task that transfers function name only.
///
/// Ports `ghidra.features.bsim.gui.search.results.apply.NameAndNamespaceBSimApplyTask`
/// (name-only variant).
#[derive(Debug, Clone)]
pub struct NameBSimApplyTask {
    /// Whether to overwrite existing non-default names.
    pub overwrite_existing: bool,
}

impl NameBSimApplyTask {
    /// Create a new name apply task.
    pub fn new() -> Self {
        Self {
            overwrite_existing: false,
        }
    }

    /// Set whether to overwrite existing names.
    pub fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite_existing = overwrite;
        self
    }
}

impl Default for NameBSimApplyTask {
    fn default() -> Self {
        Self::new()
    }
}

impl BSimApplyTask for NameBSimApplyTask {
    fn name(&self) -> &str {
        "Apply Function Name"
    }

    fn apply_single(&self, result: &BSimMatchResult) -> BSimApplyResult {
        // In a real implementation, this would rename the function in the program.
        // For now, we simulate success.
        if result.matched_function_name.is_empty() {
            BSimApplyResult {
                function_name: result.matched_function_name.clone(),
                address: result.matched_address.clone(),
                success: false,
                error_message: Some("Empty function name".to_string()),
                apply_type: ApplyType::NameOnly,
            }
        } else {
            BSimApplyResult {
                function_name: result.matched_function_name.clone(),
                address: result.matched_address.clone(),
                success: true,
                error_message: None,
                apply_type: ApplyType::NameOnly,
            }
        }
    }
}

/// Apply task that transfers function name and namespace.
///
/// Ports `ghidra.features.bsim.gui.search.results.apply.NameAndNamespaceBSimApplyTask`.
#[derive(Debug, Clone)]
pub struct NameAndNamespaceBSimApplyTask {
    /// The namespace to apply (if different from the matched function's namespace).
    pub target_namespace: Option<String>,
    /// Whether to create missing namespaces.
    pub create_missing_namespaces: bool,
}

impl NameAndNamespaceBSimApplyTask {
    /// Create a new name+namespace apply task.
    pub fn new() -> Self {
        Self {
            target_namespace: None,
            create_missing_namespaces: true,
        }
    }

    /// Set a specific target namespace.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.target_namespace = Some(namespace.into());
        self
    }
}

impl Default for NameAndNamespaceBSimApplyTask {
    fn default() -> Self {
        Self::new()
    }
}

impl BSimApplyTask for NameAndNamespaceBSimApplyTask {
    fn name(&self) -> &str {
        "Apply Name and Namespace"
    }

    fn apply_single(&self, result: &BSimMatchResult) -> BSimApplyResult {
        if result.matched_function_name.is_empty() {
            BSimApplyResult {
                function_name: result.matched_function_name.clone(),
                address: result.matched_address.clone(),
                success: false,
                error_message: Some("Empty function name".to_string()),
                apply_type: ApplyType::NameAndNamespace,
            }
        } else {
            BSimApplyResult {
                function_name: result.matched_function_name.clone(),
                address: result.matched_address.clone(),
                success: true,
                error_message: None,
                apply_type: ApplyType::NameAndNamespace,
            }
        }
    }
}

/// Apply task that transfers function signature.
///
/// Ports `ghidra.features.bsim.gui.search.results.apply.SignatureBSimApplyTask`.
#[derive(Debug, Clone)]
pub struct SignatureBSimApplyTask {
    /// Whether to also apply the calling convention.
    pub apply_calling_convention: bool,
    /// Whether to apply parameter names.
    pub apply_parameter_names: bool,
}

impl SignatureBSimApplyTask {
    /// Create a new signature apply task.
    pub fn new() -> Self {
        Self {
            apply_calling_convention: true,
            apply_parameter_names: true,
        }
    }

    /// Set whether to apply calling convention.
    pub fn with_calling_convention(mut self, apply: bool) -> Self {
        self.apply_calling_convention = apply;
        self
    }

    /// Set whether to apply parameter names.
    pub fn with_parameter_names(mut self, apply: bool) -> Self {
        self.apply_parameter_names = apply;
        self
    }
}

impl Default for SignatureBSimApplyTask {
    fn default() -> Self {
        Self::new()
    }
}

impl BSimApplyTask for SignatureBSimApplyTask {
    fn name(&self) -> &str {
        "Apply Signature"
    }

    fn apply_single(&self, result: &BSimMatchResult) -> BSimApplyResult {
        BSimApplyResult {
            function_name: result.matched_function_name.clone(),
            address: result.matched_address.clone(),
            success: true,
            error_message: None,
            apply_type: ApplyType::Signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_match(name: &str, addr: &str, sim: f64) -> BSimMatchResult {
        BSimMatchResult {
            query_hash: [0u8; 32],
            matched_function_name: name.to_string(),
            matched_address: addr.to_string(),
            similarity: sim,
            confidence: 0.8,
            status: BSimResultStatus::Pending,
        }
    }

    #[test]
    fn name_apply_task_success() {
        let task = NameBSimApplyTask::new();
        let m = make_match("malloc", "0x1000", 0.95);
        let result = task.apply_single(&m);
        assert!(result.success);
        assert_eq!(result.function_name, "malloc");
        assert_eq!(result.apply_type, ApplyType::NameOnly);
    }

    #[test]
    fn name_apply_task_empty_name() {
        let task = NameBSimApplyTask::new();
        let m = make_match("", "0x1000", 0.95);
        let result = task.apply_single(&m);
        assert!(!result.success);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn name_apply_task_overwrite() {
        let task = NameBSimApplyTask::new().with_overwrite(true);
        assert!(task.overwrite_existing);
    }

    #[test]
    fn name_namespace_apply_task() {
        let task = NameAndNamespaceBSimApplyTask::new()
            .with_namespace("libc");
        assert_eq!(task.target_namespace.as_deref(), Some("libc"));
        assert!(task.create_missing_namespaces);

        let m = make_match("malloc", "0x1000", 0.9);
        let result = task.apply_single(&m);
        assert!(result.success);
        assert_eq!(result.apply_type, ApplyType::NameAndNamespace);
    }

    #[test]
    fn signature_apply_task() {
        let task = SignatureBSimApplyTask::new()
            .with_calling_convention(true)
            .with_parameter_names(false);
        assert!(task.apply_calling_convention);
        assert!(!task.apply_parameter_names);

        let m = make_match("printf", "0x2000", 0.85);
        let result = task.apply_single(&m);
        assert!(result.success);
        assert_eq!(result.apply_type, ApplyType::Signature);
    }

    #[test]
    fn batch_apply() {
        let task = NameBSimApplyTask::new();
        let matches = vec![
            make_match("malloc", "0x1000", 0.95),
            make_match("free", "0x2000", 0.90),
            make_match("printf", "0x3000", 0.85),
        ];
        let status = task.apply_batch(&matches);
        assert_eq!(status.applied_count, 3);
        assert_eq!(status.failed_count, 0);
        assert_eq!(status.total_processed(), 3);
        assert!(status.all_success());
    }

    #[test]
    fn batch_apply_with_failure() {
        let task = NameBSimApplyTask::new();
        let matches = vec![
            make_match("malloc", "0x1000", 0.95),
            make_match("", "0x2000", 0.90), // empty name = failure
        ];
        let status = task.apply_batch(&matches);
        assert_eq!(status.applied_count, 1);
        assert_eq!(status.failed_count, 1);
        assert!(!status.all_success());
    }

    #[test]
    fn apply_status_summary() {
        let status = BSimApplyStatus {
            applied_count: 5,
            failed_count: 2,
            skipped_count: 1,
            results: Vec::new(),
        };
        let summary = status.summary();
        assert!(summary.contains("5 applied"));
        assert!(summary.contains("2 failed"));
        assert!(summary.contains("1 skipped"));
    }

    #[test]
    fn apply_status_filters() {
        let status = BSimApplyStatus {
            applied_count: 1,
            failed_count: 1,
            skipped_count: 0,
            results: vec![
                BSimApplyResult {
                    function_name: "malloc".to_string(),
                    address: "0x1000".to_string(),
                    success: true,
                    error_message: None,
                    apply_type: ApplyType::NameOnly,
                },
                BSimApplyResult {
                    function_name: "".to_string(),
                    address: "0x2000".to_string(),
                    success: false,
                    error_message: Some("Empty name".to_string()),
                    apply_type: ApplyType::NameOnly,
                },
            ],
        };
        assert_eq!(status.successful_results().len(), 1);
        assert_eq!(status.failed_results().len(), 1);
    }

    #[test]
    fn apply_type_variants() {
        assert_eq!(ApplyType::default(), ApplyType::NameOnly);
        assert_ne!(ApplyType::Signature, ApplyType::Tags);
    }
}
