//! Task for determining decompiler differences between two functions.
//!
//! Ported from Ghidra's `DetermineDecompilerDifferencesTask` Java class.
//!
//! This module provides a task that computes the token-level differences
//! between two decompiled functions. It uses the Pinning algorithm to match
//! tokens and then updates the highlight controllers with the results.

use std::sync::{Arc, Mutex};

use super::super::graphanalysis::{Side, TokenBin, Pinning};
use super::highlight_controller::DiffClangHighlightController;
use super::super::panel::ProgramLocation;

/// The status of a diff computation task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    /// Task has not started yet.
    Pending,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed with an error.
    Failed,
}

/// Result of a decompiler diff computation.
#[derive(Debug, Clone)]
pub struct DiffResult {
    /// The matched token bins.
    pub token_bins: Vec<TokenBin>,
    /// Tokens in the left function that have no match.
    pub left_unmatched_tokens: Vec<UnmatchedToken>,
    /// Tokens in the right function that have no match.
    pub right_unmatched_tokens: Vec<UnmatchedToken>,
    /// The left function name.
    pub left_function_name: String,
    /// The right function name.
    pub right_function_name: String,
    /// The number of matched token pairs.
    pub matched_count: usize,
    /// Whether constants were matched exactly.
    pub constants_matched_exactly: bool,
}

/// Information about an unmatched token.
#[derive(Debug, Clone)]
pub struct UnmatchedToken {
    /// The token text.
    pub text: String,
    /// The line number (0-based).
    pub line: usize,
    /// The column offset within the line.
    pub col_start: usize,
    /// End column (exclusive).
    pub col_end: usize,
    /// Which side this token belongs to.
    pub side: Side,
    /// The address associated with this token.
    pub address: u64,
}

impl UnmatchedToken {
    /// Create a new unmatched token.
    pub fn new(
        text: impl Into<String>,
        line: usize,
        col_start: usize,
        col_end: usize,
        side: Side,
        address: u64,
    ) -> Self {
        Self {
            text: text.into(),
            line,
            col_start,
            col_end,
            side,
            address,
        }
    }
}

/// A task that determines the differences between two decompiled functions.
///
/// Ported from Ghidra's `DetermineDecompilerDifferencesTask` Java class.
///
/// The task:
/// 1. Uses the Pinning algorithm to match tokens between the two functions
/// 2. Identifies unmatched tokens on each side
/// 3. Updates the highlight controllers with the diff information
/// 4. Updates the scroll coordinator with the token pairing
///
/// In Ghidra's Java, this runs as a `Task` with a `TaskMonitor`. In this
/// Rust port, it can be executed synchronously or in a background thread.
#[derive(Debug)]
pub struct DetermineDecompilerDifferencesTask {
    /// Whether constants must match exactly.
    match_constants_exactly: bool,
    /// Left highlight controller (to be updated).
    left_highlight_controller: Arc<Mutex<DiffClangHighlightController>>,
    /// Right highlight controller (to be updated).
    right_highlight_controller: Arc<Mutex<DiffClangHighlightController>>,
    /// Current task status.
    status: TaskStatus,
    /// The result of the computation, if completed.
    result: Option<DiffResult>,
    /// Error message, if failed.
    error: Option<String>,
}

impl DetermineDecompilerDifferencesTask {
    /// Create a new diff determination task.
    pub fn new(
        match_constants_exactly: bool,
        left_highlight_controller: Arc<Mutex<DiffClangHighlightController>>,
        right_highlight_controller: Arc<Mutex<DiffClangHighlightController>>,
    ) -> Self {
        Self {
            match_constants_exactly,
            left_highlight_controller,
            right_highlight_controller,
            status: TaskStatus::Pending,
            result: None,
            error: None,
        }
    }

    /// Get the current task status.
    pub fn status(&self) -> TaskStatus {
        self.status
    }

    /// Get the result, if the task has completed.
    pub fn result(&self) -> Option<&DiffResult> {
        self.result.as_ref()
    }

    /// Get the error message, if the task failed.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Whether constants are matched exactly.
    pub fn match_constants_exactly(&self) -> bool {
        self.match_constants_exactly
    }

    /// Run the task with the given token bins and unmatched tokens.
    ///
    /// This is the main entry point. The caller provides the pre-computed
    /// token bins and unmatched token sets (e.g., from a `DecompileDataDiff`),
    /// and this task updates the highlight controllers.
    pub fn run(
        &mut self,
        token_bins: Vec<TokenBin>,
        left_unmatched: Vec<UnmatchedToken>,
        right_unmatched: Vec<UnmatchedToken>,
        left_function_name: impl Into<String>,
        right_function_name: impl Into<String>,
    ) -> &DiffResult {
        self.status = TaskStatus::Running;

        // Build the result
        let matched_count = token_bins.iter().filter(|b| b.is_matched()).count();

        let result = DiffResult {
            token_bins,
            left_unmatched_tokens: left_unmatched,
            right_unmatched_tokens: right_unmatched,
            left_function_name: left_function_name.into(),
            right_function_name: right_function_name.into(),
            matched_count,
            constants_matched_exactly: self.match_constants_exactly,
        };

        // Update highlight controllers
        if let Ok(mut left_ctrl) = self.left_highlight_controller.lock() {
            left_ctrl.set_diff_highlights_from_result(&result, Side::Left);
        }
        if let Ok(mut right_ctrl) = self.right_highlight_controller.lock() {
            right_ctrl.set_diff_highlights_from_result(&result, Side::Right);
        }

        self.result = Some(result);
        self.status = TaskStatus::Completed;
        self.result.as_ref().unwrap()
    }

    /// Run the task with pre-computed Pinning results.
    ///
    /// This is a convenience method that runs the Pinning algorithm and then
    /// processes the results.
    pub fn run_with_pinning(
        &mut self,
        pinning: &mut Pinning,
        left_markup_lines: &[String],
        right_markup_lines: &[String],
        left_function_name: impl Into<String>,
        right_function_name: impl Into<String>,
    ) -> &DiffResult {
        let (left_bins, right_bins) = pinning.execute();

        // Combine bins from both sides
        let mut all_bins = left_bins.to_vec();
        all_bins.extend_from_slice(right_bins);

        // Identify unmatched tokens (simplified: tokens in bins without a match)
        let mut left_unmatched = Vec::new();
        let mut right_unmatched = Vec::new();

        for bin in &all_bins {
            if !bin.is_matched() {
                for token in bin.iter() {
                    let unmatched = UnmatchedToken::new(
                        &token.text,
                        0, // line would come from markup analysis
                        0,
                        token.text.len(),
                        token.side,
                        token.address,
                    );
                    match token.side {
                        Side::Left => left_unmatched.push(unmatched),
                        Side::Right => right_unmatched.push(unmatched),
                    }
                }
            }
        }

        self.run(
            all_bins,
            left_unmatched,
            right_unmatched,
            left_function_name,
            right_function_name,
        )
    }

    /// Cancel the task.
    pub fn cancel(&mut self) {
        if self.status == TaskStatus::Running || self.status == TaskStatus::Pending {
            self.status = TaskStatus::Cancelled;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::graphanalysis::{DecompilerToken, TokenKind};
    use super::super::highlight_controller::DecompilerComparisonOptions;

    fn make_highlight_ctrl() -> Arc<Mutex<DiffClangHighlightController>> {
        let opts = DecompilerComparisonOptions::default();
        Arc::new(Mutex::new(DiffClangHighlightController::new(opts)))
    }

    fn make_token_bin(side: Side, matched: bool) -> TokenBin {
        let mut bin = TokenBin::new(side);
        bin.add(DecompilerToken {
            text: "x".to_string(),
            kind: TokenKind::Variable,
            address: 0x1000,
            side,
        });
        if matched {
            bin.match_index = Some(0);
        }
        bin
    }

    #[test]
    fn test_task_creation() {
        let left = make_highlight_ctrl();
        let right = make_highlight_ctrl();
        let task = DetermineDecompilerDifferencesTask::new(true, left, right);

        assert_eq!(task.status(), TaskStatus::Pending);
        assert!(task.result().is_none());
        assert!(task.match_constants_exactly());
    }

    #[test]
    fn test_task_run_basic() {
        let left = make_highlight_ctrl();
        let right = make_highlight_ctrl();
        let mut task = DetermineDecompilerDifferencesTask::new(false, left, right);

        let bins = vec![
            make_token_bin(Side::Left, true),
            make_token_bin(Side::Right, true),
        ];

        task.run(bins, vec![], vec![], "left_func", "right_func");

        assert_eq!(task.status(), TaskStatus::Completed);
        let result = task.result().unwrap();
        assert_eq!(result.matched_count, 2);
        assert_eq!(result.left_function_name, "left_func");
        assert_eq!(result.right_function_name, "right_func");
        assert!(!result.constants_matched_exactly);
    }

    #[test]
    fn test_task_run_with_unmatched() {
        let left = make_highlight_ctrl();
        let right = make_highlight_ctrl();
        let mut task = DetermineDecompilerDifferencesTask::new(true, left, right);

        let bins = vec![make_token_bin(Side::Left, false)];
        let left_unmatched = vec![UnmatchedToken::new("extra_var", 5, 4, 13, Side::Left, 0x1000)];

        task.run(bins, left_unmatched, vec![], "left", "right");
        let result = task.result().unwrap();

        assert_eq!(result.left_unmatched_tokens.len(), 1);
        assert_eq!(result.left_unmatched_tokens[0].text, "extra_var");
        assert_eq!(result.left_unmatched_tokens[0].line, 5);
        assert!(result.constants_matched_exactly);
    }

    #[test]
    fn test_task_cancel() {
        let left = make_highlight_ctrl();
        let right = make_highlight_ctrl();
        let mut task = DetermineDecompilerDifferencesTask::new(false, left, right);

        task.cancel();
        assert_eq!(task.status(), TaskStatus::Cancelled);
    }

    #[test]
    fn test_task_cancel_after_complete() {
        let left = make_highlight_ctrl();
        let right = make_highlight_ctrl();
        let mut task = DetermineDecompilerDifferencesTask::new(false, left, right);

        task.run(vec![], vec![], vec![], "a", "b");
        task.cancel();
        // Should not change from completed
        assert_eq!(task.status(), TaskStatus::Completed);
    }

    #[test]
    fn test_unmatched_token_creation() {
        let token = UnmatchedToken::new("my_var", 10, 5, 11, Side::Right, 0x2000);
        assert_eq!(token.text, "my_var");
        assert_eq!(token.line, 10);
        assert_eq!(token.col_start, 5);
        assert_eq!(token.col_end, 11);
        assert_eq!(token.side, Side::Right);
        assert_eq!(token.address, 0x2000);
    }

    #[test]
    fn test_diff_result_properties() {
        let left = make_highlight_ctrl();
        let right = make_highlight_ctrl();
        let mut task = DetermineDecompilerDifferencesTask::new(false, left, right);

        let bins = vec![
            make_token_bin(Side::Left, true),
            make_token_bin(Side::Left, false),
            make_token_bin(Side::Right, true),
            make_token_bin(Side::Right, false),
        ];

        task.run(
            bins,
            vec![UnmatchedToken::new("a", 0, 0, 1, Side::Left, 0)],
            vec![UnmatchedToken::new("b", 0, 0, 1, Side::Right, 0)],
            "L",
            "R",
        );

        let result_ref = task.result().unwrap();
        assert_eq!(result_ref.token_bins.len(), 4);
        assert_eq!(result_ref.matched_count, 2);
        assert_eq!(result_ref.left_unmatched_tokens.len(), 1);
        assert_eq!(result_ref.right_unmatched_tokens.len(), 1);
    }

    #[test]
    fn test_task_status_transitions() {
        let left = make_highlight_ctrl();
        let right = make_highlight_ctrl();
        let mut task = DetermineDecompilerDifferencesTask::new(false, left, right);

        assert_eq!(task.status(), TaskStatus::Pending);

        task.run(vec![], vec![], vec![], "a", "b");
        assert_eq!(task.status(), TaskStatus::Completed);
    }
}
