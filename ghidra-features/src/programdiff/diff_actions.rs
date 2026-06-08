//! Diff action types for bulk operations on differences.
//!
//! Ported from Ghidra's `DiffIgnoreAllAction`, `DiffMergeAllAction`,
//! and `DiffReplaceAllAction` Java classes.
//!
//! These actions set all categories in a merge filter to a single action,
//! providing quick ways to configure how differences are applied.

use super::merge_filter::{MergeAction, ProgramMergeFilter};

/// Action to set all merge categories to Ignore.
///
/// Ported from Ghidra's `DiffIgnoreAllAction` Java class.
#[derive(Debug, Clone)]
pub struct IgnoreAllAction;

impl IgnoreAllAction {
    /// Get a description of this action.
    pub fn description(&self) -> &'static str {
        "Change all the difference type apply settings to Ignore."
    }

    /// Apply this action to a merge filter, setting all categories to Ignore.
    pub fn apply(&self, filter: &mut ProgramMergeFilter) {
        *filter = ProgramMergeFilter::all_with_action(MergeAction::Ignore);
    }

    /// Create a new filter with all categories set to Ignore.
    pub fn create_filter(&self) -> ProgramMergeFilter {
        ProgramMergeFilter::all_with_action(MergeAction::Ignore)
    }
}

/// Action to set all merge categories to Merge (or Replace if merge is not supported).
///
/// Ported from Ghidra's `DiffMergeAllAction` Java class.
#[derive(Debug, Clone)]
pub struct MergeAllAction;

impl MergeAllAction {
    /// Get a description of this action.
    pub fn description(&self) -> &'static str {
        "Change all the difference type apply settings to Merge if possible. \
         Otherwise, change to Replace."
    }

    /// Apply this action to a merge filter, setting all categories to Merge.
    pub fn apply(&self, filter: &mut ProgramMergeFilter) {
        *filter = ProgramMergeFilter::all_with_action(MergeAction::Merge);
    }

    /// Create a new filter with all categories set to Merge.
    pub fn create_filter(&self) -> ProgramMergeFilter {
        ProgramMergeFilter::all_with_action(MergeAction::Merge)
    }
}

/// Action to set all merge categories to Replace.
///
/// Ported from Ghidra's `DiffReplaceAllAction` Java class.
#[derive(Debug, Clone)]
pub struct ReplaceAllAction;

impl ReplaceAllAction {
    /// Get a description of this action.
    pub fn description(&self) -> &'static str {
        "Change all the difference type apply settings to Replace."
    }

    /// Apply this action to a merge filter, setting all categories to Replace.
    pub fn apply(&self, filter: &mut ProgramMergeFilter) {
        *filter = ProgramMergeFilter::all_with_action(MergeAction::Replace);
    }

    /// Create a new filter with all categories set to Replace.
    pub fn create_filter(&self) -> ProgramMergeFilter {
        ProgramMergeFilter::all_with_action(MergeAction::Replace)
    }
}

/// Enum of all bulk diff actions.
///
/// This provides a unified way to apply any of the bulk actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BulkDiffAction {
    /// Set all categories to Ignore.
    IgnoreAll,
    /// Set all categories to Merge.
    MergeAll,
    /// Set all categories to Replace.
    ReplaceAll,
}

impl BulkDiffAction {
    /// Get a description of this action.
    pub fn description(&self) -> &'static str {
        match self {
            Self::IgnoreAll => IgnoreAllAction.description(),
            Self::MergeAll => MergeAllAction.description(),
            Self::ReplaceAll => ReplaceAllAction.description(),
        }
    }

    /// Apply this action to a merge filter.
    pub fn apply(&self, filter: &mut ProgramMergeFilter) {
        match self {
            Self::IgnoreAll => IgnoreAllAction.apply(filter),
            Self::MergeAll => MergeAllAction.apply(filter),
            Self::ReplaceAll => ReplaceAllAction.apply(filter),
        }
    }

    /// Create a new filter with this action applied to all categories.
    pub fn create_filter(&self) -> ProgramMergeFilter {
        match self {
            Self::IgnoreAll => IgnoreAllAction.create_filter(),
            Self::MergeAll => MergeAllAction.create_filter(),
            Self::ReplaceAll => ReplaceAllAction.create_filter(),
        }
    }
}

/// Task listener for diff operations.
///
/// Ported from Ghidra's `DiffTaskListener` Java interface.
pub trait DiffTaskListener {
    /// Called when the diff task starts or stops.
    fn task_in_progress(&mut self, in_progress: bool);
}

/// A no-op task listener.
///
/// Ported from Ghidra's `DiffTaskListener.NULL_LISTENER`.
pub struct NullDiffTaskListener;

impl DiffTaskListener for NullDiffTaskListener {
    fn task_in_progress(&mut self, _in_progress: bool) {
        // no-op
    }
}

/// Simple task listener that tracks progress state.
#[derive(Debug, Clone, Default)]
pub struct SimpleDiffTaskListener {
    in_progress: bool,
}

impl SimpleDiffTaskListener {
    /// Create a new simple task listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a task is in progress.
    pub fn is_in_progress(&self) -> bool {
        self.in_progress
    }
}

impl DiffTaskListener for SimpleDiffTaskListener {
    fn task_in_progress(&mut self, in_progress: bool) {
        self.in_progress = in_progress;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::merge_filter::MergeCategory;

    #[test]
    fn test_ignore_all_action() {
        let action = IgnoreAllAction;
        let filter = action.create_filter();
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Ignore);
        assert_eq!(filter.get_filter(MergeCategory::Symbols), MergeAction::Ignore);
    }

    #[test]
    fn test_merge_all_action() {
        let action = MergeAllAction;
        let filter = action.create_filter();
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Merge);
        assert_eq!(filter.get_filter(MergeCategory::Symbols), MergeAction::Merge);
    }

    #[test]
    fn test_replace_all_action() {
        let action = ReplaceAllAction;
        let filter = action.create_filter();
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Replace);
        assert_eq!(filter.get_filter(MergeCategory::Symbols), MergeAction::Replace);
    }

    #[test]
    fn test_bulk_diff_action() {
        let action = BulkDiffAction::IgnoreAll;
        let filter = action.create_filter();
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Ignore);
    }

    #[test]
    fn test_bulk_diff_action_apply() {
        let mut filter = ProgramMergeFilter::defaults();
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Replace);
        BulkDiffAction::IgnoreAll.apply(&mut filter);
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Ignore);
    }

    #[test]
    fn test_task_listener() {
        let mut listener = SimpleDiffTaskListener::new();
        assert!(!listener.is_in_progress());
        listener.task_in_progress(true);
        assert!(listener.is_in_progress());
        listener.task_in_progress(false);
        assert!(!listener.is_in_progress());
    }
}
