//! Listing merge manager -- orchestrates all listing merge phases.
//!
//! Port of Ghidra's `ListingMergeManager`.

use crate::base::merge::constants::*;
use crate::base::merge::error::MergeResult;
use crate::base::merge::listing::comment_merger::CommentMerger;
use crate::base::merge::resolver::{ConflictResolution, MergePhase, MergeResolver};

/// Orchestrates merging of all listing elements (comments, symbols, code units,
/// equates, references, bookmarks, etc.) between program versions.
///
/// This is a headless (non-GUI) implementation that drives individual sub-mergers.
///
/// Port of Ghidra's `ListingMergeManager`.
pub struct ListingMergeManager {
    /// Comment merger instance.
    comment_merger: CommentMerger,

    /// Global conflict option (applies to all sub-mergers).
    conflict_option: i32,

    /// Current phase name.
    current_phase: Option<String>,

    /// Total phases completed.
    phases_completed: usize,
}

impl ListingMergeManager {
    /// Create a new listing merge manager.
    pub fn new() -> Self {
        Self {
            comment_merger: CommentMerger::new(),
            conflict_option: ASK_USER,
            current_phase: None,
            phases_completed: 0,
        }
    }

    /// Get a reference to the comment merger.
    pub fn comment_merger(&self) -> &CommentMerger {
        &self.comment_merger
    }

    /// Get a mutable reference to the comment merger.
    pub fn comment_merger_mut(&mut self) -> &mut CommentMerger {
        &mut self.comment_merger
    }

    /// Set the global conflict option.
    pub fn set_conflict_option(&mut self, option: i32) {
        self.conflict_option = option;
    }

    /// Get the current conflict option.
    pub fn conflict_option(&self) -> i32 {
        self.conflict_option
    }

    /// Apply a global conflict resolution.
    pub fn apply_global_resolution(&mut self, resolution: ConflictResolution) {
        match resolution {
            ConflictResolution::KeepLatest => {
                self.conflict_option = KEEP_LATEST;
            }
            ConflictResolution::KeepMy => {
                self.conflict_option = KEEP_MY;
            }
            ConflictResolution::KeepOriginal => {
                self.conflict_option = KEEP_ORIGINAL;
            }
            ConflictResolution::Remove => {
                self.conflict_option = REMOVE_LATEST;
            }
            _ => {
                self.conflict_option = ASK_USER;
            }
        }
    }

    /// Check if the merge is being canceled.
    pub fn is_canceled(&self) -> bool {
        self.conflict_option == CANCELED
    }

    /// Get the total number of unresolved comment conflicts.
    pub fn comment_conflict_count(&self) -> usize {
        self.comment_merger.conflict_count()
    }

    /// Get the current phase name.
    pub fn current_phase(&self) -> Option<&str> {
        self.current_phase.as_deref()
    }

    /// Get the number of phases completed.
    pub fn phases_completed(&self) -> usize {
        self.phases_completed
    }

    /// The listing merge phase names (in order).
    pub fn phase_names() -> Vec<&'static str> {
        vec![
            "Code Units",
            "Externals",
            "Functions",
            "Symbols",
            "Equates, User Properties, References, Bookmarks & Comments",
        ]
    }
}

impl Default for ListingMergeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MergeResolver for ListingMergeManager {
    fn name(&self) -> &str {
        "ListingMergeManager"
    }

    fn description(&self) -> &str {
        "Manages program listing changes and conflicts"
    }

    fn merge(&mut self) -> MergeResult<()> {
        self.current_phase = Some("Listing".to_string());
        // Delegate comment merging.
        self.comment_merger.merge()?;
        self.phases_completed += 1;
        Ok(())
    }

    fn apply(&mut self) {
        self.comment_merger.apply();
    }

    fn cancel(&mut self) {
        self.conflict_option = CANCELED;
        self.comment_merger.cancel();
    }

    fn phases(&self) -> Vec<MergePhase> {
        let mut phases = vec![MergePhase::simple("Listing")];
        phases.extend(self.comment_merger.phases());
        phases
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::merge::listing::comment_merger::CommentType;

    #[test]
    fn test_listing_merge_manager_creation() {
        let mgr = ListingMergeManager::new();
        assert_eq!(mgr.conflict_option(), ASK_USER);
        assert!(!mgr.is_canceled());
        assert_eq!(mgr.phases_completed(), 0);
    }

    #[test]
    fn test_listing_merge_manager_global_resolution() {
        let mut mgr = ListingMergeManager::new();
        mgr.apply_global_resolution(ConflictResolution::KeepLatest);
        assert_eq!(mgr.conflict_option(), KEEP_LATEST);

        mgr.apply_global_resolution(ConflictResolution::KeepMy);
        assert_eq!(mgr.conflict_option(), KEEP_MY);

        mgr.apply_global_resolution(ConflictResolution::KeepOriginal);
        assert_eq!(mgr.conflict_option(), KEEP_ORIGINAL);
    }

    #[test]
    fn test_listing_merge_manager_cancel() {
        let mut mgr = ListingMergeManager::new();
        mgr.cancel();
        assert!(mgr.is_canceled());
    }

    #[test]
    fn test_listing_merge_manager_comment_integration() {
        let mut mgr = ListingMergeManager::new();

        // Add a comment conflict.
        mgr.comment_merger_mut().add_comment_pair(
            "0x401000",
            CommentType::Eol,
            Some("latest".to_string()),
            Some("my".to_string()),
            None,
        );
        assert_eq!(mgr.comment_conflict_count(), 1);

        // Resolve it.
        mgr.comment_merger_mut()
            .resolve_current(ConflictResolution::KeepLatest);
        assert_eq!(mgr.comment_conflict_count(), 0);
    }

    #[test]
    fn test_listing_merge_manager_phases() {
        let mgr = ListingMergeManager::new();
        let phases = mgr.phases();
        // Should have the top-level "Listing" phase plus comment sub-phases.
        assert!(phases.len() > 1);
        assert_eq!(phases[0].path, vec!["Listing"]);
    }

    #[test]
    fn test_listing_phase_names() {
        let names = ListingMergeManager::phase_names();
        assert_eq!(names.len(), 5);
        assert_eq!(names[0], "Code Units");
    }
}
