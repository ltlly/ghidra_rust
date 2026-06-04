//! Comment merge support.
//!
//! Port of Ghidra's `CommentMerger` for merging five kinds of comments
//! (plate, pre, EOL, repeatable, post) across program versions.

use crate::base::merge::error::MergeResult;
use crate::base::merge::resolver::{ConflictResolution, MergePhase, MergeResolver};
use crate::base::merge::util;

/// The kind of comment in a Ghidra program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// A large block comment displayed above a code unit.
    Plate,
    /// A line comment displayed before a code unit.
    Pre,
    /// An end-of-line comment displayed to the right of a code unit.
    Eol,
    /// A repeatable comment that propagates to references.
    Repeatable,
    /// A comment displayed after a code unit.
    Post,
}

impl CommentType {
    /// The merge phase name for this comment type.
    pub fn phase_name(&self) -> &'static str {
        match self {
            Self::Plate => "Plate Comments",
            Self::Pre => "Pre Comments",
            Self::Eol => "EOL Comments",
            Self::Repeatable => "Repeatable Comments",
            Self::Post => "Post Comments",
        }
    }
}

/// A single comment conflict at a given address.
#[derive(Debug, Clone)]
pub struct CommentConflict {
    /// The address (hex string).
    pub address: String,
    /// The comment type.
    pub comment_type: CommentType,
    /// The latest version's comment text (or `None` if absent).
    pub latest: Option<String>,
    /// The user's (my) version's comment text (or `None` if absent).
    pub my: Option<String>,
    /// The original version's comment text (or `None` if absent).
    pub original: Option<String>,
    /// Whether this conflict is resolved.
    pub resolved: bool,
    /// The resolution chosen (once resolved).
    pub resolution: Option<ConflictResolution>,
}

impl CommentConflict {
    /// Create a new unresolved comment conflict.
    pub fn new(
        address: impl Into<String>,
        comment_type: CommentType,
        latest: Option<String>,
        my: Option<String>,
        original: Option<String>,
    ) -> Self {
        Self {
            address: address.into(),
            comment_type,
            latest,
            my,
            original,
            resolved: false,
            resolution: None,
        }
    }

    /// Mark this conflict as resolved with the given resolution.
    pub fn resolve(&mut self, resolution: ConflictResolution) {
        self.resolved = true;
        self.resolution = Some(resolution);
    }

    /// Get the content for the given resolution.
    pub fn get_resolved_content(&self) -> Option<&str> {
        match self.resolution? {
            ConflictResolution::KeepLatest => self.latest.as_deref(),
            ConflictResolution::KeepMy => self.my.as_deref(),
            ConflictResolution::KeepOriginal => self.original.as_deref(),
            ConflictResolution::Remove => None,
            _ => self.latest.as_deref(),
        }
    }
}

/// Merger for program comments.
///
/// Merges all five comment types (plate, pre, EOL, repeatable, post) between
/// the latest and my program versions. Non-conflicting changes (present in one
/// version but not the other) are auto-merged. Conflicting changes (different
/// text at the same address in both versions) are collected for interactive
/// resolution.
///
/// Port of Ghidra's `CommentMerger`.
pub struct CommentMerger {
    /// Auto-merged comments: `(address, comment_type, resolved_text)`.
    auto_merged: Vec<(String, CommentType, String)>,

    /// Conflicting comments awaiting interactive resolution.
    conflicts: Vec<CommentConflict>,

    /// The "use for all" resolution per comment type.
    /// If `Some`, future conflicts of this type are resolved automatically.
    use_for_all: [Option<ConflictResolution>; 5],

    /// Index of the current conflict being resolved.
    current_conflict_idx: usize,

    /// Total number of conflicts.
    total_conflicts: usize,
}

impl CommentMerger {
    /// Create a new empty comment merger.
    pub fn new() -> Self {
        Self {
            auto_merged: Vec::new(),
            conflicts: Vec::new(),
            use_for_all: [None; 5],
            current_conflict_idx: 0,
            total_conflicts: 0,
        }
    }

    /// Add comments from both versions at a given address for a given comment type.
    ///
    /// Non-conflicting changes are auto-merged; conflicts are queued.
    pub fn add_comment_pair(
        &mut self,
        address: impl Into<String>,
        comment_type: CommentType,
        latest: Option<String>,
        my: Option<String>,
        original: Option<String>,
    ) {
        let addr = address.into();

        let has_latest = latest.is_some();
        let has_my = my.is_some();

        match (has_latest, has_my) {
            // Both changed to the same value -- no conflict.
            (true, true) if latest == my => {
                self.auto_merged.push((
                    addr,
                    comment_type,
                    latest.unwrap(),
                ));
            }
            // Only one version changed -- auto-merge.
            (true, false) => {
                self.auto_merged.push((
                    addr,
                    comment_type,
                    latest.unwrap(),
                ));
            }
            (false, true) => {
                self.auto_merged.push((
                    addr,
                    comment_type,
                    my.unwrap(),
                ));
            }
            // Both changed to different values -- conflict.
            (true, true) => {
                // Check "use for all" first.
                let idx = Self::comment_type_index(comment_type);
                if let Some(resolution) = self.use_for_all[idx] {
                    let content = match resolution {
                        ConflictResolution::KeepLatest => latest,
                        ConflictResolution::KeepMy => my,
                        _ => latest,
                    };
                    if let Some(text) = content {
                        self.auto_merged.push((addr, comment_type, text));
                    }
                } else {
                    self.conflicts.push(CommentConflict::new(
                        addr,
                        comment_type,
                        latest,
                        my,
                        original,
                    ));
                }
            }
            // Neither changed -- nothing to do.
            (false, false) => {}
        }

        self.total_conflicts = self.conflicts.iter().filter(|c| !c.resolved).count();
    }

    /// Get the auto-merged comments.
    pub fn auto_merged(&self) -> &[(String, CommentType, String)] {
        &self.auto_merged
    }

    /// Get the list of unresolved conflicts.
    pub fn unresolved_conflicts(&self) -> Vec<&CommentConflict> {
        self.conflicts.iter().filter(|c| !c.resolved).collect()
    }

    /// Get all conflicts (resolved and unresolved).
    pub fn all_conflicts(&self) -> &[CommentConflict] {
        &self.conflicts
    }

    /// Resolve the current conflict.
    pub fn resolve_current(&mut self, resolution: ConflictResolution) {
        if let Some(conflict) = self
            .conflicts
            .iter_mut()
            .filter(|c| !c.resolved)
            .nth(self.current_conflict_idx)
        {
            conflict.resolve(resolution);
            let content = conflict.get_resolved_content().map(|s| s.to_string());
            if let Some(text) = content {
                self.auto_merged.push((
                    conflict.address.clone(),
                    conflict.comment_type,
                    text,
                ));
            }
            self.current_conflict_idx = 0;
        }
        self.total_conflicts = self.conflicts.iter().filter(|c| !c.resolved).count();
    }

    /// Set the "use for all" resolution for a comment type.
    pub fn set_use_for_all(&mut self, comment_type: CommentType, resolution: ConflictResolution) {
        let idx = Self::comment_type_index(comment_type);
        self.use_for_all[idx] = Some(resolution);
    }

    /// Get the "use for all" resolution for a comment type.
    pub fn get_use_for_all(&self, comment_type: CommentType) -> Option<ConflictResolution> {
        self.use_for_all[Self::comment_type_index(comment_type)]
    }

    /// Apply "use for all" to remaining unresolved conflicts of the given type.
    pub fn apply_use_for_all(&mut self, comment_type: CommentType) {
        let idx = Self::comment_type_index(comment_type);
        if let Some(resolution) = self.use_for_all[idx] {
            let mut newly_resolved = Vec::new();
            for conflict in &mut self.conflicts {
                if !conflict.resolved && conflict.comment_type == comment_type {
                    conflict.resolve(resolution);
                    if let Some(text) = conflict.get_resolved_content() {
                        newly_resolved
                            .push((conflict.address.clone(), comment_type, text.to_string()));
                    }
                }
            }
            self.auto_merged.extend(newly_resolved);
            self.total_conflicts = self.conflicts.iter().filter(|c| !c.resolved).count();
        }
    }

    /// The total number of unresolved conflicts.
    pub fn conflict_count(&self) -> usize {
        self.conflicts.iter().filter(|c| !c.resolved).count()
    }

    /// Format a conflict count message for display.
    pub fn conflict_count_message(&self, conflict_num: i32, total: i32, address: &str) -> String {
        util::get_conflict_count_with_address(conflict_num, total, address)
    }

    fn comment_type_index(ct: CommentType) -> usize {
        match ct {
            CommentType::Plate => 0,
            CommentType::Pre => 1,
            CommentType::Eol => 2,
            CommentType::Repeatable => 3,
            CommentType::Post => 4,
        }
    }
}

impl Default for CommentMerger {
    fn default() -> Self {
        Self::new()
    }
}

impl MergeResolver for CommentMerger {
    fn name(&self) -> &str {
        "CommentMerger"
    }

    fn description(&self) -> &str {
        "Merge comments between program versions"
    }

    fn merge(&mut self) -> MergeResult<()> {
        // Comment merging is driven by add_comment_pair() calls,
        // so the merge() method is a no-op.
        Ok(())
    }

    fn phases(&self) -> Vec<MergePhase> {
        vec![
            MergePhase::nested("Listing", CommentType::Plate.phase_name()),
            MergePhase::nested("Listing", CommentType::Pre.phase_name()),
            MergePhase::nested("Listing", CommentType::Eol.phase_name()),
            MergePhase::nested("Listing", CommentType::Repeatable.phase_name()),
            MergePhase::nested("Listing", CommentType::Post.phase_name()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_auto_merge_only_latest() {
        let mut merger = CommentMerger::new();
        merger.add_comment_pair(
            "0x401000",
            CommentType::Eol,
            Some("latest comment".to_string()),
            None,
            None,
        );
        assert_eq!(merger.auto_merged().len(), 1);
        assert_eq!(merger.conflict_count(), 0);
        assert_eq!(merger.auto_merged()[0].2, "latest comment");
    }

    #[test]
    fn test_comment_auto_merge_only_my() {
        let mut merger = CommentMerger::new();
        merger.add_comment_pair(
            "0x401000",
            CommentType::Pre,
            None,
            Some("my comment".to_string()),
            None,
        );
        assert_eq!(merger.auto_merged().len(), 1);
        assert_eq!(merger.auto_merged()[0].2, "my comment");
    }

    #[test]
    fn test_comment_auto_merge_same_value() {
        let mut merger = CommentMerger::new();
        merger.add_comment_pair(
            "0x401000",
            CommentType::Post,
            Some("same".to_string()),
            Some("same".to_string()),
            None,
        );
        assert_eq!(merger.auto_merged().len(), 1);
        assert_eq!(merger.conflict_count(), 0);
    }

    #[test]
    fn test_comment_conflict_different_values() {
        let mut merger = CommentMerger::new();
        merger.add_comment_pair(
            "0x401000",
            CommentType::Eol,
            Some("latest".to_string()),
            Some("my version".to_string()),
            Some("original".to_string()),
        );
        assert_eq!(merger.auto_merged().len(), 0);
        assert_eq!(merger.conflict_count(), 1);
    }

    #[test]
    fn test_comment_conflict_resolve() {
        let mut merger = CommentMerger::new();
        merger.add_comment_pair(
            "0x401000",
            CommentType::Eol,
            Some("latest".to_string()),
            Some("my version".to_string()),
            None,
        );
        assert_eq!(merger.conflict_count(), 1);
        merger.resolve_current(ConflictResolution::KeepLatest);
        assert_eq!(merger.conflict_count(), 0);
        assert_eq!(merger.auto_merged().len(), 1);
        assert_eq!(merger.auto_merged()[0].2, "latest");
    }

    #[test]
    fn test_comment_use_for_all() {
        let mut merger = CommentMerger::new();
        merger.set_use_for_all(CommentType::Plate, ConflictResolution::KeepMy);
        assert_eq!(
            merger.get_use_for_all(CommentType::Plate),
            Some(ConflictResolution::KeepMy)
        );
    }

    #[test]
    fn test_comment_use_for_all_auto_resolves() {
        let mut merger = CommentMerger::new();
        merger.set_use_for_all(CommentType::Eol, ConflictResolution::KeepMy);

        // First conflict -- should be auto-resolved.
        merger.add_comment_pair(
            "0x401000",
            CommentType::Eol,
            Some("latest".to_string()),
            Some("my".to_string()),
            None,
        );
        assert_eq!(merger.conflict_count(), 0);
        assert_eq!(merger.auto_merged().len(), 1);
        assert_eq!(merger.auto_merged()[0].2, "my");
    }

    #[test]
    fn test_comment_multiple_conflicts() {
        let mut merger = CommentMerger::new();
        merger.add_comment_pair(
            "0x401000",
            CommentType::Plate,
            Some("L1".to_string()),
            Some("M1".to_string()),
            None,
        );
        merger.add_comment_pair(
            "0x402000",
            CommentType::Plate,
            Some("L2".to_string()),
            Some("M2".to_string()),
            None,
        );
        merger.add_comment_pair(
            "0x403000",
            CommentType::Eol,
            Some("L3".to_string()),
            Some("M3".to_string()),
            None,
        );
        assert_eq!(merger.conflict_count(), 3);
    }

    #[test]
    fn test_comment_phases() {
        let merger = CommentMerger::new();
        let phases = merger.phases();
        assert_eq!(phases.len(), 5);
        assert_eq!(phases[0].path, vec!["Listing", "Plate Comments"]);
    }

    #[test]
    fn test_comment_conflict_get_resolved_content() {
        let mut conflict = CommentConflict::new(
            "0x401000",
            CommentType::Eol,
            Some("latest".to_string()),
            Some("my".to_string()),
            None,
        );
        assert!(conflict.get_resolved_content().is_none());

        conflict.resolve(ConflictResolution::KeepMy);
        assert_eq!(conflict.get_resolved_content(), Some("my"));
    }

    #[test]
    fn test_comment_conflict_remove() {
        let mut conflict = CommentConflict::new(
            "0x401000",
            CommentType::Plate,
            Some("text".to_string()),
            Some("text2".to_string()),
            None,
        );
        conflict.resolve(ConflictResolution::Remove);
        assert!(conflict.get_resolved_content().is_none());
    }

    #[test]
    fn test_comment_neither_changed() {
        let mut merger = CommentMerger::new();
        merger.add_comment_pair(
            "0x401000",
            CommentType::Eol,
            None,
            None,
            None,
        );
        assert_eq!(merger.auto_merged().len(), 0);
        assert_eq!(merger.conflict_count(), 0);
    }

    #[test]
    fn test_comment_conflict_count_message() {
        let merger = CommentMerger::new();
        let msg = merger.conflict_count_message(1, 5, "0x401000");
        assert!(msg.contains("Conflict #"));
        assert!(msg.contains("@ address:"));
    }

    #[test]
    fn test_apply_use_for_all() {
        let mut merger = CommentMerger::new();
        merger.add_comment_pair(
            "0x401000",
            CommentType::Plate,
            Some("L1".to_string()),
            Some("M1".to_string()),
            None,
        );
        assert_eq!(merger.conflict_count(), 1);

        merger.set_use_for_all(CommentType::Plate, ConflictResolution::KeepLatest);
        merger.apply_use_for_all(CommentType::Plate);
        assert_eq!(merger.conflict_count(), 0);
    }
}
