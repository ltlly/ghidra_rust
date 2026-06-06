//! Archive operations: open, close, save, lock, unlock, and merge.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datamgr` Java package.
//!
//! Provides the business logic for managing data type archive lifecycle
//! operations:
//! - `ArchiveOperation` -- enum of all archive operations
//! - `ArchiveOperationResult` -- result of an archive operation
//! - `ArchiveLockState` -- lock/unlock state for archives
//! - `ArchiveTransaction` -- transaction tracking for archive modifications
//! - `ConflictHandlerMode` -- how to handle data type conflicts during merge
//! - `ArchiveMergeResult` -- result of merging one archive into another

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ArchiveOperation
// ---------------------------------------------------------------------------

/// All possible operations on data type archives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveOperation {
    /// Open an archive from a file path.
    OpenFile {
        /// Path to the archive file.
        path: String,
    },
    /// Open a project archive.
    OpenProject {
        /// Project archive name.
        name: String,
    },
    /// Close an archive.
    Close {
        /// Archive name.
        name: String,
    },
    /// Save an archive.
    Save {
        /// Archive name.
        name: String,
    },
    /// Save an archive to a new location.
    SaveAs {
        /// Archive name.
        name: String,
        /// New file path.
        new_path: String,
    },
    /// Lock an archive for exclusive editing.
    Lock {
        /// Archive name.
        name: String,
    },
    /// Unlock a locked archive.
    Unlock {
        /// Archive name.
        name: String,
    },
    /// Create a new archive file.
    CreateFile {
        /// File path for the new archive.
        path: String,
    },
    /// Create a new project archive.
    CreateProject {
        /// Project archive name.
        name: String,
    },
    /// Merge one archive into another.
    Merge {
        /// Source archive name.
        source: String,
        /// Target archive name.
        target: String,
        /// Conflict handler mode.
        conflict_mode: ConflictHandlerMode,
    },
    /// Delete an archive file.
    Delete {
        /// Archive name.
        name: String,
    },
    /// Undo the last transaction in an archive.
    Undo {
        /// Archive name.
        name: String,
    },
    /// Redo the last undone transaction.
    Redo {
        /// Archive name.
        name: String,
    },
    /// Update data types from a source archive.
    Update {
        /// Archive name.
        name: String,
    },
    /// Revert an archive to its saved state.
    Revert {
        /// Archive name.
        name: String,
    },
}

// ---------------------------------------------------------------------------
// ArchiveOperationResult
// ---------------------------------------------------------------------------

/// Result of an archive operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveOperationResult {
    /// Whether the operation succeeded.
    pub success: bool,
    /// The operation that was performed.
    pub operation: String,
    /// Error message if the operation failed.
    pub error: Option<String>,
    /// Number of data types affected.
    pub types_affected: usize,
    /// Number of conflicts encountered.
    pub conflicts: usize,
}

impl ArchiveOperationResult {
    /// Create a success result.
    pub fn success(operation: impl Into<String>) -> Self {
        Self {
            success: true,
            operation: operation.into(),
            error: None,
            types_affected: 0,
            conflicts: 0,
        }
    }

    /// Create a failure result.
    pub fn failure(operation: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            success: false,
            operation: operation.into(),
            error: Some(error.into()),
            types_affected: 0,
            conflicts: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ArchiveLockState
// ---------------------------------------------------------------------------

/// Lock state for an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveLockState {
    /// Archive is unlocked and available for editing.
    Unlocked,
    /// Archive is locked by the current user.
    LockedByMe,
    /// Archive is locked by another user.
    LockedByOther {
        // The user who holds the lock.
        // user: String
    },
}

impl ArchiveLockState {
    /// Whether the archive is editable (unlocked or locked by current user).
    pub fn is_editable(&self) -> bool {
        matches!(self, Self::Unlocked | Self::LockedByMe)
    }

    /// Display string.
    pub fn display_str(&self) -> &'static str {
        match self {
            Self::Unlocked => "Unlocked",
            Self::LockedByMe => "Locked by me",
            Self::LockedByOther { .. } => "Locked by other",
        }
    }
}

// ---------------------------------------------------------------------------
// ArchiveTransaction
// ---------------------------------------------------------------------------

/// Represents a transaction on an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveTransaction {
    /// Transaction ID.
    pub id: u64,
    /// Description of what was changed.
    pub description: String,
    /// Archive name.
    pub archive_name: String,
    /// Whether the transaction has been committed.
    pub committed: bool,
    /// Number of data types modified in this transaction.
    pub types_modified: usize,
}

impl ArchiveTransaction {
    /// Create a new transaction.
    pub fn new(id: u64, archive_name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id,
            description: description.into(),
            archive_name: archive_name.into(),
            committed: false,
            types_modified: 0,
        }
    }

    /// Commit the transaction.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Abort the transaction.
    pub fn abort(&mut self) {
        self.committed = false;
    }
}

// ---------------------------------------------------------------------------
// ConflictHandlerMode
// ---------------------------------------------------------------------------

/// How to handle data type conflicts when merging archives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictHandlerMode {
    /// Use the existing (target) type, ignoring the source.
    UseExisting,
    /// Replace the existing type with the source type.
    ReplaceExisting,
    /// Rename the conflicting type.
    Rename,
    /// Use the default conflict handler behavior.
    Default,
}

impl ConflictHandlerMode {
    /// Display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::UseExisting => "Use Existing",
            Self::ReplaceExisting => "Replace Existing",
            Self::Rename => "Rename",
            Self::Default => "Default",
        }
    }
}

// ---------------------------------------------------------------------------
// ArchiveMergeResult
// ---------------------------------------------------------------------------

/// Result of merging one archive into another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveMergeResult {
    /// Whether the merge succeeded.
    pub success: bool,
    /// Total types merged.
    pub types_merged: usize,
    /// Types that conflicted and were resolved.
    pub conflicts_resolved: usize,
    /// Types that still have unresolved conflicts.
    pub unresolved_conflicts: usize,
    /// Types that were added (no conflict).
    pub types_added: usize,
    /// Types that were updated (compatible change).
    pub types_updated: usize,
    /// Merge messages.
    pub messages: Vec<String>,
}

impl ArchiveMergeResult {
    /// Create a new merge result.
    pub fn new() -> Self {
        Self {
            success: true,
            types_merged: 0,
            conflicts_resolved: 0,
            unresolved_conflicts: 0,
            types_added: 0,
            types_updated: 0,
            messages: Vec::new(),
        }
    }

    /// Get a summary string.
    pub fn summary(&self) -> String {
        format!(
            "Merged {} types ({} added, {} updated, {} conflicts resolved, {} unresolved)",
            self.types_merged,
            self.types_added,
            self.types_updated,
            self.conflicts_resolved,
            self.unresolved_conflicts,
        )
    }
}

impl Default for ArchiveMergeResult {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DataTypeSyncDetail -- detailed sync info for a single data type
// ---------------------------------------------------------------------------

/// Detailed synchronization information for a single data type between
/// a program and its source archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeSyncInfo` (expanded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeSyncDetail {
    /// The data type name.
    pub type_name: String,
    /// The data type ID.
    pub type_id: u64,
    /// The archive source name.
    pub source_archive: String,
    /// Current sync state.
    pub state: SyncState,
    /// The source (archive) version, if known.
    pub source_version: Option<String>,
    /// The program version, if known.
    pub program_version: Option<String>,
    /// Whether the type was modified in the program since last sync.
    pub modified_in_program: bool,
    /// Whether the type was modified in the archive since last sync.
    pub modified_in_archive: bool,
}

/// The synchronization state of a data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    /// The type is in sync with the archive.
    InSync,
    /// The type has been modified in the program only.
    ModifiedInProgram,
    /// The type has been modified in the archive only.
    ModifiedInArchive,
    /// The type has been modified in both the program and archive.
    Conflict,
    /// The type is not associated with any archive.
    NoArchive,
}

impl SyncState {
    /// Whether this state requires user action.
    pub fn needs_action(&self) -> bool {
        matches!(self, Self::ModifiedInProgram | Self::ModifiedInArchive | Self::Conflict)
    }

    /// Display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::InSync => "In Sync",
            Self::ModifiedInProgram => "Modified in Program",
            Self::ModifiedInArchive => "Modified in Archive",
            Self::Conflict => "Conflict",
            Self::NoArchive => "No Archive",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_operation_variants() {
        let ops = vec![
            ArchiveOperation::OpenFile { path: "/test.gdt".into() },
            ArchiveOperation::OpenProject { name: "myarchive".into() },
            ArchiveOperation::Close { name: "test".into() },
            ArchiveOperation::Save { name: "test".into() },
            ArchiveOperation::SaveAs { name: "test".into(), new_path: "/new.gdt".into() },
            ArchiveOperation::Lock { name: "test".into() },
            ArchiveOperation::Unlock { name: "test".into() },
            ArchiveOperation::CreateFile { path: "/new.gdt".into() },
            ArchiveOperation::CreateProject { name: "new".into() },
            ArchiveOperation::Merge {
                source: "src".into(),
                target: "tgt".into(),
                conflict_mode: ConflictHandlerMode::Default,
            },
            ArchiveOperation::Delete { name: "test".into() },
            ArchiveOperation::Undo { name: "test".into() },
            ArchiveOperation::Redo { name: "test".into() },
            ArchiveOperation::Update { name: "test".into() },
            ArchiveOperation::Revert { name: "test".into() },
        ];
        assert_eq!(ops.len(), 15);
    }

    #[test]
    fn test_archive_lock_state() {
        assert!(ArchiveLockState::Unlocked.is_editable());
        assert!(ArchiveLockState::LockedByMe.is_editable());
        assert!(!ArchiveLockState::LockedByOther { }.is_editable());

        assert_eq!(ArchiveLockState::Unlocked.display_str(), "Unlocked");
        assert_eq!(ArchiveLockState::LockedByMe.display_str(), "Locked by me");
    }

    #[test]
    fn test_archive_transaction() {
        let mut tx = ArchiveTransaction::new(1, "test", "Add int type");
        assert!(!tx.committed);
        tx.commit();
        assert!(tx.committed);
        tx.abort();
        assert!(!tx.committed);
    }

    #[test]
    fn test_conflict_handler_modes() {
        assert_eq!(ConflictHandlerMode::UseExisting.display_name(), "Use Existing");
        assert_eq!(ConflictHandlerMode::ReplaceExisting.display_name(), "Replace Existing");
        assert_eq!(ConflictHandlerMode::Rename.display_name(), "Rename");
        assert_eq!(ConflictHandlerMode::Default.display_name(), "Default");
    }

    #[test]
    fn test_archive_merge_result() {
        let mut result = ArchiveMergeResult::new();
        result.types_merged = 10;
        result.types_added = 5;
        result.types_updated = 3;
        result.conflicts_resolved = 2;
        result.unresolved_conflicts = 0;

        let summary = result.summary();
        assert!(summary.contains("10 types"));
        assert!(summary.contains("5 added"));
        assert!(summary.contains("3 updated"));
        assert!(summary.contains("2 conflicts resolved"));
    }

    #[test]
    fn test_archive_operation_result() {
        let success = ArchiveOperationResult::success("Save");
        assert!(success.success);
        assert!(success.error.is_none());

        let failure = ArchiveOperationResult::failure("Lock", "Already locked");
        assert!(!failure.success);
        assert_eq!(failure.error, Some("Already locked".into()));
    }

    #[test]
    fn test_data_type_sync_detail() {
        let detail = DataTypeSyncDetail {
            type_name: "my_struct".into(),
            type_id: 42,
            source_archive: "test.gdt".into(),
            state: SyncState::Conflict,
            source_version: Some("v2".into()),
            program_version: Some("v1".into()),
            modified_in_program: true,
            modified_in_archive: true,
        };

        assert_eq!(detail.state, SyncState::Conflict);
        assert!(detail.state.needs_action());
    }

    #[test]
    fn test_sync_state() {
        assert!(SyncState::ModifiedInProgram.needs_action());
        assert!(SyncState::ModifiedInArchive.needs_action());
        assert!(SyncState::Conflict.needs_action());
        assert!(!SyncState::InSync.needs_action());
        assert!(!SyncState::NoArchive.needs_action());

        assert_eq!(SyncState::InSync.display_name(), "In Sync");
        assert_eq!(SyncState::Conflict.display_name(), "Conflict");
    }

    #[test]
    fn test_archive_operation_serialization() {
        let op = ArchiveOperation::Merge {
            source: "src".into(),
            target: "tgt".into(),
            conflict_mode: ConflictHandlerMode::Rename,
        };
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: ArchiveOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(op, deserialized);
    }
}
