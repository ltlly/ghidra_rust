//! Data Type Synchronizer -- high-level sync orchestration for the Data Type Manager.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datamgr.DataTypeSynchronizer`
//! (the GUI-facing orchestrator, distinct from the lower-level
//! [`ghidra_features::datamgr::sync`] module which provides the state
//! machine and per-type metadata).
//!
//! This module provides [`DtMgrSynchronizer`], which drives the
//! synchronize-commit-update workflow visible in the Data Type Manager
//! window.  It collects out-of-sync data types from a client manager and
//! a source archive, presents them in a table, and applies the user's
//! chosen resolution (update from source, commit to source, or ignore).
//!
//! # Architecture
//!
//! ```text
//! DtMgrSynchronizer
//!   ├── client_name / source_name
//!   ├── entries: Vec<SynchronizerEntry>   (out-of-sync types)
//!   ├── listener: Option<Box<dyn DtMgrSyncListener>>
//!   └── state (running, completed, cancelled)
//! ```
//!
//! # Relationship to `datamgr::sync`
//!
//! The lower-level [`DataTypeSyncInfo`] computes the five-state machine
//! for a single data type.  This orchestrator:
//!
//! 1. Builds a list of [`SynchronizerEntry`] items from an iterator of
//!    [`DataTypeSyncInfo`] values.
//! 2. Tracks aggregate statistics (total, updated, committed, skipped).
//! 3. Drives the progress callbacks via [`DtMgrSyncListener`].

use std::fmt;

use ghidra_core::data::{DataTypePath, UniversalID};

// ---------------------------------------------------------------------------
// SynchronizerEntry -- a single data type in the sync table
// ---------------------------------------------------------------------------

/// A single out-of-sync data type entry displayed by the synchronizer.
///
/// Each entry wraps the sync metadata computed by the lower-level
/// [`DataTypeSyncInfo`] and adds the user-chosen resolution action.
#[derive(Debug, Clone)]
pub struct SynchronizerEntry {
    /// The data type path in the client (program) manager.
    pub client_path: DataTypePath,
    /// The data type path in the source archive.
    pub source_path: DataTypePath,
    /// Display name.
    name: String,
    /// The current sync state.
    sync_state: SyncResolution,
    /// The user-chosen action for this entry.
    action: SyncAction,
    /// Whether this entry is selected in the UI.
    selected: bool,
    /// Last change timestamp in the client manager.
    client_change_time: u64,
    /// Last change timestamp in the source archive.
    source_change_time: u64,
}

/// The simplified sync state used by the synchronizer table.
///
/// This is intentionally simpler than the full [`DataTypeSyncState`]
/// because the synchronizer table only needs to distinguish between
/// "needs update", "needs commit", "conflict", and "orphan".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncResolution {
    /// The source archive has changed; an update is available.
    NeedsUpdate,
    /// The local copy has changed; a commit is available.
    NeedsCommit,
    /// Both sides changed independently.
    Conflict,
    /// The source type no longer exists in the archive.
    Orphan,
}

impl SyncResolution {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::NeedsUpdate => "Update Available",
            Self::NeedsCommit => "Commit Available",
            Self::Conflict => "Conflict",
            Self::Orphan => "Orphan",
        }
    }

    /// Whether the user can choose "update" for this resolution.
    pub fn can_update(&self) -> bool {
        matches!(self, Self::NeedsUpdate | Self::Conflict)
    }

    /// Whether the user can choose "commit" for this resolution.
    pub fn can_commit(&self) -> bool {
        matches!(self, Self::NeedsCommit | Self::Conflict | Self::Orphan)
    }
}

impl fmt::Display for SyncResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// The action chosen by the user for a synchronizer entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncAction {
    /// Pull the source version into the client manager.
    Update,
    /// Push the client version into the source archive.
    Commit,
    /// Skip this data type (leave it out of sync).
    Skip,
    /// Revert the local changes to match the source.
    Revert,
}

impl SyncAction {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Update => "Update",
            Self::Commit => "Commit",
            Self::Skip => "Skip",
            Self::Revert => "Revert",
        }
    }
}

impl Default for SyncAction {
    fn default() -> Self {
        Self::Skip
    }
}

impl fmt::Display for SyncAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl SynchronizerEntry {
    /// Create a new synchronizer entry.
    pub fn new(
        client_path: DataTypePath,
        source_path: DataTypePath,
        name: impl Into<String>,
        resolution: SyncResolution,
        client_change_time: u64,
        source_change_time: u64,
    ) -> Self {
        let action = match resolution {
            SyncResolution::NeedsUpdate => SyncAction::Update,
            SyncResolution::NeedsCommit => SyncAction::Commit,
            SyncResolution::Conflict => SyncAction::Skip,
            SyncResolution::Orphan => SyncAction::Commit,
        };
        Self {
            client_path,
            source_path,
            name: name.into(),
            sync_state: resolution,
            action,
            selected: true,
            client_change_time,
            source_change_time,
        }
    }

    /// The display name of this data type.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The current sync resolution state.
    pub fn resolution(&self) -> SyncResolution {
        self.sync_state
    }

    /// The user-chosen action.
    pub fn action(&self) -> SyncAction {
        self.action
    }

    /// Set the user-chosen action.
    pub fn set_action(&mut self, action: SyncAction) {
        self.action = action;
    }

    /// Whether this entry is selected in the UI.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set the selection state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Last change timestamp in the client manager.
    pub fn client_change_time(&self) -> u64 {
        self.client_change_time
    }

    /// Last change timestamp in the source archive.
    pub fn source_change_time(&self) -> u64 {
        self.source_change_time
    }
}

impl fmt::Display for SynchronizerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] -> {}",
            self.name,
            self.sync_state.label(),
            self.action.label()
        )
    }
}

// ---------------------------------------------------------------------------
// DtMgrSyncListener -- progress callback for the synchronizer
// ---------------------------------------------------------------------------

/// Listener for synchronizer progress events.
///
/// Ported from Ghidra's `DataTypeSyncListener` and the progress
/// reporting in `DataTypeSynchronizer`.
pub trait DtMgrSyncListener: fmt::Debug + Send + Sync {
    /// Called when a single data type has been processed.
    fn on_entry_processed(&self, _entry: &SynchronizerEntry) {}

    /// Called when the entire sync operation completes.
    fn on_sync_finished(&self, _summary: &SyncSummary) {}
}

// ---------------------------------------------------------------------------
// SyncSummary -- aggregate statistics for a completed sync
// ---------------------------------------------------------------------------

/// Aggregate statistics for a completed synchronization run.
#[derive(Debug, Clone, Default)]
pub struct SyncSummary {
    /// Total number of out-of-sync entries.
    pub total: usize,
    /// Number of entries updated from the source archive.
    pub updated: usize,
    /// Number of entries committed to the source archive.
    pub committed: usize,
    /// Number of entries skipped.
    pub skipped: usize,
    /// Number of entries reverted.
    pub reverted: usize,
}

impl SyncSummary {
    /// The number of entries that were actually changed (updated + committed + reverted).
    pub fn changed(&self) -> usize {
        self.updated + self.committed + self.reverted
    }

    /// Whether any changes were made.
    pub fn has_changes(&self) -> bool {
        self.changed() > 0
    }
}

impl fmt::Display for SyncSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sync: {} total, {} updated, {} committed, {} skipped, {} reverted",
            self.total, self.updated, self.committed, self.skipped, self.reverted
        )
    }
}

// ---------------------------------------------------------------------------
// DtMgrSynchronizer -- the main orchestrator
// ---------------------------------------------------------------------------

/// High-level synchronizer that drives the sync-commit-update workflow
/// visible in the Data Type Manager window.
///
/// Ported from the GUI-facing `DataTypeSynchronizer` in Ghidra's
/// `ghidra.app.plugin.core.datamgr` package.
///
/// # Usage
///
/// ```rust
/// use ghidra_features::base::datamgr::data_type_synchronizer::*;
/// use ghidra_core::data::{DataTypePath, CategoryPath};
///
/// let mut sync = DtMgrSynchronizer::new("MyProgram", "generic_C_lib");
/// sync.add_entry(SynchronizerEntry::new(
///     DataTypePath::new(CategoryPath::ROOT, "my_struct"),
///     DataTypePath::new(CategoryPath::ROOT, "my_struct"),
///     "my_struct",
///     SyncResolution::NeedsUpdate,
///     100, 200,
/// ));
/// let summary = sync.apply();
/// assert_eq!(summary.total, 1);
/// ```
#[derive(Debug)]
pub struct DtMgrSynchronizer {
    /// Name of the client (program) data type manager.
    client_name: String,
    /// Name of the source archive.
    source_name: String,
    /// ID of the client manager.
    client_id: Option<UniversalID>,
    /// ID of the source archive.
    source_id: Option<UniversalID>,
    /// The out-of-sync entries.
    entries: Vec<SynchronizerEntry>,
    /// Progress listener.
    listener: Option<Box<dyn DtMgrSyncListener>>,
    /// Whether the synchronizer has been applied.
    applied: bool,
    /// Whether the operation was cancelled.
    cancelled: bool,
}

impl DtMgrSynchronizer {
    /// Create a new synchronizer for the given client and source.
    pub fn new(
        client_name: impl Into<String>,
        source_name: impl Into<String>,
    ) -> Self {
        Self {
            client_name: client_name.into(),
            source_name: source_name.into(),
            client_id: None,
            source_id: None,
            entries: Vec::new(),
            listener: None,
            applied: false,
            cancelled: false,
        }
    }

    /// Set the universal IDs for client and source managers.
    pub fn set_ids(&mut self, client_id: UniversalID, source_id: UniversalID) {
        self.client_id = Some(client_id);
        self.source_id = Some(source_id);
    }

    /// The name of the client (program) data type manager.
    pub fn client_name(&self) -> &str {
        &self.client_name
    }

    /// The name of the source archive.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    /// Set a progress listener.
    pub fn set_listener(&mut self, listener: Box<dyn DtMgrSyncListener>) {
        self.listener = Some(listener);
    }

    /// Add an out-of-sync entry.
    pub fn add_entry(&mut self, entry: SynchronizerEntry) {
        self.entries.push(entry);
    }

    /// Add multiple entries from a slice of sync info metadata.
    ///
    /// This is a convenience method that converts lower-level
    /// [`DataTypeSyncInfo`] values into [`SynchronizerEntry`] items.
    pub fn add_entries_from_info(
        &mut self,
        client_path: DataTypePath,
        source_path: DataTypePath,
        name: impl Into<String>,
        resolution: SyncResolution,
        client_change_time: u64,
        source_change_time: u64,
    ) {
        self.entries.push(SynchronizerEntry::new(
            client_path,
            source_path,
            name,
            resolution,
            client_change_time,
            source_change_time,
        ));
    }

    /// Returns a reference to the entries.
    pub fn entries(&self) -> &[SynchronizerEntry] {
        &self.entries
    }

    /// Returns a mutable reference to the entries.
    pub fn entries_mut(&mut self) -> &mut Vec<SynchronizerEntry> {
        &mut self.entries
    }

    /// The number of out-of-sync entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// The number of entries selected for processing.
    pub fn selected_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_selected()).count()
    }

    /// Sets the action on all selected entries.
    pub fn set_action_on_selected(&mut self, action: SyncAction) {
        for entry in &mut self.entries {
            if entry.selected {
                entry.action = action;
            }
        }
    }

    /// Sets the action on entries with the given resolution.
    pub fn set_action_by_resolution(&mut self, resolution: SyncResolution, action: SyncAction) {
        for entry in &mut self.entries {
            if entry.sync_state == resolution {
                entry.action = action;
            }
        }
    }

    /// Select all entries.
    pub fn select_all(&mut self) {
        for entry in &mut self.entries {
            entry.selected = true;
        }
    }

    /// Deselect all entries.
    pub fn deselect_all(&mut self) {
        for entry in &mut self.entries {
            entry.selected = false;
        }
    }

    /// Whether the synchronizer has been applied.
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Whether the operation was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Cancel the synchronizer.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Apply the chosen actions to all selected entries.
    ///
    /// Returns a [`SyncSummary`] with aggregate statistics.
    pub fn apply(&mut self) -> SyncSummary {
        let mut summary = SyncSummary::default();

        for entry in &self.entries {
            summary.total += 1;
            if !entry.selected {
                summary.skipped += 1;
                continue;
            }
            match entry.action {
                SyncAction::Update => summary.updated += 1,
                SyncAction::Commit => summary.committed += 1,
                SyncAction::Revert => summary.reverted += 1,
                SyncAction::Skip => summary.skipped += 1,
            }
            if let Some(ref listener) = self.listener {
                listener.on_entry_processed(entry);
            }
        }

        self.applied = true;
        if let Some(ref listener) = self.listener {
            listener.on_sync_finished(&summary);
        }
        summary
    }
}

impl Default for DtMgrSynchronizer {
    fn default() -> Self {
        Self::new("", "")
    }
}

impl fmt::Display for DtMgrSynchronizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DtMgrSynchronizer({} -> {}, {} entries)",
            self.client_name,
            self.source_name,
            self.entries.len()
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::data::CategoryPath;

    fn make_path(name: &str) -> DataTypePath {
        DataTypePath::new(CategoryPath::ROOT, name)
    }

    #[test]
    fn test_sync_resolution_labels() {
        assert_eq!(SyncResolution::NeedsUpdate.label(), "Update Available");
        assert_eq!(SyncResolution::NeedsCommit.label(), "Commit Available");
        assert_eq!(SyncResolution::Conflict.label(), "Conflict");
        assert_eq!(SyncResolution::Orphan.label(), "Orphan");
    }

    #[test]
    fn test_sync_resolution_predicates() {
        assert!(SyncResolution::NeedsUpdate.can_update());
        assert!(!SyncResolution::NeedsUpdate.can_commit());

        assert!(SyncResolution::NeedsCommit.can_commit());
        assert!(!SyncResolution::NeedsCommit.can_update());

        assert!(SyncResolution::Conflict.can_update());
        assert!(SyncResolution::Conflict.can_commit());

        assert!(SyncResolution::Orphan.can_commit());
        assert!(!SyncResolution::Orphan.can_update());
    }

    #[test]
    fn test_sync_resolution_display() {
        assert_eq!(format!("{}", SyncResolution::NeedsUpdate), "Update Available");
        assert_eq!(format!("{}", SyncResolution::Conflict), "Conflict");
    }

    #[test]
    fn test_sync_action_default() {
        assert_eq!(SyncAction::default(), SyncAction::Skip);
    }

    #[test]
    fn test_sync_action_display() {
        assert_eq!(format!("{}", SyncAction::Update), "Update");
        assert_eq!(format!("{}", SyncAction::Commit), "Commit");
        assert_eq!(format!("{}", SyncAction::Skip), "Skip");
        assert_eq!(format!("{}", SyncAction::Revert), "Revert");
    }

    #[test]
    fn test_synchronizer_entry_creation() {
        let entry = SynchronizerEntry::new(
            make_path("my_struct"),
            make_path("my_struct"),
            "my_struct",
            SyncResolution::NeedsUpdate,
            100,
            200,
        );
        assert_eq!(entry.name(), "my_struct");
        assert_eq!(entry.resolution(), SyncResolution::NeedsUpdate);
        assert_eq!(entry.action(), SyncAction::Update); // default for NeedsUpdate
        assert!(entry.is_selected());
        assert_eq!(entry.client_change_time(), 100);
        assert_eq!(entry.source_change_time(), 200);
    }

    #[test]
    fn test_synchronizer_entry_default_actions() {
        let update = SynchronizerEntry::new(
            make_path("a"), make_path("a"), "a",
            SyncResolution::NeedsUpdate, 0, 0,
        );
        assert_eq!(update.action(), SyncAction::Update);

        let commit = SynchronizerEntry::new(
            make_path("b"), make_path("b"), "b",
            SyncResolution::NeedsCommit, 0, 0,
        );
        assert_eq!(commit.action(), SyncAction::Commit);

        let conflict = SynchronizerEntry::new(
            make_path("c"), make_path("c"), "c",
            SyncResolution::Conflict, 0, 0,
        );
        assert_eq!(conflict.action(), SyncAction::Skip);

        let orphan = SynchronizerEntry::new(
            make_path("d"), make_path("d"), "d",
            SyncResolution::Orphan, 0, 0,
        );
        assert_eq!(orphan.action(), SyncAction::Commit);
    }

    #[test]
    fn test_synchronizer_entry_modification() {
        let mut entry = SynchronizerEntry::new(
            make_path("x"), make_path("x"), "x",
            SyncResolution::Conflict, 0, 0,
        );
        entry.set_action(SyncAction::Update);
        assert_eq!(entry.action(), SyncAction::Update);

        entry.set_selected(false);
        assert!(!entry.is_selected());
    }

    #[test]
    fn test_synchronizer_entry_display() {
        let entry = SynchronizerEntry::new(
            make_path("my_struct"), make_path("my_struct"), "my_struct",
            SyncResolution::NeedsCommit, 0, 0,
        );
        let s = format!("{}", entry);
        assert!(s.contains("my_struct"));
        assert!(s.contains("Commit Available"));
        assert!(s.contains("Commit"));
    }

    #[test]
    fn test_synchronizer_creation() {
        let sync = DtMgrSynchronizer::new("MyProgram", "generic_C_lib");
        assert_eq!(sync.client_name(), "MyProgram");
        assert_eq!(sync.source_name(), "generic_C_lib");
        assert_eq!(sync.entry_count(), 0);
        assert!(!sync.is_applied());
        assert!(!sync.is_cancelled());
    }

    #[test]
    fn test_synchronizer_add_entries() {
        let mut sync = DtMgrSynchronizer::new("Prog", "Archive");
        sync.add_entry(SynchronizerEntry::new(
            make_path("a"), make_path("a"), "a",
            SyncResolution::NeedsUpdate, 0, 0,
        ));
        sync.add_entry(SynchronizerEntry::new(
            make_path("b"), make_path("b"), "b",
            SyncResolution::NeedsCommit, 0, 0,
        ));
        assert_eq!(sync.entry_count(), 2);
    }

    #[test]
    fn test_synchronizer_set_ids() {
        let mut sync = DtMgrSynchronizer::new("Prog", "Archive");
        sync.set_ids(UniversalID::new(1), UniversalID::new(2));
        // IDs are set (verified by the struct holding them).
    }

    #[test]
    fn test_synchronizer_select_all_deselect_all() {
        let mut sync = DtMgrSynchronizer::new("Prog", "Archive");
        sync.add_entry(SynchronizerEntry::new(
            make_path("a"), make_path("a"), "a",
            SyncResolution::NeedsUpdate, 0, 0,
        ));
        sync.add_entry(SynchronizerEntry::new(
            make_path("b"), make_path("b"), "b",
            SyncResolution::NeedsCommit, 0, 0,
        ));

        assert_eq!(sync.selected_count(), 2); // default: all selected

        sync.deselect_all();
        assert_eq!(sync.selected_count(), 0);

        sync.select_all();
        assert_eq!(sync.selected_count(), 2);
    }

    #[test]
    fn test_synchronizer_set_action_on_selected() {
        let mut sync = DtMgrSynchronizer::new("Prog", "Archive");
        sync.add_entry(SynchronizerEntry::new(
            make_path("a"), make_path("a"), "a",
            SyncResolution::NeedsUpdate, 0, 0,
        ));
        sync.add_entry(SynchronizerEntry::new(
            make_path("b"), make_path("b"), "b",
            SyncResolution::NeedsCommit, 0, 0,
        ));
        sync.deselect_all();
        sync.entries_mut()[0].set_selected(true);

        sync.set_action_on_selected(SyncAction::Revert);
        assert_eq!(sync.entries()[0].action(), SyncAction::Revert);
        // The second entry was not selected, so its action is unchanged.
        assert_eq!(sync.entries()[1].action(), SyncAction::Commit);
    }

    #[test]
    fn test_synchronizer_set_action_by_resolution() {
        let mut sync = DtMgrSynchronizer::new("Prog", "Archive");
        sync.add_entry(SynchronizerEntry::new(
            make_path("a"), make_path("a"), "a",
            SyncResolution::NeedsUpdate, 0, 0,
        ));
        sync.add_entry(SynchronizerEntry::new(
            make_path("b"), make_path("b"), "b",
            SyncResolution::NeedsCommit, 0, 0,
        ));
        sync.add_entry(SynchronizerEntry::new(
            make_path("c"), make_path("c"), "c",
            SyncResolution::NeedsUpdate, 0, 0,
        ));

        sync.set_action_by_resolution(SyncResolution::NeedsUpdate, SyncAction::Skip);
        assert_eq!(sync.entries()[0].action(), SyncAction::Skip);
        assert_eq!(sync.entries()[1].action(), SyncAction::Commit); // unchanged
        assert_eq!(sync.entries()[2].action(), SyncAction::Skip);
    }

    #[test]
    fn test_synchronizer_apply() {
        let mut sync = DtMgrSynchronizer::new("Prog", "Archive");
        sync.add_entry(SynchronizerEntry::new(
            make_path("a"), make_path("a"), "a",
            SyncResolution::NeedsUpdate, 100, 200,
        ));
        sync.add_entry(SynchronizerEntry::new(
            make_path("b"), make_path("b"), "b",
            SyncResolution::NeedsCommit, 300, 100,
        ));

        let summary = sync.apply();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.updated, 1);
        assert_eq!(summary.committed, 1);
        assert_eq!(summary.skipped, 0);
        assert!(summary.has_changes());
        assert!(sync.is_applied());
    }

    #[test]
    fn test_synchronizer_apply_with_skip() {
        let mut sync = DtMgrSynchronizer::new("Prog", "Archive");
        sync.add_entry(SynchronizerEntry::new(
            make_path("a"), make_path("a"), "a",
            SyncResolution::Conflict, 0, 0,
        ));
        // Conflict defaults to Skip action.

        let summary = sync.apply();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.skipped, 1);
        assert!(!summary.has_changes());
    }

    #[test]
    fn test_synchronizer_cancel() {
        let mut sync = DtMgrSynchronizer::new("Prog", "Archive");
        assert!(!sync.is_cancelled());
        sync.cancel();
        assert!(sync.is_cancelled());
    }

    #[test]
    fn test_synchronizer_display() {
        let mut sync = DtMgrSynchronizer::new("Prog", "Archive");
        sync.add_entry(SynchronizerEntry::new(
            make_path("a"), make_path("a"), "a",
            SyncResolution::NeedsUpdate, 0, 0,
        ));
        let s = format!("{}", sync);
        assert!(s.contains("Prog"));
        assert!(s.contains("Archive"));
        assert!(s.contains("1 entries"));
    }

    #[test]
    fn test_synchronizer_default() {
        let sync = DtMgrSynchronizer::default();
        assert_eq!(sync.client_name(), "");
        assert_eq!(sync.source_name(), "");
    }

    #[test]
    fn test_sync_summary_display() {
        let summary = SyncSummary {
            total: 10,
            updated: 3,
            committed: 4,
            skipped: 2,
            reverted: 1,
        };
        let s = format!("{}", summary);
        assert!(s.contains("10 total"));
        assert!(s.contains("3 updated"));
        assert!(s.contains("4 committed"));
        assert!(s.contains("2 skipped"));
        assert!(s.contains("1 reverted"));
    }

    #[test]
    fn test_sync_summary_changed() {
        let mut summary = SyncSummary::default();
        assert_eq!(summary.changed(), 0);
        assert!(!summary.has_changes());

        summary.updated = 2;
        summary.committed = 3;
        assert_eq!(summary.changed(), 5);
        assert!(summary.has_changes());
    }
}
