//! Concrete association action implementations.
//!
//! Ported from individual action classes in
//! `ghidra.app.plugin.core.datamgr.actions.associate`:
//!
//! - [`AssociateDataTypeAction`] -- create a new association between a program
//!   type and an archive type
//! - [`CommitAction`] -- commit local changes back to the source archive
//! - [`CommitSingleDataTypeAction`] -- commit a single data type to the archive
//! - [`RevertAction`] -- discard local changes and restore the archive version
//! - [`RevertDataTypeAction`] -- revert a single data type to the archive version
//! - [`UpdateAction`] -- pull archive changes into the program
//! - [`UpdateSingleDataTypeAction`] -- update a single data type from the archive
//! - [`DisassociateAction`] -- sever the link between program and archive types
//! - [`DisassociateDataTypeAction`] -- disassociate a single data type
//! - [`SyncRefreshAction`] -- refresh sync state for all associations
//!
//! These actions operate on [`DataTypeSyncInfo`](super::sync::DataTypeSyncInfo)
//! entries and the [`DataTypeSynchronizer`](super::sync::DataTypeSynchronizer).

use serde::{Deserialize, Serialize};

use super::sync::DataTypeSyncState;

// ---------------------------------------------------------------------------
// SyncAction -- base trait for sync operations
// ---------------------------------------------------------------------------

/// Trait implemented by all sync actions (commit, revert, update, disassociate).
///
/// Ported from the Java `SyncAction` abstract class.
pub trait SyncAction {
    /// The display name of this action.
    fn action_name(&self) -> &str;

    /// The menu ordering (lower numbers appear first).
    fn menu_order(&self) -> i32;

    /// The help topic for this action.
    fn help_topic(&self) -> &str;

    /// Whether this action is appropriate for the given sync state.
    fn is_appropriate_for_state(&self, state: DataTypeSyncState) -> bool;

    /// Whether the item should be pre-selected in the sync dialog.
    fn is_preselected(&self, state: DataTypeSyncState) -> bool;

    /// The human-readable operation name (e.g., "Commit", "Update").
    fn operation_name(&self) -> &str;

    /// Whether the source archive must be open for editing to perform
    /// this action.
    fn requires_archive_open_for_editing(&self) -> bool;

    /// Build the title for the sync dialog.
    fn title(&self, source_name: &str, client_name: &str) -> String;

    /// Build the confirmation message shown before applying the action.
    fn confirmation_message(&self, item_count: usize) -> String;
}

// ---------------------------------------------------------------------------
// AssociateDataTypeAction
// ---------------------------------------------------------------------------

/// Action to create a new association between a program data type and a
/// source archive data type.
///
/// When a user wants to track that a local type originally came from
/// (or should be linked to) an archive type, this action creates the
/// tracking association.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.AssociateDataTypeAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociateDataTypeAction {
    /// The program data type path.
    pub program_type_path: String,
    /// The archive data type path.
    pub archive_type_path: String,
    /// The source archive name.
    pub source_archive_name: String,
}

impl AssociateDataTypeAction {
    /// Create a new associate action.
    pub fn new(
        program_type_path: impl Into<String>,
        archive_type_path: impl Into<String>,
        source_archive_name: impl Into<String>,
    ) -> Self {
        Self {
            program_type_path: program_type_path.into(),
            archive_type_path: archive_type_path.into(),
            source_archive_name: source_archive_name.into(),
        }
    }

    /// Whether this action can be performed (both paths non-empty).
    pub fn can_execute(&self) -> bool {
        !self.program_type_path.is_empty() && !self.archive_type_path.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CommitAction
// ---------------------------------------------------------------------------

/// Action to commit local data type changes back to the source archive.
///
/// This pushes program-side modifications (added/changed types) to the
/// source archive so other programs linked to that archive can see the
/// changes.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.CommitAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitAction {
    /// The source archive name to commit to.
    pub source_archive_name: String,
    /// The client (program) archive name.
    pub client_name: String,
}

impl CommitAction {
    /// Create a new commit action.
    pub fn new(
        source_archive_name: impl Into<String>,
        client_name: impl Into<String>,
    ) -> Self {
        Self {
            source_archive_name: source_archive_name.into(),
            client_name: client_name.into(),
        }
    }
}

impl SyncAction for CommitAction {
    fn action_name(&self) -> &str {
        "Commit Changes To Archive"
    }

    fn menu_order(&self) -> i32 {
        2
    }

    fn help_topic(&self) -> &str {
        "Commit_Data_Types"
    }

    fn is_appropriate_for_state(&self, state: DataTypeSyncState) -> bool {
        matches!(
            state,
            DataTypeSyncState::Commit | DataTypeSyncState::Conflict | DataTypeSyncState::Orphan
        )
    }

    fn is_preselected(&self, state: DataTypeSyncState) -> bool {
        state == DataTypeSyncState::Commit
    }

    fn operation_name(&self) -> &str {
        "Commit"
    }

    fn requires_archive_open_for_editing(&self) -> bool {
        true
    }

    fn title(&self, source_name: &str, client_name: &str) -> String {
        format!(
            "Commit Datatype Changes From \"{}\" To Archive \"{}\"",
            client_name, source_name
        )
    }

    fn confirmation_message(&self, item_count: usize) -> String {
        format!(
            "Are you sure you want to COMMIT {} datatype(s)?",
            item_count
        )
    }
}

// ---------------------------------------------------------------------------
// CommitSingleDataTypeAction
// ---------------------------------------------------------------------------

/// Action to commit a single data type to the source archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.CommitSingleDataTypeAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitSingleDataTypeAction {
    /// The data type path to commit.
    pub data_type_path: String,
    /// The source archive name.
    pub source_archive_name: String,
}

impl CommitSingleDataTypeAction {
    /// Create a new single-commit action.
    pub fn new(
        data_type_path: impl Into<String>,
        source_archive_name: impl Into<String>,
    ) -> Self {
        Self {
            data_type_path: data_type_path.into(),
            source_archive_name: source_archive_name.into(),
        }
    }
}

impl SyncAction for CommitSingleDataTypeAction {
    fn action_name(&self) -> &str {
        "Commit Single Data Type"
    }

    fn menu_order(&self) -> i32 {
        3
    }

    fn help_topic(&self) -> &str {
        "Commit_Data_Types"
    }

    fn is_appropriate_for_state(&self, state: DataTypeSyncState) -> bool {
        matches!(state, DataTypeSyncState::Commit | DataTypeSyncState::Conflict)
    }

    fn is_preselected(&self, state: DataTypeSyncState) -> bool {
        state == DataTypeSyncState::Commit
    }

    fn operation_name(&self) -> &str {
        "Commit"
    }

    fn requires_archive_open_for_editing(&self) -> bool {
        true
    }

    fn title(&self, source_name: &str, _client_name: &str) -> String {
        format!("Commit \"{}\" To Archive \"{}\"", self.data_type_path, source_name)
    }

    fn confirmation_message(&self, _item_count: usize) -> String {
        format!(
            "Are you sure you want to COMMIT \"{}\"?",
            self.data_type_path
        )
    }
}

// ---------------------------------------------------------------------------
// RevertAction
// ---------------------------------------------------------------------------

/// Action to discard local changes and restore the archive version of
/// all selected data types.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.RevertAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevertAction {
    /// The source archive name.
    pub source_archive_name: String,
    /// The client (program) name.
    pub client_name: String,
}

impl RevertAction {
    /// Create a new revert action.
    pub fn new(
        source_archive_name: impl Into<String>,
        client_name: impl Into<String>,
    ) -> Self {
        Self {
            source_archive_name: source_archive_name.into(),
            client_name: client_name.into(),
        }
    }
}

impl SyncAction for RevertAction {
    fn action_name(&self) -> &str {
        "Revert Data Types"
    }

    fn menu_order(&self) -> i32 {
        4
    }

    fn help_topic(&self) -> &str {
        "Revert_Data_Types"
    }

    fn is_appropriate_for_state(&self, state: DataTypeSyncState) -> bool {
        matches!(
            state,
            DataTypeSyncState::Commit | DataTypeSyncState::Conflict | DataTypeSyncState::Orphan
        )
    }

    fn is_preselected(&self, state: DataTypeSyncState) -> bool {
        state == DataTypeSyncState::Commit
    }

    fn operation_name(&self) -> &str {
        "Revert"
    }

    fn requires_archive_open_for_editing(&self) -> bool {
        false
    }

    fn title(&self, source_name: &str, client_name: &str) -> String {
        format!(
            "Revert Datatype Changes From \"{}\" To Match Archive \"{}\"",
            client_name, source_name
        )
    }

    fn confirmation_message(&self, item_count: usize) -> String {
        format!(
            "Are you sure you want to REVERT {} datatype(s)?",
            item_count
        )
    }
}

// ---------------------------------------------------------------------------
// RevertDataTypeAction
// ---------------------------------------------------------------------------

/// Action to revert a single data type to its archive version.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.RevertDataTypeAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevertDataTypeAction {
    /// The data type path to revert.
    pub data_type_path: String,
    /// The source archive name.
    pub source_archive_name: String,
}

impl RevertDataTypeAction {
    /// Create a new single-revert action.
    pub fn new(
        data_type_path: impl Into<String>,
        source_archive_name: impl Into<String>,
    ) -> Self {
        Self {
            data_type_path: data_type_path.into(),
            source_archive_name: source_archive_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// UpdateAction
// ---------------------------------------------------------------------------

/// Action to pull archive changes into the program for all selected
/// data types.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.UpdateAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAction {
    /// The source archive name.
    pub source_archive_name: String,
    /// The client (program) name.
    pub client_name: String,
}

impl UpdateAction {
    /// Create a new update action.
    pub fn new(
        source_archive_name: impl Into<String>,
        client_name: impl Into<String>,
    ) -> Self {
        Self {
            source_archive_name: source_archive_name.into(),
            client_name: client_name.into(),
        }
    }
}

impl SyncAction for UpdateAction {
    fn action_name(&self) -> &str {
        "Update Data Types From Archive"
    }

    fn menu_order(&self) -> i32 {
        1
    }

    fn help_topic(&self) -> &str {
        "Update_Data_Types"
    }

    fn is_appropriate_for_state(&self, state: DataTypeSyncState) -> bool {
        matches!(
            state,
            DataTypeSyncState::Update | DataTypeSyncState::Conflict | DataTypeSyncState::Orphan
        )
    }

    fn is_preselected(&self, state: DataTypeSyncState) -> bool {
        state == DataTypeSyncState::Update
    }

    fn operation_name(&self) -> &str {
        "Update"
    }

    fn requires_archive_open_for_editing(&self) -> bool {
        false
    }

    fn title(&self, source_name: &str, client_name: &str) -> String {
        format!(
            "Update Datatype Changes From Archive \"{}\" Into \"{}\"",
            source_name, client_name
        )
    }

    fn confirmation_message(&self, item_count: usize) -> String {
        format!(
            "Are you sure you want to UPDATE {} datatype(s)?",
            item_count
        )
    }
}

// ---------------------------------------------------------------------------
// UpdateSingleDataTypeAction
// ---------------------------------------------------------------------------

/// Action to update a single data type from the archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.UpdateSingleDataTypeAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSingleDataTypeAction {
    /// The data type path to update.
    pub data_type_path: String,
    /// The source archive name.
    pub source_archive_name: String,
}

impl UpdateSingleDataTypeAction {
    /// Create a new single-update action.
    pub fn new(
        data_type_path: impl Into<String>,
        source_archive_name: impl Into<String>,
    ) -> Self {
        Self {
            data_type_path: data_type_path.into(),
            source_archive_name: source_archive_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// DisassociateAction
// ---------------------------------------------------------------------------

/// Action to sever the link between program data types and their source
/// archive for all selected associations.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.DisassociateAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassociateAction {
    /// The source archive name.
    pub source_archive_name: String,
    /// The client (program) name.
    pub client_name: String,
}

impl DisassociateAction {
    /// Create a new disassociate action.
    pub fn new(
        source_archive_name: impl Into<String>,
        client_name: impl Into<String>,
    ) -> Self {
        Self {
            source_archive_name: source_archive_name.into(),
            client_name: client_name.into(),
        }
    }
}

impl SyncAction for DisassociateAction {
    fn action_name(&self) -> &str {
        "Disassociate Data Types"
    }

    fn menu_order(&self) -> i32 {
        5
    }

    fn help_topic(&self) -> &str {
        "Disassociate_Data_Types"
    }

    fn is_appropriate_for_state(&self, state: DataTypeSyncState) -> bool {
        !matches!(state, DataTypeSyncState::Unknown)
    }

    fn is_preselected(&self, _state: DataTypeSyncState) -> bool {
        false
    }

    fn operation_name(&self) -> &str {
        "Disassociate"
    }

    fn requires_archive_open_for_editing(&self) -> bool {
        false
    }

    fn title(&self, source_name: &str, client_name: &str) -> String {
        format!(
            "Disassociate Datatypes Between \"{}\" And \"{}\"",
            client_name, source_name
        )
    }

    fn confirmation_message(&self, item_count: usize) -> String {
        format!(
            "Are you sure you want to DISASSOCIATE {} datatype(s)?",
            item_count
        )
    }
}

// ---------------------------------------------------------------------------
// DisassociateDataTypeAction
// ---------------------------------------------------------------------------

/// Action to disassociate a single data type.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.DisassociateDataTypeAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassociateDataTypeAction {
    /// The data type path to disassociate.
    pub data_type_path: String,
    /// The source archive name.
    pub source_archive_name: String,
}

impl DisassociateDataTypeAction {
    /// Create a new single-disassociate action.
    pub fn new(
        data_type_path: impl Into<String>,
        source_archive_name: impl Into<String>,
    ) -> Self {
        Self {
            data_type_path: data_type_path.into(),
            source_archive_name: source_archive_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// SyncRefreshAction
// ---------------------------------------------------------------------------

/// Action to refresh the sync state for all associations between a
/// program and its source archives.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate.SyncRefreshAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRefreshAction {
    /// The program name whose associations should be refreshed.
    pub program_name: String,
}

impl SyncRefreshAction {
    /// Create a new sync refresh action.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            program_name: program_name.into(),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_associate_data_type_action() {
        let action = AssociateDataTypeAction::new("/int", "/int", "StandardC");
        assert!(action.can_execute());
        assert_eq!(action.program_type_path, "/int");
        assert_eq!(action.archive_type_path, "/int");
        assert_eq!(action.source_archive_name, "StandardC");
    }

    #[test]
    fn test_associate_data_type_action_empty() {
        let action = AssociateDataTypeAction::new("", "/int", "StandardC");
        assert!(!action.can_execute());
    }

    #[test]
    fn test_commit_action() {
        let action = CommitAction::new("archive", "program");
        assert_eq!(action.action_name(), "Commit Changes To Archive");
        assert_eq!(action.menu_order(), 2);
        assert_eq!(action.operation_name(), "Commit");
        assert!(action.requires_archive_open_for_editing());

        assert!(action.is_appropriate_for_state(DataTypeSyncState::Commit));
        assert!(action.is_appropriate_for_state(DataTypeSyncState::Conflict));
        assert!(action.is_appropriate_for_state(DataTypeSyncState::Orphan));
        assert!(!action.is_appropriate_for_state(DataTypeSyncState::Update));

        assert!(action.is_preselected(DataTypeSyncState::Commit));
        assert!(!action.is_preselected(DataTypeSyncState::Conflict));
    }

    #[test]
    fn test_commit_single_action() {
        let action = CommitSingleDataTypeAction::new("/int", "archive");
        assert_eq!(action.data_type_path, "/int");
        assert!(action.is_appropriate_for_state(DataTypeSyncState::Commit));
    }

    #[test]
    fn test_revert_action() {
        let action = RevertAction::new("archive", "program");
        assert_eq!(action.action_name(), "Revert Data Types");
        assert_eq!(action.operation_name(), "Revert");
        assert!(!action.requires_archive_open_for_editing());

        assert!(action.is_appropriate_for_state(DataTypeSyncState::Commit));
        assert!(action.is_appropriate_for_state(DataTypeSyncState::Conflict));
        assert!(action.is_appropriate_for_state(DataTypeSyncState::Orphan));
        assert!(!action.is_appropriate_for_state(DataTypeSyncState::Update));

        assert!(action.is_preselected(DataTypeSyncState::Commit));
    }

    #[test]
    fn test_revert_data_type_action() {
        let action = RevertDataTypeAction::new("/int", "archive");
        assert_eq!(action.data_type_path, "/int");
        assert_eq!(action.source_archive_name, "archive");
    }

    #[test]
    fn test_update_action() {
        let action = UpdateAction::new("archive", "program");
        assert_eq!(action.action_name(), "Update Data Types From Archive");
        assert_eq!(action.menu_order(), 1);
        assert!(!action.requires_archive_open_for_editing());

        assert!(action.is_appropriate_for_state(DataTypeSyncState::Update));
        assert!(action.is_appropriate_for_state(DataTypeSyncState::Conflict));
        assert!(!action.is_appropriate_for_state(DataTypeSyncState::Commit));

        assert!(action.is_preselected(DataTypeSyncState::Update));
    }

    #[test]
    fn test_update_single_data_type_action() {
        let action = UpdateSingleDataTypeAction::new("/int", "archive");
        assert_eq!(action.data_type_path, "/int");
    }

    #[test]
    fn test_disassociate_action() {
        let action = DisassociateAction::new("archive", "program");
        assert_eq!(action.action_name(), "Disassociate Data Types");
        assert_eq!(action.menu_order(), 5);
        assert!(!action.requires_archive_open_for_editing());

        // Should be appropriate for all states except Unknown
        assert!(action.is_appropriate_for_state(DataTypeSyncState::InSync));
        assert!(action.is_appropriate_for_state(DataTypeSyncState::Commit));
        assert!(!action.is_appropriate_for_state(DataTypeSyncState::Unknown));
    }

    #[test]
    fn test_disassociate_data_type_action() {
        let action = DisassociateDataTypeAction::new("/int", "archive");
        assert_eq!(action.data_type_path, "/int");
    }

    #[test]
    fn test_sync_refresh_action() {
        let action = SyncRefreshAction::new("my_program");
        assert_eq!(action.program_name, "my_program");
    }

    #[test]
    fn test_commit_confirmation_message() {
        let action = CommitAction::new("arc", "prog");
        let msg = action.confirmation_message(5);
        assert!(msg.contains("COMMIT"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn test_revert_title() {
        let action = RevertAction::new("arc", "prog");
        let title = action.title("arc", "prog");
        assert!(title.contains("Revert"));
        assert!(title.contains("arc"));
        assert!(title.contains("prog"));
    }

    #[test]
    fn test_update_title() {
        let action = UpdateAction::new("arc", "prog");
        let title = action.title("arc", "prog");
        assert!(title.contains("Update"));
    }

    #[test]
    fn test_disassociate_confirmation_message() {
        let action = DisassociateAction::new("arc", "prog");
        let msg = action.confirmation_message(3);
        assert!(msg.contains("DISASSOCIATE"));
        assert!(msg.contains("3"));
    }
}
