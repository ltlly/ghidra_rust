//! Archive management actions for the data type manager.
//!
//! Ported from individual action classes in
//! `ghidra.app.plugin.core.datamgr.actions`:
//!
//! - [`SaveAsAction`] -- save an archive to a new file path
//! - [`ExpandAllAction`] -- recursively expand selected tree nodes
//! - [`CollapseAllArchivesAction`] -- collapse all archive nodes
//! - [`ClearCutAction`] -- cancel a pending cut operation
//! - [`CreateArchiveAction`] -- create a new data type archive file
//! - [`CreateProjectArchiveAction`] -- create a new project-level archive
//! - [`DeleteArchiveAction`] -- delete an archive file
//! - [`OpenProjectArchiveAction`] -- open a project archive
//! - [`EditArchivePathAction`] -- edit the file path for an archive
//! - [`UnlockArchiveAction`] -- unlock a locked archive for editing
//! - [`ClearArchiveArchitectureAction`] -- clear the architecture association
//! - [`SetArchiveArchitectureAction`] -- set the architecture for an archive
//! - [`RecentlyOpenedArchiveAction`] -- re-open a recently used archive
//! - [`RemoveInvalidArchiveFromProgramAction`] -- remove a broken archive link
//! - [`UpdateSourceArchiveNamesAction`] -- update source archive display names
//! - [`PreviewWindowAction`] -- show a preview of the selected data type
//! - [`IncludeDataTypesInFilterAction`] -- toggle data types in the tree filter
//! - [`AnnotationHandlerDialog`] -- dialog for annotation handling settings
//! - [`ConflictHandlerModesAction`] -- set conflict resolution mode for merges
//! - [`DataTypeMergeConfirmationDialog`] -- confirmation before merge
//! - [`DataTypeMergeErrorDialog`] -- display merge errors
//! - [`AbstractUndoRedoArchiveTransactionAction`] -- base for undo/redo actions

use serde::{Deserialize, Serialize};

use super::archive_ops::{ArchiveOperation, ConflictHandlerMode};

// ---------------------------------------------------------------------------
// SaveAsAction
// ---------------------------------------------------------------------------

/// Action to save a data type archive under a new file path.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.SaveAsAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveAsAction {
    /// The name of the archive to save.
    pub archive_name: String,
    /// The new file path for the archive.
    pub new_path: String,
}

impl SaveAsAction {
    /// Create a new "Save As" action.
    pub fn new(archive_name: impl Into<String>, new_path: impl Into<String>) -> Self {
        Self {
            archive_name: archive_name.into(),
            new_path: new_path.into(),
        }
    }

    /// Whether this action is enabled for the given archive kind.
    pub fn is_enabled_for(&self, archive_kind: &str) -> bool {
        matches!(archive_kind, "File" | "Project")
    }

    /// Build the archive operation for this action.
    pub fn to_operation(&self) -> ArchiveOperation {
        ArchiveOperation::SaveAs {
            name: self.archive_name.clone(),
            new_path: self.new_path.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// ExpandAllAction
// ---------------------------------------------------------------------------

/// Action to recursively expand all selected tree nodes.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.ExpandAllAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpandAllAction;

impl ExpandAllAction {
    /// Create a new expand-all action.
    pub fn new() -> Self {
        Self
    }

    /// Whether this action is enabled (at least one non-leaf node selected).
    pub fn is_enabled(&self, selected_nodes: &[TreeNodeInfo]) -> bool {
        !selected_nodes.is_empty() && selected_nodes.iter().all(|n| !n.is_leaf)
    }

    /// Returns the list of node IDs to expand.
    pub fn nodes_to_expand(&self, selected_nodes: &[TreeNodeInfo]) -> Vec<u64> {
        selected_nodes
            .iter()
            .filter(|n| !n.is_leaf)
            .map(|n| n.id)
            .collect()
    }
}

impl Default for ExpandAllAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CollapseAllArchivesAction
// ---------------------------------------------------------------------------

/// Action to collapse all expanded archive nodes.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.CollapseAllArchivesAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollapseAllArchivesAction;

impl CollapseAllArchivesAction {
    /// Create a new collapse-all action.
    pub fn new() -> Self {
        Self
    }

    /// Always enabled when the tree has at least one expanded archive.
    pub fn is_enabled(&self, has_expanded_archives: bool) -> bool {
        has_expanded_archives
    }
}

impl Default for CollapseAllArchivesAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ClearCutAction
// ---------------------------------------------------------------------------

/// Action to cancel a pending cut (i.e., clear the clipboard).
///
/// Bound to the Escape key.  Only valid when the clipboard contains
/// cut nodes from the data type manager tree.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.ClearCutAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearCutAction;

impl ClearCutAction {
    /// Create a new clear-cut action.
    pub fn new() -> Self {
        Self
    }

    /// Whether the action is valid (there are cut nodes on the clipboard).
    pub fn is_valid(&self, has_clipboard_nodes: bool) -> bool {
        has_clipboard_nodes
    }

    /// Execute the action: clear the clipboard.
    pub fn execute(&self, clipboard_nodes_are_cut: bool) -> bool {
        // Returns true if the clipboard was cleared
        clipboard_nodes_are_cut
    }
}

impl Default for ClearCutAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateArchiveAction
// ---------------------------------------------------------------------------

/// Action to create a new file-backed data type archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.CreateArchiveAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateArchiveAction {
    /// The file path for the new archive.
    pub path: String,
    /// Whether to open the archive after creation.
    pub open_after_create: bool,
}

impl CreateArchiveAction {
    /// Create a new archive creation action.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            open_after_create: true,
        }
    }

    /// Whether to open the archive after creation.
    pub fn set_open_after_create(&mut self, open: bool) {
        self.open_after_create = open;
    }

    /// Build the archive operation.
    pub fn to_operation(&self) -> ArchiveOperation {
        ArchiveOperation::CreateFile {
            path: self.path.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// CreateProjectArchiveAction
// ---------------------------------------------------------------------------

/// Action to create a new project-level data type archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.CreateProjectArchiveAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProjectArchiveAction {
    /// The name for the new project archive.
    pub name: String,
}

impl CreateProjectArchiveAction {
    /// Create a new project archive creation action.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Build the archive operation.
    pub fn to_operation(&self) -> ArchiveOperation {
        ArchiveOperation::CreateProject {
            name: self.name.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// DeleteArchiveAction
// ---------------------------------------------------------------------------

/// Action to delete a data type archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.DeleteArchiveAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteArchiveAction {
    /// The name of the archive to delete.
    pub archive_name: String,
    /// Whether to also delete the backing file from disk.
    pub delete_file: bool,
}

impl DeleteArchiveAction {
    /// Create a new archive deletion action.
    pub fn new(archive_name: impl Into<String>) -> Self {
        Self {
            archive_name: archive_name.into(),
            delete_file: false,
        }
    }

    /// Whether this action requires user confirmation.
    pub fn requires_confirmation(&self) -> bool {
        true
    }

    /// Build the archive operation.
    pub fn to_operation(&self) -> ArchiveOperation {
        ArchiveOperation::Delete {
            name: self.archive_name.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// OpenProjectArchiveAction
// ---------------------------------------------------------------------------

/// Action to open a project-level data type archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.OpenProjectArchiveAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenProjectArchiveAction {
    /// The name of the project archive to open.
    pub archive_name: String,
}

impl OpenProjectArchiveAction {
    /// Create a new open-project-archive action.
    pub fn new(archive_name: impl Into<String>) -> Self {
        Self {
            archive_name: archive_name.into(),
        }
    }

    /// Build the archive operation.
    pub fn to_operation(&self) -> ArchiveOperation {
        ArchiveOperation::OpenProject {
            name: self.archive_name.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// EditArchivePathAction
// ---------------------------------------------------------------------------

/// Action to edit the file path associated with an archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.EditArchivePathAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditArchivePathAction {
    /// The current archive name.
    pub archive_name: String,
    /// The new file path.
    pub new_path: String,
}

impl EditArchivePathAction {
    /// Create a new edit-archive-path action.
    pub fn new(archive_name: impl Into<String>, new_path: impl Into<String>) -> Self {
        Self {
            archive_name: archive_name.into(),
            new_path: new_path.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// UnlockArchiveAction
// ---------------------------------------------------------------------------

/// Action to unlock a locked data type archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.UnlockArchiveAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockArchiveAction {
    /// The name of the archive to unlock.
    pub archive_name: String,
    /// Whether to save changes before unlocking.
    pub save_before_unlock: bool,
}

impl UnlockArchiveAction {
    /// Create a new unlock action.
    pub fn new(archive_name: impl Into<String>) -> Self {
        Self {
            archive_name: archive_name.into(),
            save_before_unlock: true,
        }
    }

    /// Build the archive operation.
    pub fn to_operation(&self) -> ArchiveOperation {
        ArchiveOperation::Unlock {
            name: self.archive_name.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// ClearArchiveArchitectureAction
// ---------------------------------------------------------------------------

/// Action to clear the architecture association from an archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.ClearArchiveArchitectureAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearArchiveArchitectureAction {
    /// The name of the archive.
    pub archive_name: String,
}

impl ClearArchiveArchitectureAction {
    /// Create a new clear-architecture action.
    pub fn new(archive_name: impl Into<String>) -> Self {
        Self {
            archive_name: archive_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// SetArchiveArchitectureAction
// ---------------------------------------------------------------------------

/// Action to set the architecture association for an archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.SetArchiveArchitectureAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetArchiveArchitectureAction {
    /// The name of the archive.
    pub archive_name: String,
    /// The language ID to associate.
    pub language_id: String,
    /// The compiler spec ID to associate.
    pub compiler_spec_id: String,
}

impl SetArchiveArchitectureAction {
    /// Create a new set-architecture action.
    pub fn new(
        archive_name: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            archive_name: archive_name.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// RecentlyOpenedArchiveAction
// ---------------------------------------------------------------------------

/// Action to re-open a recently used archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.RecentlyOpenedArchiveAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentlyOpenedArchiveAction {
    /// The file path of the recently opened archive.
    pub path: String,
    /// Display name for the menu item.
    pub display_name: String,
}

impl RecentlyOpenedArchiveAction {
    /// Create a new recently-opened action.
    pub fn new(path: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            display_name: display_name.into(),
        }
    }

    /// Build the archive operation.
    pub fn to_operation(&self) -> ArchiveOperation {
        ArchiveOperation::OpenFile {
            path: self.path.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// RemoveInvalidArchiveFromProgramAction
// ---------------------------------------------------------------------------

/// Action to remove a broken/invalid archive link from a program.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.RemoveInvalidArchiveFromProgramAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveInvalidArchiveFromProgramAction {
    /// The name of the invalid archive to remove.
    pub archive_name: String,
    /// The name of the program from which to remove the link.
    pub program_name: String,
}

impl RemoveInvalidArchiveFromProgramAction {
    /// Create a new remove-invalid action.
    pub fn new(archive_name: impl Into<String>, program_name: impl Into<String>) -> Self {
        Self {
            archive_name: archive_name.into(),
            program_name: program_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// UpdateSourceArchiveNamesAction
// ---------------------------------------------------------------------------

/// Action to update display names for source archives in a program.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.UpdateSourceArchiveNamesAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSourceArchiveNamesAction {
    /// The program name whose archive names should be updated.
    pub program_name: String,
}

impl UpdateSourceArchiveNamesAction {
    /// Create a new update-names action.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            program_name: program_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// PreviewWindowAction
// ---------------------------------------------------------------------------

/// Action to show a preview of the selected data type.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.PreviewWindowAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewWindowAction {
    /// The data type path to preview.
    pub data_type_path: String,
}

impl PreviewWindowAction {
    /// Create a new preview action.
    pub fn new(data_type_path: impl Into<String>) -> Self {
        Self {
            data_type_path: data_type_path.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// IncludeDataTypesInFilterAction
// ---------------------------------------------------------------------------

/// Action to toggle whether data types are included in the tree filter.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.IncludeDataTypesInFilterAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludeDataTypesInFilterAction {
    /// Whether data types are currently included.
    pub include: bool,
}

impl IncludeDataTypesInFilterAction {
    /// Create a new filter toggle action.
    pub fn new(include: bool) -> Self {
        Self { include }
    }

    /// Toggle the current state.
    pub fn toggle(&mut self) {
        self.include = !self.include;
    }
}

// ---------------------------------------------------------------------------
// ConflictHandlerModesAction
// ---------------------------------------------------------------------------

/// Action to set the conflict resolution mode for archive merges.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.ConflictHandlerModesAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictHandlerModesAction {
    /// The selected conflict mode.
    pub mode: ConflictHandlerMode,
}

impl ConflictHandlerModesAction {
    /// Create a new conflict mode action with the given mode.
    pub fn new(mode: ConflictHandlerMode) -> Self {
        Self { mode }
    }

    /// Create with the default (ask user) mode.
    pub fn with_default_mode() -> Self {
        Self::new(ConflictHandlerMode::Default)
    }
}

impl Default for ConflictHandlerModesAction {
    fn default() -> Self {
        Self::with_default_mode()
    }
}

// ---------------------------------------------------------------------------
// DataTypeMergeConfirmationDialog
// ---------------------------------------------------------------------------

/// Confirmation dialog shown before merging data types.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.DataTypeMergeConfirmationDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeMergeConfirmationDialog {
    /// The message to display.
    pub message: String,
    /// The number of types that will be merged.
    pub type_count: usize,
    /// The source archive name.
    pub source_name: String,
    /// The target archive name.
    pub target_name: String,
    /// Whether the user confirmed the merge.
    pub confirmed: bool,
}

impl DataTypeMergeConfirmationDialog {
    /// Create a new merge confirmation dialog.
    pub fn new(
        source_name: impl Into<String>,
        target_name: impl Into<String>,
        type_count: usize,
    ) -> Self {
        let source = source_name.into();
        let target = target_name.into();
        Self {
            message: format!(
                "Merge {} data type(s) from \"{}\" into \"{}\"?",
                type_count, source, target
            ),
            type_count,
            source_name: source,
            target_name: target,
            confirmed: false,
        }
    }

    /// Confirm the merge.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Cancel the merge.
    pub fn cancel(&mut self) {
        self.confirmed = false;
    }
}

// ---------------------------------------------------------------------------
// DataTypeMergeErrorDialog
// ---------------------------------------------------------------------------

/// Error dialog displayed when a merge operation fails.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.DataTypeMergeErrorDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeMergeErrorDialog {
    /// The error title.
    pub title: String,
    /// The error message.
    pub message: String,
    /// Individual error details (type name -> error message).
    pub errors: Vec<(String, String)>,
}

impl DataTypeMergeErrorDialog {
    /// Create a new merge error dialog.
    pub fn new(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            errors: Vec::new(),
        }
    }

    /// Add an individual error detail.
    pub fn add_error(&mut self, type_name: impl Into<String>, error: impl Into<String>) {
        self.errors.push((type_name.into(), error.into()));
    }

    /// Whether there are any errors.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

// ---------------------------------------------------------------------------
// AbstractUndoRedoArchiveTransactionAction
// ---------------------------------------------------------------------------

/// Base action for undo/redo on archive transactions.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.AbstractUndoRedoArchiveTransactionAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoRedoArchiveTransactionAction {
    /// The archive name.
    pub archive_name: String,
    /// Whether this is an undo (true) or redo (false) action.
    pub is_undo: bool,
    /// The transaction ID to undo/redo (if known).
    pub transaction_id: Option<u64>,
}

impl UndoRedoArchiveTransactionAction {
    /// Create a new undo action.
    pub fn new_undo(archive_name: impl Into<String>) -> Self {
        Self {
            archive_name: archive_name.into(),
            is_undo: true,
            transaction_id: None,
        }
    }

    /// Create a new redo action.
    pub fn new_redo(archive_name: impl Into<String>) -> Self {
        Self {
            archive_name: archive_name.into(),
            is_undo: false,
            transaction_id: None,
        }
    }

    /// Set the transaction ID.
    pub fn with_transaction_id(mut self, id: u64) -> Self {
        self.transaction_id = Some(id);
        self
    }

    /// Build the archive operation.
    pub fn to_operation(&self) -> ArchiveOperation {
        if self.is_undo {
            ArchiveOperation::Undo {
                name: self.archive_name.clone(),
            }
        } else {
            ArchiveOperation::Redo {
                name: self.archive_name.clone(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AnnotationHandlerDialog
// ---------------------------------------------------------------------------

/// Dialog for configuring annotation handling during data type operations.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.AnnotationHandlerDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationHandlerDialog {
    /// Whether to preserve existing annotations.
    pub preserve_annotations: bool,
    /// Whether to strip annotations from imported types.
    pub strip_annotations: bool,
    /// Custom annotation prefix filter.
    pub prefix_filter: String,
}

impl AnnotationHandlerDialog {
    /// Create a new annotation handler dialog with defaults.
    pub fn new() -> Self {
        Self {
            preserve_annotations: true,
            strip_annotations: false,
            prefix_filter: String::new(),
        }
    }
}

impl Default for AnnotationHandlerDialog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AbstractDataTypeMergeDialog
// ---------------------------------------------------------------------------

/// Base dialog for data type merge operations.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.AbstractDataTypeMergeDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeMergeDialog {
    /// The source archive name.
    pub source_name: String,
    /// The target archive name.
    pub target_name: String,
    /// The conflict handler mode to use.
    pub conflict_mode: ConflictHandlerMode,
    /// The list of data types to merge.
    pub types_to_merge: Vec<String>,
    /// Whether the merge was confirmed.
    pub confirmed: bool,
}

impl DataTypeMergeDialog {
    /// Create a new merge dialog.
    pub fn new(
        source_name: impl Into<String>,
        target_name: impl Into<String>,
        conflict_mode: ConflictHandlerMode,
    ) -> Self {
        Self {
            source_name: source_name.into(),
            target_name: target_name.into(),
            conflict_mode,
            types_to_merge: Vec::new(),
            confirmed: false,
        }
    }

    /// Add a data type to the merge list.
    pub fn add_type(&mut self, type_name: impl Into<String>) {
        self.types_to_merge.push(type_name.into());
    }

    /// Confirm the merge.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Cancel the merge.
    pub fn cancel(&mut self) {
        self.confirmed = false;
    }
}

// ---------------------------------------------------------------------------
// AbstractFindReferencesToFieldAction
// ---------------------------------------------------------------------------

/// Base action for finding references to a field within a data type.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.AbstractFindReferencesToFieldAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReferencesToFieldAction {
    /// The data type path containing the field.
    pub data_type_path: String,
    /// The field name to search for.
    pub field_name: String,
    /// The field ordinal within the composite.
    pub field_ordinal: usize,
}

impl FindReferencesToFieldAction {
    /// Create a new field-reference search action.
    pub fn new(
        data_type_path: impl Into<String>,
        field_name: impl Into<String>,
        field_ordinal: usize,
    ) -> Self {
        Self {
            data_type_path: data_type_path.into(),
            field_name: field_name.into(),
            field_ordinal,
        }
    }
}

// ---------------------------------------------------------------------------
// AbstractTypeDefAction
// ---------------------------------------------------------------------------

/// Base action for creating type definitions (typedefs).
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.AbstractTypeDefAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDefAction {
    /// The name for the new typedef.
    pub typedef_name: String,
    /// The base data type to point to.
    pub base_type_path: String,
    /// The category path for the new typedef.
    pub category_path: String,
}

impl TypeDefAction {
    /// Create a new typedef action.
    pub fn new(
        typedef_name: impl Into<String>,
        base_type_path: impl Into<String>,
        category_path: impl Into<String>,
    ) -> Self {
        Self {
            typedef_name: typedef_name.into(),
            base_type_path: base_type_path.into(),
            category_path: category_path.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// CreateTypeDefDialog
// ---------------------------------------------------------------------------

/// Dialog for creating a new data type definition (typedef).
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.CreateTypeDefDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTypeDefDialog {
    /// The name for the new typedef.
    pub name: String,
    /// The base data type path.
    pub base_type_path: String,
    /// The category path.
    pub category_path: String,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl CreateTypeDefDialog {
    /// Create a new typedef dialog.
    pub fn new(base_type_path: impl Into<String>, category_path: impl Into<String>) -> Self {
        Self {
            name: String::new(),
            base_type_path: base_type_path.into(),
            category_path: category_path.into(),
            confirmed: false,
        }
    }

    /// Set the typedef name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        if !self.name.is_empty() {
            self.confirmed = true;
        }
    }
}

// ---------------------------------------------------------------------------
// CreateTypeDefFromDialogAction
// ---------------------------------------------------------------------------

/// Action to create a typedef from the dialog result.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.CreateTypeDefFromDialogAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTypeDefFromDialogAction {
    /// The dialog state.
    pub dialog: CreateTypeDefDialog,
}

impl CreateTypeDefFromDialogAction {
    /// Create a new action from a dialog.
    pub fn new(dialog: CreateTypeDefDialog) -> Self {
        Self { dialog }
    }

    /// Whether the action can be executed.
    pub fn can_execute(&self) -> bool {
        self.dialog.confirmed && !self.dialog.name.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TreeNodeInfo -- helper for expand/collapse actions
// ---------------------------------------------------------------------------

/// Minimal information about a tree node for action evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNodeInfo {
    /// The node ID.
    pub id: u64,
    /// The display name.
    pub name: String,
    /// Whether the node is a leaf (no children).
    pub is_leaf: bool,
    /// Whether the node is currently expanded.
    pub expanded: bool,
}

impl TreeNodeInfo {
    /// Create a new tree node info.
    pub fn new(id: u64, name: impl Into<String>, is_leaf: bool) -> Self {
        Self {
            id,
            name: name.into(),
            is_leaf,
            expanded: false,
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
    fn test_save_as_action() {
        let action = SaveAsAction::new("MyArchive", "/tmp/new.gdt");
        assert_eq!(action.archive_name, "MyArchive");
        assert_eq!(action.new_path, "/tmp/new.gdt");
        assert!(action.is_enabled_for("File"));
        assert!(action.is_enabled_for("Project"));
        assert!(!action.is_enabled_for("BuiltIn"));

        let op = action.to_operation();
        assert!(matches!(op, ArchiveOperation::SaveAs { .. }));
    }

    #[test]
    fn test_expand_all_action() {
        let action = ExpandAllAction::new();
        assert!(!action.is_enabled(&[]));

        let nodes = vec![
            TreeNodeInfo::new(1, "cat1", false),
            TreeNodeInfo::new(2, "cat2", false),
        ];
        assert!(action.is_enabled(&nodes));

        let with_leaf = vec![
            TreeNodeInfo::new(1, "cat1", false),
            TreeNodeInfo::new(2, "type1", true),
        ];
        assert!(!action.is_enabled(&with_leaf));

        let to_expand = action.nodes_to_expand(&nodes);
        assert_eq!(to_expand, vec![1, 2]);
    }

    #[test]
    fn test_collapse_all_archives_action() {
        let action = CollapseAllArchivesAction::new();
        assert!(!action.is_enabled(false));
        assert!(action.is_enabled(true));
    }

    #[test]
    fn test_clear_cut_action() {
        let action = ClearCutAction::new();
        assert!(!action.is_valid(false));
        assert!(action.is_valid(true));
        assert!(action.execute(true));
    }

    #[test]
    fn test_create_archive_action() {
        let mut action = CreateArchiveAction::new("/tmp/test.gdt");
        assert!(action.open_after_create);
        action.set_open_after_create(false);
        assert!(!action.open_after_create);

        let op = action.to_operation();
        assert!(matches!(op, ArchiveOperation::CreateFile { .. }));
    }

    #[test]
    fn test_create_project_archive_action() {
        let action = CreateProjectArchiveAction::new("MyProject");
        let op = action.to_operation();
        assert!(matches!(op, ArchiveOperation::CreateProject { .. }));
    }

    #[test]
    fn test_delete_archive_action() {
        let action = DeleteArchiveAction::new("OldArchive");
        assert!(action.requires_confirmation());
        let op = action.to_operation();
        assert!(matches!(op, ArchiveOperation::Delete { .. }));
    }

    #[test]
    fn test_open_project_archive_action() {
        let action = OpenProjectArchiveAction::new("StandardLib");
        let op = action.to_operation();
        assert!(matches!(op, ArchiveOperation::OpenProject { .. }));
    }

    #[test]
    fn test_edit_archive_path_action() {
        let action = EditArchivePathAction::new("MyArchive", "/new/path.gdt");
        assert_eq!(action.archive_name, "MyArchive");
        assert_eq!(action.new_path, "/new/path.gdt");
    }

    #[test]
    fn test_unlock_archive_action() {
        let mut action = UnlockArchiveAction::new("LockedArchive");
        assert!(action.save_before_unlock);
        action.save_before_unlock = false;
        let op = action.to_operation();
        assert!(matches!(op, ArchiveOperation::Unlock { .. }));
    }

    #[test]
    fn test_clear_archive_architecture_action() {
        let action = ClearArchiveArchitectureAction::new("MyArchive");
        assert_eq!(action.archive_name, "MyArchive");
    }

    #[test]
    fn test_set_archive_architecture_action() {
        let action = SetArchiveArchitectureAction::new(
            "MyArchive",
            "x86:LE:64:default",
            "default",
        );
        assert_eq!(action.language_id, "x86:LE:64:default");
        assert_eq!(action.compiler_spec_id, "default");
    }

    #[test]
    fn test_recently_opened_archive_action() {
        let action = RecentlyOpenedArchiveAction::new("/tmp/recent.gdt", "recent.gdt");
        let op = action.to_operation();
        assert!(matches!(op, ArchiveOperation::OpenFile { .. }));
    }

    #[test]
    fn test_remove_invalid_archive_action() {
        let action = RemoveInvalidArchiveFromProgramAction::new("bad.gdt", "prog.exe");
        assert_eq!(action.archive_name, "bad.gdt");
        assert_eq!(action.program_name, "prog.exe");
    }

    #[test]
    fn test_update_source_archive_names_action() {
        let action = UpdateSourceArchiveNamesAction::new("prog.exe");
        assert_eq!(action.program_name, "prog.exe");
    }

    #[test]
    fn test_preview_window_action() {
        let action = PreviewWindowAction::new("/MyStruct");
        assert_eq!(action.data_type_path, "/MyStruct");
    }

    #[test]
    fn test_include_data_types_in_filter_action() {
        let mut action = IncludeDataTypesInFilterAction::new(true);
        assert!(action.include);
        action.toggle();
        assert!(!action.include);
    }

    #[test]
    fn test_conflict_handler_modes_action() {
        let action = ConflictHandlerModesAction::new(ConflictHandlerMode::ReplaceExisting);
        assert_eq!(action.mode, ConflictHandlerMode::ReplaceExisting);

        let default_action = ConflictHandlerModesAction::default();
        assert_eq!(default_action.mode, ConflictHandlerMode::Default);
    }

    #[test]
    fn test_data_type_merge_confirmation_dialog() {
        let mut dialog = DataTypeMergeConfirmationDialog::new("archive1", "archive2", 10);
        assert_eq!(dialog.type_count, 10);
        assert!(!dialog.confirmed);
        dialog.confirm();
        assert!(dialog.confirmed);
        dialog.cancel();
        assert!(!dialog.confirmed);
    }

    #[test]
    fn test_data_type_merge_error_dialog() {
        let mut dialog = DataTypeMergeErrorDialog::new("Merge Failed", "Cannot merge types");
        assert!(!dialog.has_errors());
        dialog.add_error("MyStruct", "Name conflict");
        assert!(dialog.has_errors());
        assert_eq!(dialog.errors.len(), 1);
    }

    #[test]
    fn test_undo_redo_archive_transaction_action() {
        let undo = UndoRedoArchiveTransactionAction::new_undo("MyArchive");
        assert!(undo.is_undo);
        let op = undo.to_operation();
        assert!(matches!(op, ArchiveOperation::Undo { .. }));

        let redo = UndoRedoArchiveTransactionAction::new_redo("MyArchive")
            .with_transaction_id(42);
        assert!(!redo.is_undo);
        assert_eq!(redo.transaction_id, Some(42));
        let op = redo.to_operation();
        assert!(matches!(op, ArchiveOperation::Redo { .. }));
    }

    #[test]
    fn test_annotation_handler_dialog() {
        let dialog = AnnotationHandlerDialog::new();
        assert!(dialog.preserve_annotations);
        assert!(!dialog.strip_annotations);
        assert!(dialog.prefix_filter.is_empty());
    }

    #[test]
    fn test_data_type_merge_dialog() {
        let mut dialog = DataTypeMergeDialog::new(
            "archive1",
            "archive2",
            ConflictHandlerMode::Default,
        );
        dialog.add_type("int");
        dialog.add_type("char");
        assert_eq!(dialog.types_to_merge.len(), 2);
        dialog.confirm();
        assert!(dialog.confirmed);
    }

    #[test]
    fn test_find_references_to_field_action() {
        let action = FindReferencesToFieldAction::new("/MyStruct", "field1", 0);
        assert_eq!(action.data_type_path, "/MyStruct");
        assert_eq!(action.field_name, "field1");
        assert_eq!(action.field_ordinal, 0);
    }

    #[test]
    fn test_type_def_action() {
        let action = TypeDefAction::new("my_int", "/int", "/CustomTypes");
        assert_eq!(action.typedef_name, "my_int");
        assert_eq!(action.base_type_path, "/int");
        assert_eq!(action.category_path, "/CustomTypes");
    }

    #[test]
    fn test_create_typedef_dialog() {
        let mut dialog = CreateTypeDefDialog::new("/int", "/CustomTypes");
        assert!(!dialog.confirmed);
        dialog.set_name("my_int");
        dialog.confirm();
        assert!(dialog.confirmed);
        assert_eq!(dialog.name, "my_int");
    }

    #[test]
    fn test_create_typedef_dialog_empty_name() {
        let mut dialog = CreateTypeDefDialog::new("/int", "/CustomTypes");
        dialog.confirm(); // name is empty
        assert!(!dialog.confirmed);
    }

    #[test]
    fn test_create_typedef_from_dialog_action() {
        let mut dialog = CreateTypeDefDialog::new("/int", "/CustomTypes");
        dialog.set_name("my_int");
        dialog.confirm();
        let action = CreateTypeDefFromDialogAction::new(dialog);
        assert!(action.can_execute());
    }

    #[test]
    fn test_tree_node_info() {
        let node = TreeNodeInfo::new(1, "category", false);
        assert_eq!(node.id, 1);
        assert!(!node.is_leaf);
        assert!(!node.expanded);
    }
}
