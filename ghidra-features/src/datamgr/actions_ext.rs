//! Extended data type manager actions.
//!
//! Ported from individual action classes in
//! `ghidra.app.plugin.core.datamgr.actions`.
//!
//! Provides the action types for operations like create, delete, rename,
//! copy/paste, import/export, merge, and synchronization of data types.

use serde::{Deserialize, Serialize};

/// Action types available in the data type manager.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataTypeManagerAction {
    /// Create a new data type.
    CreateDataType,
    /// Create a new structure.
    CreateStructure,
    /// Create a new union.
    CreateUnion,
    /// Create a new enum.
    CreateEnum,
    /// Create a new pointer.
    CreatePointer,
    /// Create a new type definition.
    CreateTypeDef,
    /// Create a new function definition.
    CreateFunctionDef,
    /// Create a new category.
    CreateCategory,
    /// Delete selected data types.
    Delete,
    /// Rename a data type.
    Rename,
    /// Cut data types to clipboard.
    Cut,
    /// Copy data types to clipboard.
    Copy,
    /// Paste data types from clipboard.
    Paste,
    /// Edit a data type.
    Edit,
    /// Replace one data type with another.
    Replace,
    /// Merge data types from an archive.
    Merge,
    /// Show properties of a data type.
    Properties,
    /// Set a data type as favorite.
    SetFavorite,
    /// Find data types by name.
    FindByName,
    /// Find data types by size.
    FindBySize,
    /// Find data types by value.
    FindByValue,
    /// Find structures by offset.
    FindStructuresByOffset,
    /// Find references to a data type.
    FindReferences,
    /// Find references to a field.
    FindFieldReferences,
    /// Export data types to a header file.
    ExportToHeader,
    /// Apply data types from archive to program.
    ApplyToProgram,
    /// Apply enum values as labels.
    ApplyEnumsAsLabels,
    /// Open an archive.
    OpenArchive,
    /// Close an archive.
    CloseArchive,
    /// Save an archive.
    SaveArchive,
    /// Save an archive as a new file.
    SaveAs,
    /// Lock an archive.
    LockArchive,
    /// Unlock an archive.
    UnlockArchive,
    /// Undo archive transaction.
    UndoTransaction,
    /// Redo archive transaction.
    RedoTransaction,
    /// Set the architecture for an archive.
    SetArchiveArchitecture,
    /// Clear the architecture for an archive.
    ClearArchiveArchitecture,
    /// Display type as a dependency graph.
    DisplayAsGraph,
    /// Refresh the tree.
    Refresh,
    /// Expand all nodes.
    ExpandAll,
    /// Collapse all nodes.
    CollapseAll,
    /// Show the preview window.
    PreviewWindow,
    /// Associate data types with an archive.
    Associate,
    /// Disassociate data types from an archive.
    Disassociate,
    /// Commit data type changes to archive.
    Commit,
    /// Update data types from archive.
    Update,
    /// Revert data type changes.
    Revert,
    /// Sync data types with archive.
    Sync,
}

impl DataTypeManagerAction {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::CreateDataType => "New Data Type",
            Self::CreateStructure => "New Structure",
            Self::CreateUnion => "New Union",
            Self::CreateEnum => "New Enum",
            Self::CreatePointer => "New Pointer",
            Self::CreateTypeDef => "New TypeDef",
            Self::CreateFunctionDef => "New Function Definition",
            Self::CreateCategory => "New Category",
            Self::Delete => "Delete",
            Self::Rename => "Rename",
            Self::Cut => "Cut",
            Self::Copy => "Copy",
            Self::Paste => "Paste",
            Self::Edit => "Edit",
            Self::Replace => "Replace",
            Self::Merge => "Merge",
            Self::Properties => "Properties",
            Self::SetFavorite => "Set Favorite",
            Self::FindByName => "Find by Name",
            Self::FindBySize => "Find by Size",
            Self::FindByValue => "Find by Value",
            Self::FindStructuresByOffset => "Find Structures by Offset",
            Self::FindReferences => "Find References",
            Self::FindFieldReferences => "Find Field References",
            Self::ExportToHeader => "Export to Header",
            Self::ApplyToProgram => "Apply to Program",
            Self::ApplyEnumsAsLabels => "Apply Enums as Labels",
            Self::OpenArchive => "Open File Archive",
            Self::CloseArchive => "Close Archive",
            Self::SaveArchive => "Save Archive",
            Self::SaveAs => "Save As",
            Self::LockArchive => "Lock Archive",
            Self::UnlockArchive => "Unlock Archive",
            Self::UndoTransaction => "Undo Transaction",
            Self::RedoTransaction => "Redo Transaction",
            Self::SetArchiveArchitecture => "Set Architecture",
            Self::ClearArchiveArchitecture => "Clear Architecture",
            Self::DisplayAsGraph => "Display as Graph",
            Self::Refresh => "Refresh",
            Self::ExpandAll => "Expand All",
            Self::CollapseAll => "Collapse All",
            Self::PreviewWindow => "Preview Window",
            Self::Associate => "Associate",
            Self::Disassociate => "Disassociate",
            Self::Commit => "Commit",
            Self::Update => "Update",
            Self::Revert => "Revert",
            Self::Sync => "Sync",
        }
    }

    /// Whether this action requires a selection.
    pub fn requires_selection(&self) -> bool {
        matches!(
            self,
            Self::Delete
                | Self::Rename
                | Self::Cut
                | Self::Copy
                | Self::Edit
                | Self::Replace
                | Self::Properties
                | Self::SetFavorite
                | Self::FindReferences
                | Self::FindFieldReferences
                | Self::Merge
                | Self::DisplayAsGraph
        )
    }

    /// Whether this action applies to archives.
    pub fn is_archive_action(&self) -> bool {
        matches!(
            self,
            Self::OpenArchive
                | Self::CloseArchive
                | Self::SaveArchive
                | Self::SaveAs
                | Self::LockArchive
                | Self::UnlockArchive
                | Self::UndoTransaction
                | Self::RedoTransaction
                | Self::SetArchiveArchitecture
                | Self::ClearArchiveArchitecture
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_display_names() {
        assert_eq!(DataTypeManagerAction::CreateStructure.display_name(), "New Structure");
        assert_eq!(DataTypeManagerAction::Delete.display_name(), "Delete");
        assert_eq!(DataTypeManagerAction::ExportToHeader.display_name(), "Export to Header");
    }

    #[test]
    fn test_action_requires_selection() {
        assert!(DataTypeManagerAction::Delete.requires_selection());
        assert!(DataTypeManagerAction::Rename.requires_selection());
        assert!(!DataTypeManagerAction::Refresh.requires_selection());
        assert!(!DataTypeManagerAction::ExpandAll.requires_selection());
    }

    #[test]
    fn test_action_is_archive_action() {
        assert!(DataTypeManagerAction::OpenArchive.is_archive_action());
        assert!(DataTypeManagerAction::SaveArchive.is_archive_action());
        assert!(DataTypeManagerAction::LockArchive.is_archive_action());
        assert!(!DataTypeManagerAction::Delete.is_archive_action());
        assert!(!DataTypeManagerAction::CreateStructure.is_archive_action());
    }

    #[test]
    fn test_all_action_variants_have_names() {
        let actions = vec![
            DataTypeManagerAction::CreateDataType,
            DataTypeManagerAction::Delete,
            DataTypeManagerAction::Rename,
            DataTypeManagerAction::Cut,
            DataTypeManagerAction::Copy,
            DataTypeManagerAction::Paste,
            DataTypeManagerAction::Edit,
            DataTypeManagerAction::Replace,
            DataTypeManagerAction::Merge,
            DataTypeManagerAction::Properties,
            DataTypeManagerAction::SetFavorite,
            DataTypeManagerAction::FindByName,
            DataTypeManagerAction::FindBySize,
            DataTypeManagerAction::FindByValue,
            DataTypeManagerAction::FindStructuresByOffset,
            DataTypeManagerAction::FindReferences,
            DataTypeManagerAction::FindFieldReferences,
            DataTypeManagerAction::ExportToHeader,
            DataTypeManagerAction::ApplyToProgram,
            DataTypeManagerAction::ApplyEnumsAsLabels,
            DataTypeManagerAction::OpenArchive,
            DataTypeManagerAction::CloseArchive,
            DataTypeManagerAction::SaveArchive,
            DataTypeManagerAction::SaveAs,
            DataTypeManagerAction::LockArchive,
            DataTypeManagerAction::UnlockArchive,
            DataTypeManagerAction::UndoTransaction,
            DataTypeManagerAction::RedoTransaction,
            DataTypeManagerAction::SetArchiveArchitecture,
            DataTypeManagerAction::ClearArchiveArchitecture,
            DataTypeManagerAction::DisplayAsGraph,
            DataTypeManagerAction::Refresh,
            DataTypeManagerAction::ExpandAll,
            DataTypeManagerAction::CollapseAll,
            DataTypeManagerAction::PreviewWindow,
            DataTypeManagerAction::Associate,
            DataTypeManagerAction::Disassociate,
            DataTypeManagerAction::Commit,
            DataTypeManagerAction::Update,
            DataTypeManagerAction::Revert,
            DataTypeManagerAction::Sync,
        ];
        for action in actions {
            assert!(!action.display_name().is_empty());
        }
    }
}
