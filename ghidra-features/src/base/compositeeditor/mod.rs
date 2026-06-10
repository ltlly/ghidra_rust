//! Composite (struct/union) data type editor for Base.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor` Java packages
//! under Ghidra's Features/Base module.
//!
//! This module provides the Base-integrated composite editor subsystem:
//!
//! - [`composite_editor_panel`] -- the main editor panel with table management,
//!   selection, cell editing, drag-and-drop, and undo/redo snapshot support
//! - [`field_list_editor`] -- field list editing logic for composite components
//! - [`editor_provider`] -- editor provider types (structure, union) with
//!   lifecycle, save-check, and data type manager integration
//! - [`structure_editor_panel`] -- structure-specific editor panel with
//!   bit-field editing and offset/alignment management
//!
//! # Relationship to the `compositeeditor` crate module
//!
//! The sibling `compositeeditor` module (at crate root) provides the
//! standalone model, actions, and rendering logic.  This `base::compositeeditor`
//! module wraps those primitives into the Base plugin framework, adding
//! docking integration, program-aware providers, and editor lifecycle.

pub mod composite_editor_panel;
pub mod field_list_editor;
pub mod editor_provider;
pub mod structure_editor_panel;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Re-exports from the crate-level compositeeditor module
// ---------------------------------------------------------------------------

pub use crate::compositeeditor::{
    ComponentRow,
    CompositeEditorModel,
    CompositeEditorEvent,
    CompositeEditorModelListener,
    StructureEditorModel,
    UnionEditorModel,
    CompositeViewerModel,
    StructureColumns,
    UnionColumns,
    BitFieldEditorModel,
    EditTransaction,
};

// ---------------------------------------------------------------------------
// DataTypePath (local stand-in for ghidra.program.model.data.DataTypePath)
// ---------------------------------------------------------------------------

/// Identifies a data type by its category path and name.
///
/// Ported from `ghidra.program.model.data.DataTypePath`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataTypePath {
    /// The category path (e.g., "/my/structs").
    pub category_path: String,
    /// The data type name (e.g., "MyStruct").
    pub data_type_name: String,
}

impl DataTypePath {
    /// Create a new data type path.
    pub fn new(category_path: impl Into<String>, data_type_name: impl Into<String>) -> Self {
        Self {
            category_path: category_path.into(),
            data_type_name: data_type_name.into(),
        }
    }

    /// The full path as a string: category_path + "/" + data_type_name.
    pub fn full_path(&self) -> String {
        if self.category_path.is_empty() || self.category_path == "/" {
            format!("/{}", self.data_type_name)
        } else {
            format!("{}/{}", self.category_path, self.data_type_name)
        }
    }
}

impl std::fmt::Display for DataTypePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_path())
    }
}

// ---------------------------------------------------------------------------
// EditorListener
// ---------------------------------------------------------------------------

/// Listener notified when an editor window is closed.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditorListener`.
pub trait EditorListener: Send + Sync {
    /// Called when the editor is closing.
    fn editor_closing(&self, dt_path: &DataTypePath);
}

// ---------------------------------------------------------------------------
// Editor service interface
// ---------------------------------------------------------------------------

/// Service for managing open composite editors.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorProvider`.
pub trait CompositeEditorService: Send + Sync {
    /// Open an editor for the data type at the given path.
    fn open_editor(&self, dt_path: &DataTypePath);

    /// Close the editor for the data type at the given path.
    fn close_editor(&self, dt_path: &DataTypePath);

    /// Return whether an editor is open for the given data type path.
    fn is_editor_open(&self, dt_path: &DataTypePath) -> bool;

    /// Get all currently open editor paths.
    fn open_editor_paths(&self) -> Vec<DataTypePath>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_path_display() {
        let p = DataTypePath::new("/my/structs", "MyStruct");
        assert_eq!(p.full_path(), "/my/structs/MyStruct");
        assert_eq!(format!("{p}"), "/my/structs/MyStruct");
    }

    #[test]
    fn test_data_type_path_root_category() {
        let p = DataTypePath::new("/", "int");
        assert_eq!(p.full_path(), "/int");
    }

    #[test]
    fn test_data_type_path_empty_category() {
        let p = DataTypePath::new("", "int");
        assert_eq!(p.full_path(), "/int");
    }
}
