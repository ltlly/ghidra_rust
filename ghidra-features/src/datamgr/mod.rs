//! Data Type Manager plugin components for Ghidra Rust.
//!
//! This module is a Rust port of Ghidra's
//! `ghidra.app.plugin.core.datamgr` and `ghidra.app.plugin.core.data`
//! Java packages.  It provides:
//!
//! - **Archive management** ([`archive`]): Trait and concrete types for
//!   built-in, file-backed, program, project, and invalid archives.
//!
//! - **Synchronization** ([`sync`]): Tracking and reconciling data type
//!   differences between a program and its source archives via
//!   [`DataTypeSyncState`], [`DataTypeSyncInfo`], and [`DataTypeSynchronizer`].
//!
//! - **Handler** ([`handler`]): [`DataTypeManagerHandler`] -- the central
//!   coordinator that tracks all open archives, manages the built-in
//!   manager, and provides the lookup / lifecycle operations used by the
//!   rest of the plugin.
//!
//! - **Editor management** ([`editor`]): [`DataTypeEditorManager`] with
//!   [`EditorProvider`] for creating, opening, checking, and dismissing
//!   inline structure / union / enum editors.
//!
//! - **Tree model** ([`tree`]): A node hierarchy rooted at
//!   [`ArchiveRootNode`] with [`ArchiveNode`], [`CategoryNode`], and
//!   [`DataTypeNode`] for the data-type tree view.
//!
//! # Quick start
//!
//! ```rust
//! use ghidra_features::datamgr::handler::DataTypeManagerHandler;
//!
//! let mut handler = DataTypeManagerHandler::new("My Plugin");
//! assert_eq!(handler.all_archives().len(), 0);
//! ```

pub mod actions;
pub mod archive;
pub mod dialog;
pub mod dnd;
pub mod enum_table;
pub mod filter;
pub mod find_actions;
pub mod sync;
pub mod handler;
pub mod plugin;
pub mod property_manager;
pub mod provider;
pub mod editor;
pub mod tasks;
pub mod tree;
pub mod util;
pub mod utils;

/// Extended data type manager actions (create, delete, rename, merge, etc.).
///
/// Ported from individual action classes in
/// `ghidra.app.plugin.core.datamgr.actions`.
pub mod actions_ext;

/// Data type clipboard operations (cut/copy/paste).
///
/// Ported from cut/copy/paste actions in
/// `ghidra.app.plugin.core.datamgr.actions`.
pub mod clipboard;

/// Data type tree operations (create/rename/delete categories and types).
///
/// Ported from action and tree management classes in
/// `ghidra.app.plugin.core.datamgr.actions` and
/// `ghidra.app.plugin.core.datamgr.tree`.
pub mod tree_ops;

/// Data type association management (sync, commit, revert, update).
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate`.
pub mod associate;

// Re-export the most-used public types at the datamgr level.
pub use archive::{Archive, ArchiveKind, BuiltInArchive, FileArchive, ProgramArchive,
                   ProjectArchive, InvalidFileArchive, ArchiveManagerListener};
pub use sync::{DataTypeSyncState, DataTypeSyncInfo, DataTypeSynchronizer};
pub use handler::DataTypeManagerHandler;
pub use editor::{DataTypeEditorManager, EditorProvider, EditorState, EditorListener};
pub use plugin::DataTypeManagerPlugin;
pub use property_manager::DataTypePropertyManager;
pub use provider::{DataTypesProvider, DataTypesConfig};
pub use dialog::{DataTypeSyncDialog, DataTypeSyncTableModel, SyncDialogLayout};
pub use util::{RecentArchiveTracker, DataTypeSelection, AllowedDataTypes};
pub use tree::{TreeNodeKind, ArchiveRootNode, ArchiveNode, CategoryNode, DataTypeNode};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Filter state for the data type tree
// ---------------------------------------------------------------------------

/// Filter configuration for the data type tree.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.DtFilterState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtFilterState {
    /// Text filter pattern.
    pub name_filter: String,
    /// Whether to show only recently used types.
    pub show_recent_only: bool,
    /// Whether to show categories.
    pub show_categories: bool,
    /// Maximum size to show (0 = unlimited).
    pub max_size: u64,
}

impl Default for DtFilterState {
    fn default() -> Self {
        Self {
            name_filter: String::new(),
            show_recent_only: false,
            show_categories: true,
            max_size: 0,
        }
    }
}

impl DtFilterState {
    /// Check if a type name passes the filter.
    pub fn matches(&self, name: &str) -> bool {
        if self.name_filter.is_empty() {
            return true;
        }
        name.to_lowercase().contains(&self.name_filter.to_lowercase())
    }
}

// ---------------------------------------------------------------------------
// NextPreviousDataTypeAction -- navigate recently used types
// ---------------------------------------------------------------------------

/// Action context for navigating through recently used data types.
///
/// Ported from `ghidra.app.plugin.core.datamgr.NextPreviousDataTypeAction`.
#[derive(Debug, Clone, Default)]
pub struct DataTypeNavigator {
    /// Recently used data type names (most recent first).
    pub recent: Vec<String>,
    /// Current position in the recent list.
    pub position: usize,
}

impl DataTypeNavigator {
    /// Create a new navigator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a data type was used.
    pub fn record_use(&mut self, type_name: &str) {
        self.recent.retain(|n| n != type_name);
        self.recent.insert(0, type_name.to_string());
        self.position = 0;
    }

    /// Go to the previous (older) recently used type.
    pub fn go_previous(&mut self) -> Option<&str> {
        if self.position + 1 < self.recent.len() {
            self.position += 1;
            self.recent.get(self.position).map(|s| s.as_str())
        } else {
            None
        }
    }

    /// Go to the next (newer) recently used type.
    pub fn go_next(&mut self) -> Option<&str> {
        if self.position > 0 {
            self.position -= 1;
            self.recent.get(self.position).map(|s| s.as_str())
        } else {
            None
        }
    }

    /// Get the current recently used type.
    pub fn current(&self) -> Option<&str> {
        self.recent.get(self.position).map(|s| s.as_str())
    }

    /// Number of recently used types.
    pub fn count(&self) -> usize {
        self.recent.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dt_filter_state_default() {
        let filter = DtFilterState::default();
        assert!(filter.name_filter.is_empty());
        assert!(!filter.show_recent_only);
        assert!(filter.show_categories);
    }

    #[test]
    fn test_dt_filter_state_matches() {
        let filter = DtFilterState { name_filter: "int".to_string(), ..Default::default() };
        assert!(filter.matches("int"));
        assert!(filter.matches("Integer"));
        assert!(filter.matches("uint32"));
        assert!(!filter.matches("float"));
    }

    #[test]
    fn test_dt_filter_state_empty_filter() {
        let filter = DtFilterState::default();
        assert!(filter.matches("anything"));
        assert!(filter.matches(""));
    }

    #[test]
    fn test_data_type_navigator_record_use() {
        let mut nav = DataTypeNavigator::new();
        nav.record_use("int");
        nav.record_use("float");
        nav.record_use("char");
        assert_eq!(nav.count(), 3);
        assert_eq!(nav.current(), Some("char"));
    }

    #[test]
    fn test_data_type_navigator_dedup() {
        let mut nav = DataTypeNavigator::new();
        nav.record_use("int");
        nav.record_use("float");
        nav.record_use("int");
        assert_eq!(nav.count(), 2);
        assert_eq!(nav.current(), Some("int"));
    }

    #[test]
    fn test_data_type_navigator_navigation() {
        let mut nav = DataTypeNavigator::new();
        nav.record_use("int");
        nav.record_use("float");
        nav.record_use("char");
        // Current: "char"
        assert_eq!(nav.current(), Some("char"));
        // Previous: "float"
        assert_eq!(nav.go_previous(), Some("float"));
        // Previous: "int"
        assert_eq!(nav.go_previous(), Some("int"));
        // Can't go further back
        assert_eq!(nav.go_previous(), None);
        // Next: "float"
        assert_eq!(nav.go_next(), Some("float"));
        // Next: "char"
        assert_eq!(nav.go_next(), Some("char"));
        // Can't go further forward
        assert_eq!(nav.go_next(), None);
    }
}

