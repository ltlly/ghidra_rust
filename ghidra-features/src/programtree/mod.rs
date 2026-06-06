//! Program Tree management -- ported from Ghidra's
//! `ghidra.app.plugin.core.programtree` Java package.
//!
//! This module models the hierarchical program tree structure (modules and
//! fragments) that controls what address ranges are visible in the code
//! browser.  It provides:
//!
//! - [`ProgramNode`] -- a tree node wrapping a [`Group`] (module or fragment)
//! - [`ProgramTree`] -- the tree data structure with expansion/selection state
//! - [`ProgramTreePlugin`] -- plugin-level coordination of multiple tree views
//! - [`TreeViewProvider`] -- a single tree view with its address-set view
//! - [`ProgramTreeActionManager`] -- action dispatch (cut/copy/paste/merge/delete/rename)
//! - [`PasteManager`] / [`ReorderManager`] -- clipboard and drag-drop support
//! - [`GroupPath`] -- a path through the tree to a specific group
//!
//! Swing-specific UI code (renderers, DnD adapters, cell editors) is omitted;
//! only the model, state, and business logic are ported.

pub mod node;
pub mod tree;
pub mod plugin;
pub mod view_provider;
pub mod action_manager;
pub mod paste_manager;
pub mod reorder_manager;
pub mod group_path;
pub mod dnd_move_manager;
pub mod transferable;
pub mod view_panel;
pub mod listeners;

pub use group_path::GroupPath;
pub use node::ProgramNode;
pub use tree::ProgramTree;
pub use plugin::ProgramTreePlugin;
pub use view_provider::TreeViewProvider;
pub use action_manager::ProgramTreeActionManager;
pub use paste_manager::PasteManager;
pub use reorder_manager::ReorderManager;
pub use dnd_move_manager::{DnDMoveManager, DropAction, DropResult, DropError};
pub use transferable::{GroupTransferable, ProgramTreeTransferable, TransferData};
pub use view_panel::ViewPanel;
pub use listeners::{TreeEvent, TreeListener, ViewChangeListener, CallbackTreeListener};

// ---------------------------------------------------------------------------
// ProgramTreeActionContext
// ---------------------------------------------------------------------------

/// Context for program tree actions.
///
/// Ported from `ghidra.app.plugin.core.programtree.ProgramTreeActionContext`.
#[derive(Debug, Clone, Default)]
pub struct ProgramTreeActionContext {
    /// Selected nodes in the tree.
    pub selected_nodes: Vec<String>,
    /// The tree name.
    pub tree_name: String,
    /// Whether the context is in a valid state for actions.
    pub valid: bool,
}

impl ProgramTreeActionContext {
    /// Create a new action context.
    pub fn new(tree_name: impl Into<String>) -> Self {
        Self {
            selected_nodes: Vec::new(),
            tree_name: tree_name.into(),
            valid: true,
        }
    }

    /// Add a selected node.
    pub fn add_selection(&mut self, node_name: impl Into<String>) {
        self.selected_nodes.push(node_name.into());
    }

    /// Whether there is a selection.
    pub fn has_selection(&self) -> bool {
        !self.selected_nodes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ProgramTreeModelListener
// ---------------------------------------------------------------------------

/// Listener for program tree model changes.
///
/// Ported from `ghidra.app.plugin.core.programtree.ProgramTreeModelListener`.
pub trait ProgramTreeModelListener: Send + Sync {
    /// Called when a node is added to the tree.
    fn node_added(&mut self, parent_path: &str, child_name: &str);

    /// Called when a node is removed from the tree.
    fn node_removed(&mut self, parent_path: &str, child_name: &str);

    /// Called when the tree structure changes.
    fn structure_changed(&mut self);

    /// Called when a node is renamed.
    fn node_renamed(&mut self, old_name: &str, new_name: &str);
}

// ---------------------------------------------------------------------------
// ProgramTreeModularizationPlugin
// ---------------------------------------------------------------------------

/// Plugin for program tree modularization (reorganizing tree structure).
///
/// Ported from `ghidra.app.plugin.core.programtree
/// .ProgramTreeModularizationPlugin`.
#[derive(Debug)]
pub struct ProgramTreeModularizationPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// The target tree name.
    pub target_tree: Option<String>,
}

impl ProgramTreeModularizationPlugin {
    /// Create a new modularization plugin.
    pub fn new() -> Self {
        Self {
            name: "ProgramTreeModularizationPlugin".into(),
            enabled: true,
            target_tree: None,
        }
    }

    /// Set the target tree.
    pub fn set_target_tree(&mut self, tree: impl Into<String>) {
        self.target_tree = Some(tree.into());
    }
}

impl Default for ProgramTreeModularizationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_tree_action_context() {
        let mut ctx = ProgramTreeActionContext::new("Tree1");
        assert!(!ctx.has_selection());
        ctx.add_selection("Fragment1");
        ctx.add_selection("Fragment2");
        assert!(ctx.has_selection());
        assert_eq!(ctx.selected_nodes.len(), 2);
    }

    #[test]
    fn test_program_tree_modularization_plugin() {
        let mut plugin = ProgramTreeModularizationPlugin::new();
        assert!(plugin.enabled);
        assert!(plugin.target_tree.is_none());
        plugin.set_target_tree("MyTree");
        assert_eq!(plugin.target_tree.as_deref(), Some("MyTree"));
    }
}
