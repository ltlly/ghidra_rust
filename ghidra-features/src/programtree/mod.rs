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
