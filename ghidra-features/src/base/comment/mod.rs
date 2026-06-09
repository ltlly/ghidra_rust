//! Comment management for Ghidra Rust.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.comments` package:
//!
//! - [`CommentPlugin`] -- the main plugin service, managing comment CRUD,
//!   dialog lifecycle, actions, and history tracking
//! - [`CommentDialog`] -- dialog model for editing a single comment
//! - [`TabModel`] -- tabbed editor model for all five comment types
//!
//! The GUI-specific portions (Swing text areas, tabs, key listeners) are
//! omitted.  Only the domain model, state management, and action logic
//! are ported.
//!
//! # Sub-modules
//!
//! - [`comment_plugin`] -- the main plugin struct, actions, history, and
//!   popup path resolution
//! - [`comment_dialog`] -- the dialog model, result type, dialog manager,
//!   and tabbed editor model

pub mod comment_dialog;
pub mod comment_plugin;

pub use comment_dialog::{CommentDialog, CommentDialogManager, CommentDialogResult, TabModel};
pub use comment_plugin::{
    CommentAction, CommentActionKind, CommentActions, CommentHistory, CommentHistoryEntry,
    CommentPlugin, PluginOptions,
};
