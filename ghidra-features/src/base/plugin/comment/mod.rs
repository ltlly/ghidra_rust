//! Comment Plugin -- manages comments in the program listing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.comments` package.
//!
//! This module provides the comment plugin that manages comments in the
//! program listing. Supports various comment types (end-of-line, pre, post,
//! plate, repeatable) and operations like add, edit, delete, and history.
//!
//! # Modules
//!
//! - [`comment_plugin`] -- The main plugin struct and lifecycle

pub mod comment_plugin;

pub use comment_plugin::{
    Comment, CommentHistoryAction, CommentHistoryEntry, CommentHistoryStore, CommentOption,
    CommentPlugin, CommentType,
};
