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

pub mod archive;
pub mod sync;
pub mod handler;
pub mod editor;
pub mod tree;

// Re-export the most-used public types at the datamgr level.
pub use archive::{Archive, ArchiveKind, BuiltInArchive, FileArchive, ProgramArchive,
                   ProjectArchive, InvalidFileArchive, ArchiveManagerListener};
pub use sync::{DataTypeSyncState, DataTypeSyncInfo, DataTypeSynchronizer};
pub use handler::DataTypeManagerHandler;
pub use editor::{DataTypeEditorManager, EditorProvider, EditorState, EditorListener};
pub use tree::{TreeNodeKind, ArchiveRootNode, ArchiveNode, CategoryNode, DataTypeNode};
