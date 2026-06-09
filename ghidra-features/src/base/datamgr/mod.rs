//! DataTypeManager feature -- the data type manager GUI.
//!
//! Ported from Ghidra's `Features/DataTypeManager` Java packages:
//! - `ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin`
//! - `ghidra.app.plugin.core.datamgr.DataTypeManagerProvider`
//!
//! This module provides the plugin and provider for browsing, searching,
//! editing, and managing data types in Ghidra's Data Type Manager window.
//! It integrates with the core [`DataTypeManager`] trait to display and
//! manipulate the hierarchical tree of data types, categories, and archives.
//!
//! # Architecture
//!
//! ```text
//! DataTypeManagerPlugin
//!   ├── provider: DataTypeManagerProvider  (the main tree view)
//!   ├── archive_providers: Vec<DataTypeManagerProvider>  (external archives)
//!   ├── actions (new type, edit, delete, rename, cut/copy/paste, search)
//!   └── program lifecycle events
//!
//! DataTypeManagerProvider
//!   ├── name / visible / disposed
//!   ├── program connection (program_name)
//!   ├── tree state (root node, expanded set, selected node)
//!   ├── filter / search state
//!   ├── sort mode
//!   └── undo/redo support
//! ```
//!
//! # Modules
//!
//! - [`data_type_manager_plugin`] -- The plugin struct managing provider
//!   lifecycle, actions, and program events
//! - [`data_type_manager_provider`] -- The component provider managing the
//!   data type tree display, filtering, sorting, selection, and editing

pub mod data_type_manager_plugin;
pub mod data_type_manager_provider;

pub use data_type_manager_plugin::{
    ArchiveInfo, DataTypeManagerPlugin, DtMgrAction, DtMgrConfigValue,
};
pub use data_type_manager_provider::{
    DataTypeManagerProvider, DtMgrDisplayRow, FilterState, NodeType, SortMode,
};
