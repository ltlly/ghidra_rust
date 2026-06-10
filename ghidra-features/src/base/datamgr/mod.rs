//! DataTypeManager feature -- the data type manager GUI.
//!
//! Ported from Ghidra's `Features/DataTypeManager` Java packages:
//! - `ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin`
//! - `ghidra.app.plugin.core.datamgr.DataTypeManagerProvider`
//! - `ghidra.app.plugin.core.datamgr.DataTypeSynchronizer`
//! - `ghidra.app.plugin.core.datamgr.archivebrowser`
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
//!
//! DtMgrSynchronizer
//!   ├── client_name / source_name
//!   ├── entries: Vec<SynchronizerEntry>
//!   ├── listener / state
//!   └── apply() -> SyncSummary
//!
//! DataTypeArchiveBrowser
//!   ├── archive_nodes: Vec<ArchiveBrowserNode>
//!   ├── filter / sort
//!   └── selection tracking
//! ```
//!
//! # Modules
//!
//! - [`data_type_manager_plugin`] -- The plugin struct managing provider
//!   lifecycle, actions, and program events
//! - [`data_type_manager_provider`] -- The component provider managing the
//!   data type tree display, filtering, sorting, selection, and editing
//! - [`data_type_synchronizer`] -- High-level sync orchestration for
//!   the synchronize-commit-update workflow
//! - [`data_type_archive_browser`] -- Tree-based browser for navigating
//!   open data type archives

pub mod data_type_manager_plugin;
pub mod data_type_manager_provider;
pub mod data_type_synchronizer;
pub mod data_type_archive_browser;

pub use data_type_manager_plugin::{
    ArchiveInfo, DataTypeManagerPlugin, DtMgrAction, DtMgrConfigValue,
};
pub use data_type_manager_provider::{
    DataTypeManagerProvider, DtMgrDisplayRow, FilterState, NodeType, SortMode,
};
pub use data_type_synchronizer::{
    DtMgrSynchronizer, DtMgrSyncListener, SyncAction, SyncResolution,
    SyncSummary, SynchronizerEntry,
};
pub use data_type_archive_browser::{
    ArchiveBrowserFilter, ArchiveBrowserKind, ArchiveBrowserNode,
    ArchiveBrowserSort, CategoryBrowserNode, DataTypeArchiveBrowser,
    TypeBrowserEntry,
};
