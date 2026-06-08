//! Bookmark management for Ghidra programs.
//!
//! This module ports Ghidra's `ghidra.app.plugin.core.bookmark` Java package
//! to Rust. It provides:
//!
//! - [`Bookmark`] -- a single bookmark annotation at an address
//! - [`BookmarkManager`] -- manages all bookmarks in a program with indexed
//!   lookup, creation, update, and deletion
//! - [`BookmarkType`] -- built-in and custom bookmark type definitions
//! - [`BookmarkRowObject`] -- lightweight table row key
//! - [`FilterState`] -- serializable filter snapshot
//! - [`BookmarkEditCmd`] / [`BookmarkDeleteCmd`] -- undo-able commands
//! - [`BookmarkNavigator`] -- marker management for listing display
//! - [`BookmarkTableModel`] -- tabular data model with type filtering
//!
//! # Architecture
//!
//! The module separates data management ([`BookmarkManager`]) from display
//! logic ([`BookmarkNavigator`], [`BookmarkTableModel`]) and mutation
//! commands ([`BookmarkEditCmd`], [`BookmarkDeleteCmd`]). This mirrors
//! Ghidra's Command pattern where mutations are encapsulated in command
//! objects for undo/redo support.

pub mod actions;
pub mod commands;
pub mod dialog;
pub mod mappers;
pub mod model;
pub mod navigator;
pub mod plugin;
pub mod provider;
pub mod table;
pub mod types;

pub use actions::{
    BookmarkAction, BookmarkActionContext, BookmarkDeleteAction, MAX_DELETE_ACTIONS,
};
pub use commands::{
    AddressSet, BookmarkCommand, BookmarkDeleteBackgroundCmd, BookmarkDeleteCmd, BookmarkEditCmd,
};
pub use dialog::{
    CreateBookmarkDialog, CreateBookmarkResult, FilterDialog, FilterTypeEntry,
};
pub use mappers::{
    BookmarkRowObjectToAddressTableRowMapper, BookmarkRowObjectToProgramLocationTableRowMapper,
    ProgramLocation,
};
pub use model::{Bookmark, BookmarkManager, BookmarkRowObject, FilterState};
pub use navigator::{BookmarkMarkerSet, BookmarkNavigator};
pub use plugin::{
    BookmarkActionState, BookmarkPlugin, BookmarkPluginState, BookmarkTransientState,
    CreateBookmarkRequest, NavUpdater, PluginStatus, ProgramEvent,
    TIMER_DELAY, MIN_TIMEOUT, MAX_TIMEOUT,
};
pub use provider::{BookmarkFilterState, BookmarkProviderEntry, BookmarkProviderModel};
pub use table::{BookmarkColumn, BookmarkTableEntry, BookmarkTableModel};
pub use types::BookmarkType;
