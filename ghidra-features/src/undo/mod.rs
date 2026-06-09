//! Undo/Redo framework for Ghidra.
//!
//! Ported from Ghidra's undo/redo infrastructure spanning:
//! - `docking.UndoRedoKeeper` -- generic undo/redo stack with style-edit coalescing
//! - `ghidra.framework.plugintool.util.UndoRedoToolState` -- tool-wide state snapshot
//! - `ghidra.app.services.UndoService` -- service interface for undo/redo
//! - `ghidra.app.plugin.core.progmgr.UndoAction` / `RedoAction` -- UI actions
//! - `ghidra.app.plugin.core.progmgr.AbstractUndoRedoAction` -- action base class
//! - `ghidra.app.plugin.core.datamgr.actions.UndoArchiveTransactionAction`
//!
//! # Submodules
//!
//! - [`undo_service`] -- service interface, undo/redo stack, and state types
//! - [`undo_plugin`] -- undo/redo plugin, actions, and event types
//!
//! # Key Types
//!
//! - [`UndoRedoKeeper`] -- manages undo/redo stack with style-edit coalescing
//! - [`UndoService`] -- trait for undo/redo operations
//! - [`UndoPlugin`] -- plugin managing undo/redo actions
//! - [`UndoRedoToolState`] -- snapshot of per-plugin undo/redo state
//! - [`UndoStateInfo`] -- lightweight undo/redo state summary for UI

pub mod undo_service;
pub mod undo_plugin;

pub use undo_service::{
    UndoError, UndoRedoKeeper, UndoRedoToolState, UndoService, UndoStateInfo, UndoableEdit,
};
pub use undo_plugin::{
    RedoAction, RepeatAction, UndoAction, UndoPlugin, UndoRedoPluginEvent, UndoRedoPluginListener,
};
