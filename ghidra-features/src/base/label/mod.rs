//! Label management for Ghidra programs.
//!
//! This module ports Ghidra's `ghidra.app.plugin.core.label` Java package
//! to Rust. It provides:
//!
//! - [`LabelManager`] -- core label operations (add, edit, remove, history)
//! - [`LabelPlugin`] -- full plugin with action registration and callbacks
//! - [`LabelAction`] -- enum of available label management actions
//! - [`LabelActionContext`] -- context for determining action enablement
//! - [`LabelHistoryEntry`] / [`LabelHistoryTableModel`] -- label history display
//! - [`LabelHistoryDialog`] -- dialog for displaying label history
//! - [`AllHistoryAction`] -- action for searching all label history
//! - [`AddEditDialog`] -- dialog for adding/editing labels
//! - [`LabelDialogResult`] -- result of confirming the add/edit dialog
//! - Action enablement functions matching Ghidra's `isEnabledForContext`
//!
//! # Architecture
//!
//! The module separates core business logic ([`LabelManager`]) from
//! action enablement logic ([`actions`] module) and display models
//! ([`history`] module). This mirrors Ghidra's separation between the
//! plugin, its actions, and the table model.
//!
//! GUI-specific code (dialogs, Swing components) is not ported; instead,
//! the module provides trait-based abstractions that can be implemented
//! by any frontend.

pub mod actions;
pub mod all_history_action;
pub mod dialogs;
pub mod history;
pub mod label_dialog;
pub mod label_history_dialog;
pub mod label_plugin;
pub mod operand_label;
pub mod plugin;

pub use actions::{
    is_add_label_enabled, is_edit_label_enabled, is_label_history_enabled, is_remove_label_enabled,
    LabelAction, LabelActionContext,
};
pub use all_history_action::AllHistoryAction;
pub use dialogs::{
    EditExternalLabelAction, LabelHistoryInputDialog, LabelHistoryPanel, LabelHistoryTask,
    SymbolChooserDialog,
};
pub use label_dialog::{
    AddEditDialog, LabelDialogMode, LabelDialogResult, NamespaceCache, NamespaceOption,
};
pub use history::{
    LabelHistoryAction, LabelHistoryColumn, LabelHistoryEntry, LabelHistoryListener,
    LabelHistoryTableModel,
};
pub use label_history_dialog::LabelHistoryDialog;
pub use label_plugin::{
    LabelPlugin, ListingContext, ListingFieldType, RegisteredAction, SymbolInfo,
};
pub use plugin::{LabelHistoryAction as PluginHistoryAction, LabelManager};
