//! Label management for Ghidra programs.
//!
//! This module ports Ghidra's `ghidra.app.plugin.core.label` Java package
//! to Rust. It provides:
//!
//! - [`LabelManager`] -- core label operations (add, edit, remove, history)
//! - [`LabelAction`] -- enum of available label management actions
//! - [`LabelActionContext`] -- context for determining action enablement
//! - [`LabelHistoryEntry`] / [`LabelHistoryTableModel`] -- label history display
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
pub mod dialogs;
pub mod history;
pub mod operand_label;
pub mod plugin;

pub use actions::{
    is_add_label_enabled, is_edit_label_enabled, is_label_history_enabled,
    is_remove_label_enabled, LabelAction, LabelActionContext,
};
pub use dialogs::{
    EditExternalLabelAction, LabelHistoryInputDialog, LabelHistoryPanel, LabelHistoryTask,
    SymbolChooserDialog,
};
pub use history::{
    LabelHistoryAction, LabelHistoryColumn, LabelHistoryEntry, LabelHistoryListener,
    LabelHistoryTableModel,
};
pub use plugin::{LabelHistoryAction as PluginHistoryAction, LabelManager};
