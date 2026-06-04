//! Rename operations for Ghidra programs.
//!
//! This module ports Ghidra's rename functionality from
//! `ghidra.app.plugin.core` to Rust. It provides commands and plugin
//! logic for renaming labels, functions, namespaces, and moving symbols
//! between namespaces.
//!
//! - [`RenameAction`] -- enum of available rename actions
//! - [`RenameActionContext`] -- context carrying address/symbol information
//! - [`RenamePlugin`] -- controller providing action enablement and command creation
//! - Commands: [`RenameLabelCmd`], [`RenameFunctionCmd`],
//!   [`RenameNamespaceCmd`], [`SetNamespaceCmd`], [`RenameAndMoveCmd`],
//!   [`SetLabelPrimaryCmd`]
//! - Validation: [`validate_symbol_name`], [`is_default_label_name`],
//!   [`is_default_function_name`]
//!
//! # Architecture
//!
//! The module separates validation and command objects ([`cmd`]) from
//! action dispatching and enablement logic ([`plugin`]). GUI dialogs
//! are not ported; the plugin provides methods that return command
//! objects suitable for execution by any frontend.

pub mod cmd;
pub mod plugin;

pub use cmd::{
    is_default_function_name, is_default_label_name, validate_symbol_name, RenameAndMoveCmd,
    RenameFunctionCmd, RenameLabelCmd, RenameNamespaceCmd, SetLabelPrimaryCmd, SetNamespaceCmd,
    MAX_SYMBOL_NAME_LENGTH,
};
pub use plugin::{RenameAction, RenameActionContext, RenamePlugin};
