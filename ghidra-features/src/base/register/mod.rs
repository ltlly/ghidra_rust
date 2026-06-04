//! Register management subsystem.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.register` Java package.
//!
//! This module provides:
//! - [`RegisterManager`] — manages register value display, selection, and modification
//! - [`RegisterValueRange`] — represents a range of addresses with a specific register value
//! - [`RegisterTree`] — hierarchical tree of registers organized by group
//! - [`RegisterValuesPanel`] — panel for displaying and editing register value ranges
//! - [`RegisterValueDialogModel`] — validation model for the register value dialog
//! - [`SetRegisterValueCmd`] — command to set or clear register values over an address range

mod commands;
mod dialog;
mod manager;
mod tree;
mod value_range;
mod values_panel;

pub use commands::{RegisterCommand, SetRegisterValueCmd};
pub use dialog::{RegisterDialogError, RegisterDialogMode, RegisterValueDialogModel};
pub use manager::RegisterManager;
pub use tree::{RegisterGroupNode, RegisterNode, RegisterTree};
pub use value_range::RegisterValueRange;
pub use values_panel::{RegisterValuesPanel, SortDirection};
