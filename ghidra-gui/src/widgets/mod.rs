//! Docking widget library ported from Ghidra's Java Swing components to egui.
//!
//! This module provides Rust equivalents of Ghidra's `docking.widgets` package,
//! adapted for the egui immediate-mode GUI paradigm.
//!
//! # Submodules
//!
//! - **[`table`]** — Table model traits, filter models, sort state, and the
//!   filter-table composite widget. Ports `docking.widgets.table`.
//!
//! - **[`auto_lookup`]** — Type-ahead lookup for row-based widgets.
//!   Ports `docking.widgets.AutoLookup`.
//!
//! - **[`option_dialog`]** — Modal option/confirmation dialogs.
//!   Ports `docking.widgets.OptionDialog`.
//!
//! - **[`find_dialog`]** — Find/search dialog with string and regex modes.
//!   Ports `docking.widgets.FindDialog`.

pub mod table;
pub mod auto_lookup;
pub mod option_dialog;
pub mod find_dialog;

// Re-export key types at the widgets module level.
pub use auto_lookup::AutoLookup;
pub use find_dialog::{FindDialog, FindMode};
pub use option_dialog::{DialogResult, MessageType, OptionDialog};
pub use table::{
    ColumnSortState, GFilterTable, RowObjectFilterModel, RowObjectTableModel, SortDirection,
    TableFilter, TableSortState,
};
