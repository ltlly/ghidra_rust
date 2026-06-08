//! Table model traits, filter models, sort state, and filter-table widget.
//!
//! Port of Ghidra's `docking.widgets.table` package for egui.
//!
//! # Architecture
//!
//! The Java Swing table model hierarchy is replaced by a set of Rust traits:
//!
//! - [`RowObjectTableModel`] — core trait for models where each row maps to a
//!   typed row object.
//! - [`TableFilter`] — predicate over row objects used for filtering.
//! - [`RowObjectFilterModel`] — extends the table model with filtering support.
//! - [`AbstractGTableModel`] — a concrete base implementing common logic.
//!
//! Sort state is captured by [`ColumnSortState`] and [`TableSortState`].
//!
//! The composite [`GFilterTable`] widget combines a table view with a filter
//! text field, mirroring Ghidra's `GFilterTable` / `GTableFilterPanel`.

mod row_object_table_model;
mod table_filter;
mod row_object_filter_model;
mod abstract_g_table_model;
mod column_sort_state;
mod table_sort_state;
mod g_filter_table;

pub use row_object_table_model::RowObjectTableModel;
pub use table_filter::TableFilter;
pub use row_object_filter_model::RowObjectFilterModel;
pub use abstract_g_table_model::AbstractGTableModel;
pub use column_sort_state::{ColumnSortState, SortDirection};
pub use table_sort_state::TableSortState;
pub use g_filter_table::GFilterTable;
