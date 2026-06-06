//! Table management framework.
//!
//! This module is a port of Ghidra's table management packages:
//!
//! - `ghidra.app.plugin.core.table` -- table component provider and
//!   table service plugin.
//! - `ghidra.app.tablechooser` -- table-chooser dialog, executor,
//!   column display, and row mappers.
//! - `ghidra.app.util.query` -- the `TableService` interface.
//!
//! # Module Structure
//!
//! - [`traits`] -- Core traits: [`AddressableRowObject`],
//!   [`ColumnDisplay`], [`TableChooserExecutor`], [`TableService`].
//! - [`display`] -- Column display implementations:
//!   [`AbstractColumnDisplay`], [`AbstractComparableColumnDisplay`],
//!   [`StringColumnDisplay`].
//! - [`adapter`] -- [`ColumnDisplayDynamicTableColumnAdapter`] that
//!   bridges `ColumnDisplay` to [`DynamicTableColumn`].
//! - [`mapper`] -- Row-object mappers (address, function, program
//!   location).
//! - [`model`] -- [`TableChooserTableModel`] and [`TableSortState`].
//! - [`dialog`] -- [`TableChooserDialog`] and
//!   [`TableServiceTableChooserDialog`].
//! - [`provider`] -- [`TableComponentProvider`] with marker and
//!   navigation support.
//! - [`plugin`] -- [`TableServicePlugin`] managing providers and
//!   dialogs per program.
//! - [`field`] -- Program-location-based table column definitions
//!   (ported from `ghidra.util.table.field`).
//! - [`models`] -- Program-aware table model implementations.
//! - [`render`] -- Cell renderers for table display.

pub mod adapter;
pub mod dialog;
pub mod display;
pub mod mapper;
pub mod model;
pub mod plugin;
pub mod provider;
pub mod traits;

/// Program-location-based table column definitions (61 Java files ported).
pub mod field;

/// Program-aware table model implementations.
pub mod models;

/// Cell renderers for table display.
pub mod render;

// Re-export key types at the module root for convenience.
pub use adapter::{ColumnDisplayDynamicTableColumnAdapter, DynamicTableColumn};
pub use dialog::{DialogState, TableChooserDialog, TableServiceTableChooserDialog};
pub use display::{AbstractColumnDisplay, AbstractComparableColumnDisplay, StringColumnDisplay};
pub use mapper::{
    AddressTableRowMapper, FunctionRef, FunctionTableRowMapper, ProgramLocation,
    ProgramLocationTableRowMapper, RowMapper,
};
pub use model::{SimpleRowObject, SortColumn, TableChooserTableModel, TableSortState};
pub use plugin::{PluginState, TableServicePlugin};
pub use provider::{ComponentProviderState, MarkerSet, TableComponentProvider};
pub use traits::{AddressableRowObject, ColumnDisplay, TableChooserExecutor, TableService};

// Re-export key types from the new sub-modules.
pub use field::core::{AddressBasedLocation, ReferenceEndpoint, IncomingReferenceEndpoint,
    OutgoingReferenceEndpoint, ReferenceAddressPair};
pub use field::traits::{ProgramBasedDynamicTableColumn, ProgramLocationTableColumn,
    Settings, ServiceProvider, ProgramInfo, RefType, SymbolType, SourceType};
pub use field::function_columns::FunctionInfo;
pub use models::{ProgramTableModel, GhidraProgramTableModel, AddressBasedTableModel,
    AddressSetTableModel, IncomingReferencesTableModel, ReferencesFromTableModel};
pub use render::{GhidraTableCellRenderer, CodeUnitTableCellRenderer,
    CompositeGhidraTableCellRenderer, PreviewDataTableCellRenderer, RenderStyle};
