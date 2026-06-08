//! GUI components for the DWARF external debug files configuration.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.gui`.
//!
//! This module provides the data model and configuration structures
//! for the DWARF external debug files configuration UI.  The actual
//! Swing rendering is not ported; instead we provide the logical
//! components that can be used by any UI framework.
//!
//! # Components
//!
//! - [`WellKnownDebugProvider`] -- pre-configured debug file search locations
//! - [`ExternalDebugInfoProviderTableRow`] -- represents a row in the provider table
//! - [`ExternalDebugInfoProviderTableModel`] -- table model for provider configuration
//! - [`TableColumnInitializer`] -- trait for initializing table column properties
//! - [`EnumIconColumnRenderer`] -- renders enum values as icons in table cells
//! - [`FilePromptConfig`] -- configuration for file/directory chooser dialogs
//! - [`ExternalDebugFilesConfigDialog`] -- main configuration dialog state

pub mod enum_icon_column_renderer;
pub mod external_debug_files_config_dialog;
pub mod external_debug_info_provider_table_model;
pub mod external_debug_info_provider_table_row;
pub mod file_prompt_dialog;
pub mod table_column_initializer;
pub mod well_known_debug_provider;

pub use enum_icon_column_renderer::{EnumIconColumnRenderer, IconDescriptor};
pub use external_debug_files_config_dialog::{
    AddLocationMenuEntry, AddLocationType, ConfigDialogAction, ConfigDialogState,
};
pub use external_debug_info_provider_table_model::{ColumnIndex, ExternalDebugInfoProviderTableModel};
pub use external_debug_info_provider_table_row::ExternalDebugInfoProviderTableRow;
pub use file_prompt_dialog::{FileChooserMode, FilePromptConfig, FilePromptResult};
pub use table_column_initializer::{FontMetrics, TableColumnInitializer, TableColumnProperties};
pub use well_known_debug_provider::WellKnownDebugProvider;
