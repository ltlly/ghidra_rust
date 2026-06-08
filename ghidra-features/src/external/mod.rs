//! External Program Management -- ported from Ghidra's
//! `ghidra.program.database.external`, `ghidra.app.cmd.refs`,
//! `ghidra.app.cmd.label`, `ghidra.app.events`, `ghidra.app.util.xml`,
//! `ghidra.app.plugin.core.analysis`, and
//! `ghidra.app.plugin.core.function` Java packages.
//!
//! # Database-backed external location management
//!
//! - [`ExternalLocationDB`] -- a database-backed external location
//! - [`ExternalManagerDB`] -- the manager for all external references
//! - [`ExternalLocationVecIterator`] / [`FilteredExternalLocationIterator`]
//!   -- iterators over external locations
//! - [`OldExtNameAdapter`] -- legacy "External Program Names" table adapter
//! - [`OldExtRefAdapter`] -- legacy "External References" table adapter
//!
//! # Commands
//!
//! - [`CreateExternalFunctionCmd`] -- command for creating external functions
//! - [`AddExternalNameCmd`] -- command for adding an external program name
//! - [`RemoveExternalNameCmd`] -- command for removing an external program name
//! - [`UpdateExternalNameCmd`] -- command for updating an external program name
//! - [`ExternalEntryCmd`] -- command for setting/unsetting external entry points
//!
//! # Plugin events
//!
//! - [`ExternalReferencePluginEvent`] -- navigate to external references
//! - [`ExternalProgramLocationPluginEvent`] -- external program location change
//! - [`ExternalProgramSelectionPluginEvent`] -- external program selection change
//!
//! # Analyzers
//!
//! - [`ExternalSymbolResolverAnalyzer`] -- analyzer for linking unresolved external symbols
//! - [`ExternalSymbolResolver`] -- resolver that matches symbols to library exports
//! - [`ExternalEntryFunctionAnalyzer`] -- analyzer for creating functions at external entry points
//!
//! # XML serialization
//!
//! - [`ExternalLibXmlMgr`] -- XML manager for external library table
//! - [`ExternalLibEntry`] -- a single external library entry
//!
//! # Traits
//!
//! - [`ExternalManager`] trait re-export for use by the rest of the crate
//! - [`ExternalLocation`] trait re-export from ghidra-core
//!
//! # DWARF external debug files (sub-module [`dwarf_ext`])
//!
//! The [`dwarf_ext`] module provides the infrastructure for locating and
//! managing external DWARF debug files stripped from ELF binaries,
//! including debuginfod HTTP providers and local cache management.
//!
//! External locations represent symbols (functions or data) imported from
//! external libraries.

pub mod add_external_name_cmd;
pub mod clear_external_path_cmd;
pub mod create_external_function_cmd;
pub mod create_external_location_action;
pub mod dwarf_ext;
pub mod edit_external_location_action;
pub mod external_call_node;
pub mod external_debug_file_symbol_importer;
pub mod external_entry_cmd;
pub mod external_entry_function_analyzer;
pub mod external_lib_xml_mgr;
pub mod external_location_db;
pub mod external_location_iterator;
pub mod external_manager_db;
pub mod external_reference_event;
pub mod external_references_provider;
pub mod external_symbol_resolver;
pub mod external_symbol_resolver_analyzer;
pub mod externals_address_translator;
pub mod go_to_external_location_action;
pub mod old_ext_name_adapter;
pub mod old_ext_ref_adapter;
pub mod remove_external_name_cmd;
pub mod remove_external_ref_cmd;
pub mod set_external_name_cmd;
pub mod set_external_program_action;
pub mod set_external_ref_cmd;
pub mod update_external_name_cmd;

pub use add_external_name_cmd::AddExternalNameCmd;
pub use clear_external_path_cmd::ClearExternalPathCmd;
pub use create_external_function_cmd::CreateExternalFunctionCmd;
pub use create_external_location_action::CreateExternalLocationAction;
pub use edit_external_location_action::EditExternalLocationAction;
pub use external_call_node::ExternalCallNode;
pub use external_debug_file_symbol_importer::ExternalDebugFileSymbolImporter;
pub use external_entry_cmd::{ExternalEntryPointManager, ExternalEntryPointTable, ExternalEntryCmd};
pub use external_entry_function_analyzer::{
    ExternalEntryFunctionAnalyzer, FunctionStartDatabase, InstructionInfo,
};
pub use external_lib_xml_mgr::{ExternalLibEntry, ExternalLibXmlMgr};
pub use external_location_db::ExternalLocationDB;
pub use external_location_iterator::{
    ExternalLocationIterator, ExternalLocationVecIterator, FilteredExternalLocationIterator,
};
pub use external_manager_db::{ExternalManagerDB, UNKNOWN_LIBRARY};
pub use external_reference_event::{
    ExternalProgramLocationPluginEvent, ExternalProgramSelectionPluginEvent,
    ExternalReferencePluginEvent,
};
pub use external_references_provider::{
    ExternalNamesRow, ExternalReferencesError, ExternalReferencesProvider,
};
pub use external_symbol_resolver::{
    ExtLibInfo, LibraryExportTable, LibraryResolutionDetail, ProgramSymbolResolver,
    ProgramSymbolTable, ResolutionResult,
};
// Note: external_symbol_resolver::ExternalSymbolResolver and
// external_symbol_resolver_analyzer::ExternalSymbolResolver share the
// same name -- re-export the analyzer version under its original name,
// and leave the resolver version accessible via the module path.
pub use external_symbol_resolver_analyzer::{
    ExecutableFormat, ExternalSymbolResolverAnalyzer, ProblemLibrary,
    ResolvedSymbol, UnresolvedSymbol,
};
pub use externals_address_translator::{AddressTranslationError, ExternalsAddressTranslator};
pub use go_to_external_location_action::{
    GoToExternalLocationAction, GoToExternalError, NavigationTarget,
};
pub use old_ext_name_adapter::OldExtNameAdapter;
pub use old_ext_ref_adapter::OldExtRefAdapter;
pub use remove_external_name_cmd::RemoveExternalNameCmd;
pub use remove_external_ref_cmd::RemoveExternalRefCmd;
pub use set_external_name_cmd::SetExternalNameCmd;
pub use set_external_program_action::SetExternalProgramAction;
pub use set_external_ref_cmd::{ExternalRefType, SetExternalRefCmd};
pub use update_external_name_cmd::UpdateExternalNameCmd;

// Re-export traits from ghidra-core
pub use ghidra_core::symbol::ExternalLocation;
pub use ghidra_core::symbol::ExternalManager;
