//! DWARF External Debug Files -- ported from Ghidra's
//! `ghidra.app.util.bin.format.dwarf.external` Java package.
//!
//! This module provides the infrastructure for locating and managing
//! external DWARF debug files that have been stripped from ELF binaries.
//! When an ELF binary is stripped, its debug information can be stored
//! separately and located via:
//!
//! - `.gnu_debuglink` sections (filename + CRC32)
//! - `.note.gnu.build-id` sections (hash-based lookup via debuginfod)
//!
//! # Architecture
//!
//! The module follows a provider-based architecture:
//!
//! - [`DebugInfoProvider`] -- base trait for all providers
//! - [`DebugFileProvider`] -- provides files from the local filesystem
//! - [`DebugStreamProvider`] -- provides data as byte streams (e.g. HTTP)
//! - [`DebugFileStorage`] -- can store streamed data to local files
//!
//! Concrete providers:
//!
//! - [`SameDirDebugInfoProvider`] -- searches the program's directory
//! - [`LocalDirDebugLinkProvider`] -- recursive directory search
//! - [`LocalDirDebugInfoDProvider`] -- debuginfod-compatible local cache
//! - [`BuildIdDebugFileProvider`] -- build-id based directory lookup
//! - [`HttpDebugInfoDProvider`] -- HTTP debuginfod server client
//! - [`DisabledDebugInfoProvider`] -- wrapper that disables a provider
//!
//! Orchestration:
//!
//! - [`ExternalDebugFilesService`] -- coordinates providers to find debug files
//! - [`DebugInfoProviderRegistry`] -- registry for provider deserialization
//!
//! Data types:
//!
//! - [`ExternalDebugInfo`] -- metadata for locating debug files
//! - [`ObjectType`] -- type of debug object (debuginfo, executable, source)
//! - [`DebugInfoProviderStatus`] -- provider status (valid, invalid, unknown)

pub mod build_id_debug_file_provider;
pub mod debug_info_provider;
pub mod debug_info_provider_registry;
pub mod debug_info_provider_status;
pub mod disabled_debug_info_provider;
pub mod dwarf_external_debug_files_plugin;
pub mod external_debug_files_service;
pub mod external_debug_info;
pub mod http_debuginfo_d_provider;
pub mod local_dir_debug_info_d_provider;
pub mod local_dir_debug_link_provider;
pub mod object_type;
pub mod same_dir_debug_info_provider;

// Re-export core traits
pub use debug_info_provider::{
    DebugFileProvider, DebugFileStorage, DebugInfoProvider, DebugProviderError,
    DebugProviderResult, DebugStreamProvider, StreamInfo,
};
pub use debug_info_provider_registry::{DebugInfoProviderCreatorContext, DebugInfoProviderRegistry};
pub use debug_info_provider_status::DebugInfoProviderStatus;

// Re-export data types
pub use external_debug_info::ExternalDebugInfo;
pub use object_type::ObjectType;

// Re-export concrete providers
pub use build_id_debug_file_provider::BuildIdDebugFileProvider;
pub use disabled_debug_info_provider::DisabledDebugInfoProvider;
pub use http_debuginfo_d_provider::HttpDebugInfoDProvider;
pub use local_dir_debug_info_d_provider::LocalDirDebugInfoDProvider;
pub use local_dir_debug_link_provider::LocalDirDebugLinkProvider;
pub use same_dir_debug_info_provider::SameDirDebugInfoProvider;

// Re-export orchestration
pub use dwarf_external_debug_files_plugin::DWARFExternalDebugFilesPlugin;
pub use external_debug_files_service::ExternalDebugFilesService;
