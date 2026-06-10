//! Android APK virtual filesystem and browser handler modules.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.apk` package.
//!
//! Covers: APK filesystem (ZIP-based virtual filesystem with APK metadata
//! overlay), and the filesystem browser handler (context-menu actions for
//! APK export and info display).

pub mod apk_file_system;
pub mod apk_fsb_file_handler;

// Re-exports
pub use apk_file_system::ApkFileSystem;
pub use apk_fsb_file_handler::{ApkFSBFileHandler, EclipseProjectMetadata, ExportError};
