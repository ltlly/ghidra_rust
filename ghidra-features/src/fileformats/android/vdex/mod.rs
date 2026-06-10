//! Android VDEX file format modules.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.vdex` package.
//!
//! Covers: VDEX file headers (versions 006-027), and the analyzer.

pub mod vdex_analyzer;
pub mod vdex_header;

// Re-exports
pub use vdex_analyzer::VdexAnalyzer;
pub use vdex_header::{
    is_supported_version, is_vdex, parse_vdex_header, VdexHeader, VdexHeaderVersion, VDEX_MAGIC,
    VDEX_VERSION_006, VDEX_VERSION_010, VDEX_VERSION_012, VDEX_VERSION_015, VDEX_VERSION_019,
    VDEX_VERSION_021, VDEX_VERSION_023, VDEX_VERSION_027, SUPPORTED_VERSIONS,
};
