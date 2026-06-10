//! Android OAT format modules.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.oat` package.
//!
//! Covers: OAT file headers (versions 064-206), DEX file descriptors,
//! compiled class metadata, and compiled method metadata.

pub mod oat_class;
pub mod oat_dex_file;
pub mod oat_header;
pub mod oat_method;

// Re-exports
pub use oat_class::{OatClass, OatClassStatus, OatClassType};
pub use oat_dex_file::OatDexFile;
pub use oat_header::{
    is_oat, is_supported_version, parse_oat_header, InstructionSet, OatHeaderVersion,
    OAT_ISA_ARM, OAT_ISA_ARM_64, OAT_ISA_MIPS, OAT_ISA_MIPS_64, OAT_ISA_NONE, OAT_ISA_THUMB2,
    OAT_ISA_X86, OAT_ISA_X86_64, OAT_MAGIC, OAT_VERSION_064, OAT_VERSION_065, OAT_VERSION_079,
    OAT_VERSION_088, OAT_VERSION_124, OAT_VERSION_131, OAT_VERSION_138, OAT_VERSION_170,
    OAT_VERSION_183, OAT_VERSION_195, OAT_VERSION_199, OAT_VERSION_206, SUPPORTED_VERSIONS,
};
pub use oat_method::OatMethod;
