//! Android-specific file format parsers.
//!
//! Ported from Ghidra's `ghidra.file.formats.android` package.
//!
//! Covers: DEX, OAT, VDEX, ART, boot image, boot loader, APEX,
//! FBPK, LZ4, profiler, and other Android runtime formats.

pub mod bootimg;
pub mod dex_format;
pub mod oat;
pub mod vdex;

// Re-exports
pub use bootimg::AndroidBootImage;
pub use dex_format::DexHeader;
pub use oat::OatHeader;
pub use vdex::VdexHeader;
