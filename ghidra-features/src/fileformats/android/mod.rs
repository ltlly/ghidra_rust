//! Android-specific file format parsers.
//!
//! Ported from Ghidra's `ghidra.file.formats.android` package.
//!
//! Covers: DEX, OAT, VDEX, ART, boot image, boot loader, APEX,
//! FBPK, LZ4, profiler, and other Android runtime formats.

pub mod bootimg;
pub mod dex_class_def;
pub mod dex_format;
pub mod dex_header;
pub mod dex_method;
pub mod oat;
pub mod vdex;

// Re-exports
pub use bootimg::AndroidBootImage;
pub use dex_class_def::{ClassDataItem, ClassDefItem, EncodedClassField, EncodedClassMethod};
pub use dex_format::DexHeader;
pub use dex_method::{CodeItem, EncodedMethod, MethodIDItem};
pub use oat::OatHeader;
pub use vdex::VdexHeader;
