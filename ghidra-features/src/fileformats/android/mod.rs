//! Android-specific file format parsers.
//!
//! Ported from Ghidra's `ghidra.file.formats.android` package.
//!
//! Covers: DEX, OAT, VDEX, ART, boot image, boot loader, APEX,
//! FBPK, LZ4, profiler, and other Android runtime formats.

pub mod art;
pub mod bootimg;
pub mod dex_class_def;
pub mod dex_field;
pub mod dex_format;
pub mod dex_header;
pub mod dex_method;
pub mod dex_string;
pub mod dex_type;
pub mod oat;
pub mod vdex;

// Re-exports
pub use bootimg::AndroidBootImage;
pub use dex_class_def::{ClassDataItem, ClassDefItem, EncodedClassField, EncodedClassMethod};
pub use dex_field::{EncodedField, FieldIDItem};
pub use dex_format::DexHeader;
pub use dex_method::{CodeItem, EncodedMethod, MethodIDItem};
pub use dex_string::{StringDataItem, StringIDItem};
pub use dex_type::{ProtoIDItem, TypeIDItem, TypeItem, TypeList};
pub use oat::{is_oat, OatHeaderVersion, OatMethod};
pub use vdex::VdexHeader;
