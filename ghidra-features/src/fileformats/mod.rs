//! File format parsers - ELF, PE/COFF, Mach-O, DEX, APK, Java class,
//! ZIP, ISO 9660, XBE, and raw binary.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format` package.
//!
//! Each sub-module provides a `parse_*` entry-point that takes a `&[u8]`
//! blob and returns a structured representation of the binary file.

pub mod apk;
pub mod classfile;
pub mod dex;
pub mod elf;
pub mod iso;
pub mod macho;
pub mod nintendo;
pub mod pe;
pub mod pe_full;
pub mod raw;
pub mod xbe;
pub mod zip;

// Re-export BinaryLoader structs for each format.
pub use macho::MachOLoader;
pub use raw::RawBinaryLoader;
pub use zip::ZipLoader;
pub use iso::IsoLoader;
pub use apk::ApkLoader;
pub use dex::DexLoader;
pub use classfile::JavaClassLoader;
