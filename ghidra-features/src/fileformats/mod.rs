//! File format parsers - ELF, PE/COFF, Mach-O, DEX, APK, Java class,
//! ZIP, ISO 9660, XBE, Intel HEX, Motorola S-Records, COFF, DOS MZ, PEF,
//! and raw binary.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format` package.
//!
//! Each sub-module provides a `parse_*` entry-point that takes a `&[u8]`
//! blob and returns a structured representation of the binary file.

pub mod android;
pub mod apk;
pub mod bplist;
pub mod cart;
pub mod classfile;
pub mod coff;
pub mod coff_file;
pub mod cpio;
pub mod cramfs;
pub mod dex;
pub mod dtb;
pub mod dump;
pub mod elf;
pub mod ext4;
pub mod gzip;
pub mod intel_hex;
pub mod ios;
pub mod iso;
pub mod lzfse;
pub mod lzss;
pub mod macho;
pub mod mz;
pub mod nintendo;
pub mod omf;
pub mod omf51;
pub mod pe;
pub mod pe_full;
pub mod pef;
pub mod raw;
pub mod sevenzip;
pub mod sparse_image;
pub mod srec;
pub mod squashfs;
pub mod tar;
pub mod xar;
pub mod xbe;
pub mod yaffs2;
pub mod zip;
pub mod zlib;
pub mod zstd;

// Re-export BinaryLoader structs for each format.
pub use macho::MachOLoader;
pub use raw::RawBinaryLoader;
pub use zip::ZipLoader;
pub use iso::IsoLoader;
pub use apk::ApkLoader;
pub use dex::DexLoader;
pub use classfile::JavaClassLoader;
