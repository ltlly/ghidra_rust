//! File format parsers - ELF, PE/COFF, Mach-O, DEX, APK, Java class, and raw binary.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format` package.
//!
//! Each sub-module provides a `parse_*` entry-point that takes a `&[u8]`
//! blob and returns a structured representation of the binary file.

pub mod apk;
pub mod classfile;
pub mod dex;
pub mod elf;
pub mod macho;
pub mod pe;
pub mod pe_full;
pub mod raw;
