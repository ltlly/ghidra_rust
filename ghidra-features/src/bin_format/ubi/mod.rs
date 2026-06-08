//! Universal Binary Image (UBI / Fat Binary) format ported from Ghidra's
//! `ghidra.app.util.bin.format.ubi` package.
//!
//! Provides types for parsing Mach-O Universal Binary (fat) headers:
//! - [`FatHeader`] -- fat_header structure containing multiple architectures
//! - [`FatArch`] -- fat_arch structure describing one architecture slice
//! - [`UbiException`] -- error for invalid UBI headers
//!
//! A Mach-O Universal Binary (also called a "fat binary") contains one or more
//! Mach-O object files for different CPU architectures. The fat header is always
//! stored in big-endian byte order.
//!
//! See: <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/fat.h>

pub mod fat_arch;
pub mod fat_header;
pub mod ubi_exception;

pub use fat_arch::{cpu_types, FatArch, SIZEOF_FAT_ARCH};
pub use fat_header::{FatHeader, FAT_CIGAM, FAT_MAGIC};
pub use ubi_exception::UbiException;
