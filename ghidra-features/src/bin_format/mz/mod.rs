//! DOS MZ executable format ported from Ghidra's `ghidra.app.util.bin.format.mz`.
//!
//! Provides types for parsing old-style DOS MZ executables:
//! - [`OldDOSHeader`] -- 14-word DOS header (28 bytes)
//! - [`DOSHeader`] -- full IMAGE_DOS_HEADER (64 bytes) with e_lfanew
//! - [`MzRelocation`] -- segment:offset relocation entry
//! - [`MzExecutable`] -- complete MZ executable with header and relocations

pub mod dos_header;
pub mod mz_executable;
pub mod mz_relocation;
pub mod old_dos_header;

pub use dos_header::DOSHeader;
pub use mz_executable::MzExecutable;
pub use mz_relocation::MzRelocation;
pub use old_dos_header::{OldDOSHeader, IMAGE_DOS_SIGNATURE};
