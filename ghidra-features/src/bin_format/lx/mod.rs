//! LX (Linear Executable) format stub ported from Ghidra's
//! `ghidra.app.util.bin.format.lx` package.
//!
//! NOTE: This module is not fully implemented in the upstream Java source.
//! It provides only the magic number constant for LX executable identification.

/// Magic number for LX executables: "LX" (0x584C).
pub const IMAGE_LX_SIGNATURE: u16 = 0x584C;
