//! XCOFF section header flags ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffSectionHeaderFlags`.
//!
//! Provides constants for the `s_flags` field of an XCOFF section header.

/// Section is a padding section.
pub const STYP_PAD: u32 = 0x0008;

/// Section contains executable code.
pub const STYP_TEXT: u32 = 0x0020;

/// Section contains initialized data.
pub const STYP_DATA: u32 = 0x0040;

/// Section contains uninitialized data (BSS).
pub const STYP_BSS: u32 = 0x0080;

/// Section contains exception information.
pub const STYP_EXCEPT: u32 = 0x0080;

/// Section contains comment information.
pub const STYP_INFO: u32 = 0x0200;

/// Section contains loader information.
pub const STYP_LOADER: u32 = 0x1000;

/// Section contains debug information.
pub const STYP_DEBUG: u32 = 0x2000;

/// Section contains type-checking information.
pub const STYP_TYPCHK: u32 = 0x4000;

/// Section is an overflow section.
pub const STYP_OVRFLO: u32 = 0x8000;
