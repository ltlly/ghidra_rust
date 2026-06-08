//! XCOFF file header magic numbers ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffFileHeaderMagic`.
//!
//! Provides constants for XCOFF32 and XCOFF64 magic values and helper
//! functions to test the bit-width of an XCOFF file from its magic number.

use super::xcoff_file_header::XCoffFileHeader;

/// XCOFF32 magic number.
pub const MAGIC_XCOFF32: u16 = 0x01DF;

/// XCOFF64 magic number (discontinued AIX format).
pub const MAGIC_XCOFF64_OLD: u16 = 0x01EF;

/// XCOFF64 magic number.
pub const MAGIC_XCOFF64: u16 = 0x01F7;

/// Returns `true` if the given magic value matches any known XCOFF variant.
pub fn is_match(magic: u16) -> bool {
    magic == MAGIC_XCOFF32 || magic == MAGIC_XCOFF64_OLD || magic == MAGIC_XCOFF64
}

/// Returns `true` if the header represents an XCOFF32 file.
pub fn is_32bit(header: &XCoffFileHeader) -> bool {
    header.f_magic == MAGIC_XCOFF32
}

/// Returns `true` if the header represents an XCOFF64 file.
pub fn is_64bit(header: &XCoffFileHeader) -> bool {
    header.f_magic == MAGIC_XCOFF64_OLD || header.f_magic == MAGIC_XCOFF64
}
