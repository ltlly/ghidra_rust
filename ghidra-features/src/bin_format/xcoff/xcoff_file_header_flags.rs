//! XCOFF file header flags ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffFileHeaderFlags`.
//!
//! Provides flag constants and helper predicates for the `f_flags` field
//! of an XCOFF file header.

use super::xcoff_file_header::XCoffFileHeader;

/// Relocation info stripped from file.
pub const F_RELFLG: u16 = 0x0001;

/// File is executable (no unresolved external references).
pub const F_EXEC: u16 = 0x0002;

/// Line numbers stripped from file.
pub const F_LNNO: u16 = 0x0004;

/// Local symbols stripped from file.
pub const F_LSYMS: u16 = 0x0008;

/// File was profiled with fdpr command.
pub const F_FDPR_PROF: u16 = 0x0010;

/// File was reordered with fdpr command.
pub const F_FDPR_OPTI: u16 = 0x0020;

/// File uses Very Large Program Support.
pub const F_DSA: u16 = 0x0040;

/// File is 16-bit little-endian.
pub const F_AR16WR: u16 = 0x0080;

/// File is 32-bit little-endian.
pub const F_AR32WR: u16 = 0x0100;

/// File is 32-bit big-endian.
pub const F_AR32W: u16 = 0x0200;

/// RS/6000 AIX: dynamically loadable with imports and exports.
pub const F_DYNLOAD: u16 = 0x1000;

/// RS/6000 AIX: file is a shared object.
pub const F_SHROBJ: u16 = 0x2000;

/// RS/6000 AIX: if the object file is a member of an archive it can be loaded
/// by the system loader but the member is ignored by the binder.
pub const F_LOADONLY: u16 = 0x4000;

/// Returns `true` if relocation info has been stripped from the file.
pub fn is_strip(header: &XCoffFileHeader) -> bool {
    (header.f_flags & F_RELFLG) != 0
}

/// Returns `true` if the file is executable.
pub fn is_exec(header: &XCoffFileHeader) -> bool {
    (header.f_flags & F_EXEC) != 0
}

/// Returns `true` if the file contains debug information (line numbers not stripped).
pub fn is_debug(header: &XCoffFileHeader) -> bool {
    (header.f_flags & F_LNNO) == 0
}
