//! XCOFF archive constants ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffArchiveConstants`.
//!
//! Provides the magic string for XCOFF big archive files.

/// Archive magic string for XCOFF big archive format.
pub const MAGIC: &str = "<bigaf>\n";

/// Length of the archive magic string in bytes.
pub const MAGIC_LENGTH: usize = 8;
