//! Crash dump format parsers.
//!
//! Ported from Ghidra's `ghidra.file.formats.dump` package.
//!
//! Covers: MiniDump (Windows), Pagedump, Userdump, and Apport (Linux).

pub mod minidump;

// Re-exports
pub use minidump::MinidumpHeader;
