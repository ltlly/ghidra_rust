//! XCOFF section header names ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffSectionHeaderNames`.
//!
//! Provides the names of "special" XCOFF sections.

/// Executable code section.
pub const TEXT: &str = ".text";

/// Initialized data section.
pub const DATA: &str = ".data";

/// Uninitialized data (BSS) section.
pub const BSS: &str = ".bss";

/// Padding section.
pub const PAD: &str = ".pad";

/// Loader information section.
pub const LOADER: &str = ".loader";

/// Debug information section.
pub const DEBUG: &str = ".debug";

/// Type-checking section.
pub const TYPCHK: &str = ".typchk";

/// Exception information section.
pub const EXCEPT: &str = ".except";

/// Overflow section.
pub const OVRFLO: &str = ".ovrflo";

/// Comment information section.
pub const INFO: &str = ".info";
