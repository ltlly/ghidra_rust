//! DWARF debugging information format support ported from Ghidra's
//! `ghidra.app.util.bin.format.dwarf` package.
//!
//! Currently provides:
//! - [`DwarfChildren`] -- child determination constants (DW_CHILDREN_*)
//! - [`DwarfEncoding`] -- attribute encoding constants (DW_ATE_*)
//! - [`DwarfException`] -- error type for DWARF parsing operations

pub mod dwarf_children;
pub mod dwarf_encoding;
pub mod dwarf_exception;

// Re-export key types for convenience
pub use dwarf_children::DwarfChildren;
pub use dwarf_encoding::DwarfEncoding;
pub use dwarf_exception::DwarfException;
