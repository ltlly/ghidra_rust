//! UNIX a.out executable format ported from Ghidra's
//! `ghidra.app.util.bin.format.unixaout`.
//!
//! Provides types for parsing UNIX a.out executables:
//! - [`machine_type`] -- machine ID constants and language spec lookup
//! - [`UnixAoutRelocation`] -- relocation entry with bitfield parsing
//! - [`UnixAoutSymbol`] -- symbol table entry with type/kind classification
//! - [`UnixAoutSymbolTable`] -- parsed symbol table with string resolution
//! - [`UnixAoutRelocationTable`] -- parsed relocation table

pub mod machine_type;
pub mod relocation;
pub mod relocation_table;
pub mod symbol;
pub mod symbol_table;

pub use relocation::UnixAoutRelocation;
pub use relocation_table::UnixAoutRelocationTable;
pub use symbol::{SymbolKind, SymbolType, UnixAoutSymbol};
pub use symbol_table::UnixAoutSymbolTable;
