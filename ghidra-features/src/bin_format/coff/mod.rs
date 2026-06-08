//! COFF (Common Object File Format) ported from Ghidra's
//! `ghidra.app.util.bin.format.coff` package.
//!
//! Provides types for parsing COFF object files and archives:
//! - [`CoffFileHeader`] -- COFF file header
//! - [`CoffSectionHeader`] -- COFF section header with relocations and line numbers
//! - [`CoffRelocation`] -- COFF relocation entry
//! - [`CoffLineNumber`] -- COFF line number entry
//! - [`CoffSymbol`] -- COFF symbol table entry
//! - [`CoffException`] -- error type for COFF parsing
//! - [`coff_machine_type`] -- machine type constants and utilities
//! - [`coff_constants`] -- field size constants
//! - [`coff_section_header_flags`] -- section header flag constants
//! - [`coff_section_header_reserved`] -- section header reserved field constants
//! - [`coff_symbol_type`] -- symbol type constants
//! - [`coff_symbol_storage_class`] -- symbol storage class constants
//! - [`coff_symbol_section_number`] -- symbol section number constants
//! - [`archive`] -- COFF archive (.lib / .ar) parsing

pub mod archive;
pub mod coff_constants;
pub mod coff_exception;
pub mod coff_file_header;
pub mod coff_line_number;
pub mod coff_machine_type;
pub mod coff_relocation;
pub mod coff_section_header;
pub mod coff_section_header_flags;
pub mod coff_section_header_reserved;
pub mod coff_symbol;
pub mod coff_symbol_section_number;
pub mod coff_symbol_storage_class;
pub mod coff_symbol_type;

pub use coff_exception::CoffException;
pub use coff_file_header::CoffFileHeader;
pub use coff_line_number::CoffLineNumber;
pub use coff_relocation::CoffRelocation;
pub use coff_section_header::CoffSectionHeader;
pub use coff_symbol::CoffSymbol;
