//! XCOFF (Extended Common Object File Format) ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff` package.
//!
//! Provides types for parsing XCOFF object files and archives used on
//! IBM AIX systems:
//! - [`XCoffFileHeader`] -- XCOFF file header (32-bit and 64-bit)
//! - [`XCoffOptionalHeader`] -- XCOFF optional header
//! - [`XCoffSectionHeader`] -- XCOFF section header
//! - [`XCoffSymbol`] -- XCOFF symbol table entry
//! - [`XCoffArchiveHeader`] -- XCOFF big archive header
//! - [`XCoffArchiveMemberHeader`] -- XCOFF archive member header
//! - [`XCoffException`] -- error type for XCOFF parsing
//! - [`xcoff_file_header_magic`] -- magic number constants and helpers
//! - [`xcoff_file_header_flags`] -- file header flag constants
//! - [`xcoff_section_header_flags`] -- section header flag constants
//! - [`xcoff_section_header_names`] -- well-known section names
//! - [`xcoff_symbol_storage_class`] -- symbol storage class constants
//! - [`xcoff_symbol_storage_class_csect`] -- csect storage mapping class constants
//! - [`xcoff_archive_constants`] -- archive magic constants

pub mod xcoff_archive_constants;
pub mod xcoff_archive_header;
pub mod xcoff_archive_member_header;
pub mod xcoff_exception;
pub mod xcoff_file_header;
pub mod xcoff_file_header_flags;
pub mod xcoff_file_header_magic;
pub mod xcoff_optional_header;
pub mod xcoff_section_header;
pub mod xcoff_section_header_flags;
pub mod xcoff_section_header_names;
pub mod xcoff_symbol;
pub mod xcoff_symbol_storage_class;
pub mod xcoff_symbol_storage_class_csect;

pub use xcoff_archive_header::XCoffArchiveHeader;
pub use xcoff_archive_member_header::XCoffArchiveMemberHeader;
pub use xcoff_exception::XCoffException;
pub use xcoff_file_header::XCoffFileHeader;
pub use xcoff_optional_header::XCoffOptionalHeader;
pub use xcoff_section_header::XCoffSectionHeader;
pub use xcoff_symbol::XCoffSymbol;
