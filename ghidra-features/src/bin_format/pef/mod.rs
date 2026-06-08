//! PEF (Preferred Executable Format) ported from Ghidra's
//! `ghidra.app.util.bin.format.pef`.
//!
//! Apple's classic binary format used on pre-Mac OS X systems (PowerPC and 68k).
//!
//! See Apple's PEFBinaryFormat.h for the original C struct definitions.

pub mod constants;
pub mod container_header;
pub mod exported_symbol;
pub mod exported_symbol_hash_slot;
pub mod exported_symbol_key;
pub mod imported_library;
pub mod imported_symbol;
pub mod loader_info_header;
pub mod loader_relocation_header;
pub mod packed_data_opcodes;
pub mod relocation;
pub mod relocation_factory;
pub mod section_header;
pub mod section_kind;
pub mod section_share_kind;
pub mod symbol_class;

pub use constants::PefConstants;
pub use container_header::ContainerHeader;
pub use exported_symbol::ExportedSymbol;
pub use exported_symbol_hash_slot::ExportedSymbolHashSlot;
pub use exported_symbol_key::ExportedSymbolKey;
pub use imported_library::ImportedLibrary;
pub use imported_symbol::ImportedSymbol;
pub use loader_info_header::LoaderInfoHeader;
pub use loader_relocation_header::LoaderRelocationHeader;
pub use packed_data_opcodes::PackedDataOpcodes;
pub use relocation::Relocation;
pub use relocation_factory::RelocationFactory;
pub use section_header::SectionHeader;
pub use section_kind::SectionKind;
pub use section_share_kind::SectionShareKind;
pub use symbol_class::SymbolClass;
