//! PDB Symbol base types.
//!
//! This module provides the foundational types and traits for PDB symbol
//! records, ported from Ghidra's Java implementation under
//! `ghidra.app.util.bin.format.pdb2.pdbreader.symbol` and
//! `ghidra.app.util.bin.format.pdb2.pdbreader`.
//!
//! # Contents
//!
//! - [`AbstractMsSymbol`] — Base trait for all PDB symbol types.
//! - [`AddressMsSymbol`] — Trait for symbols that carry a segment:offset address.
//! - [`NameMsSymbol`] — Trait for symbols that have a name.
//! - [`DataSymbolInternals`] — Shared internal fields for data symbol variants.
//! - [`RecordNumber`] — Typed wrapper for PDB record indices (type/item).
//! - [`Numeric`] — MSFT Numeric value type for variable-length encoded numbers.
//! - [`StringParseType`] — Enum selecting how symbol name strings are parsed.

pub mod abstract_ms_symbol;
pub mod address_ms_symbol;
pub mod data_symbol_internals;
pub mod name_ms_symbol;
pub mod numeric;
pub mod record_number;
pub mod string_parse_type;

// Abstract symbol types ported from Ghidra Java
pub mod abstract_base_pointer_relative;
pub mod abstract_block;
pub mod abstract_compile2;
pub mod abstract_constant;
pub mod abstract_data;

pub use abstract_ms_symbol::{AbstractMsSymbol, UnknownMsSymbol};
pub use address_ms_symbol::AddressMsSymbol;
pub use name_ms_symbol::{NameMsSymbol, NamedSymbol};
pub use data_symbol_internals::DataSymbolInternals;
pub use numeric::{Numeric, NumericValue};
pub use record_number::{RecordCategory, RecordNumber};
pub use string_parse_type::StringParseType;

pub use abstract_base_pointer_relative::AbstractBasePointerRelative;
pub use abstract_block::AbstractBlock;
pub use abstract_compile2::AbstractCompile2;
pub use abstract_constant::AbstractConstant;
pub use abstract_data::AbstractData;
