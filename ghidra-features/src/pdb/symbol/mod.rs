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

// Concrete symbol types ported from Ghidra Java
pub mod s_bprel32;
pub mod s_callsite;
pub mod s_callsiteinfo;
pub mod s_coffgroup;
pub mod s_constant;
pub mod s_end;
pub mod s_export;
pub mod s_frameproc;
pub mod s_gdata32;
pub mod s_gproc32;
pub mod s_heapalloca;
pub mod s_label32;
pub mod s_ldata32;
pub mod s_lproc32;
pub mod s_lthread32;
pub mod s_objname;
pub mod s_procref;
pub mod s_pub32;
pub mod s_regrel32;
pub mod s_section;
pub mod s_skip;
pub mod s_thunk32;
pub mod s_trampoline;
pub mod s_udt;

// New symbol types ported from Ghidra Java
pub mod s_defrange_register;
pub mod s_defrange_framepointer;
pub mod s_defrange_subfield;
pub mod s_defrange_register_rel;
pub mod s_local;
pub mod s_inlinesite;

// Additional symbol types ported from Ghidra Java
pub mod s_envblock;
pub mod s_buildinfo;
pub mod s_filestatic;
pub mod s_manframerel;
pub mod s_regframe;
pub mod s_defrange_framepointer_rel;

// IA-64 and namespace symbol types ported from Ghidra Java
pub mod s_unamespace;
pub mod s_gprocia64;
pub mod s_lprocia64;
pub mod s_callsite_info;

// Reference and annotation symbol types ported from Ghidra Java
pub mod s_gprocref;
pub mod s_lprocref;
pub mod s_dataref;
pub mod s_annotation;

// Block, scope, return, and entry symbol types ported from Ghidra Java
pub mod s_block32;
pub mod s_with32;
pub mod s_return;
pub mod s_entrythis;

pub use abstract_base_pointer_relative::AbstractBasePointerRelative;
pub use abstract_block::AbstractBlock;
pub use abstract_compile2::AbstractCompile2;
pub use abstract_constant::AbstractConstant;
pub use abstract_data::AbstractData;

pub use s_bprel32::SBpRel32;
pub use s_callsite::{SCallSite, SIndirectCallSiteInfo};
pub use s_callsiteinfo::SCallSiteInfo;
pub use s_coffgroup::SCoffGroup;
pub use s_constant::SConstant;
pub use s_end::SEnd;
pub use s_export::SExport;
pub use s_frameproc::SFrameProc;
pub use s_gdata32::SGData32;
pub use s_gproc32::SGProc32;
pub use s_heapalloca::SHeapAlloca;
pub use s_label32::SLabel32;
pub use s_ldata32::SLData32;
pub use s_lproc32::SLProc32;
pub use s_lthread32::SLThread32;
pub use s_objname::SObjName;
pub use s_procref::SProcRef;
pub use s_pub32::SPub32;
pub use s_regrel32::SRegRel32;
pub use s_section::{SSection, SPeCoffSection};
pub use s_skip::SSkip;
pub use s_thunk32::SThunk32;
pub use s_trampoline::STrampoline;
pub use s_udt::SUdt;

pub use s_defrange_register::SDefRangeRegister;
pub use s_defrange_framepointer::SDefRangeFramePointer;
pub use s_defrange_subfield::SDefRangeSubfield;
pub use s_defrange_register_rel::SDefRangeRegisterRel;
pub use s_local::{SLocal, LocalFlags};
pub use s_inlinesite::SInlineSite;

pub use s_envblock::SEnvBlock;
pub use s_buildinfo::SBuildInfo;
pub use s_filestatic::SFileStatic;
pub use s_manframerel::SManFrameRel;
pub use s_regframe::SRegFrame;
pub use s_defrange_framepointer_rel::SDefRangeFramePointerRelFullScope;

pub use s_unamespace::SUNamespace;
pub use s_gprocia64::SGProcIA64;
pub use s_lprocia64::SLProcIA64;

pub use s_gprocref::SGProcRef;
pub use s_lprocref::SLProcRef;
pub use s_dataref::SDataRef;
pub use s_annotation::SAnnotation;

// Register-related symbol types ported from Ghidra Java
pub mod s_register;
pub mod s_manyreg;

pub use s_register::SRegister;
pub use s_manyreg::SManyReg;

pub use s_block32::SBlock32;
pub use s_with32::SWith32;
pub use s_return::SReturn;
pub use s_entrythis::SEntryThis;
