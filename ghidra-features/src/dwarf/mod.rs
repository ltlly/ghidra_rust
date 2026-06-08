//! DWARF Debug Information Format Parser
//!
//! Complete parser for DWARF v2-v5 debug information sections.
//! Maps DWARF type information to Ghidra's DataType system.
//!
//! ## Supported Sections
//! - .debug_info: CU headers (DWARF32/64, v2-5, DW_UT_*, DWO ID)
//! - .debug_abbrev: Abbreviation declarations
//! - .debug_str: Null-terminated string table
//! - .debug_line: Line number state machine (v2-5)
//! - .debug_line_str: DWARF 5 line string table
//! - .debug_ranges / .debug_rnglists: Range list parsing
//! - .debug_aranges: Address range lookup table
//! - .debug_loc / .debug_loclists: Location lists
//! - .debug_frame / .eh_frame: CIE/FDE and CFA instructions
//! - .debug_macro: Macro information (DWARF 5)
//! - .debug_addr: Address table (DWARF 5)
//! - .debug_str_offsets: String offsets table (DWARF 5)
//! - .debug_pubnames / .debug_pubtypes: Public name tables
//!
//! ## Constants (pub mod blocks)
//! dw_tag (70+), dw_at (100+), dw_form (40+), dw_op (70+)
//! dw_lns, dw_lne, dw_cfa, dw_ate, dw_lang, dw_lnct, dw_ut
//! dw_ds, dw_cc, dw_vis, dw_inl, dw_id, dw_virtuality
//! dw_access, dw_ord, dw_lle, dw_rle
//!
//! ## Main API
//! parse_dwarf_sections, parse_dwarf, parse_compilation_unit
//! parse_abbrev_table, parse_attribute, execute_line_program
//! parse_cie, parse_fde, evaluate_dwarf_expression
//! dwarf_type_to_ghidra, build_type_map

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use ghidra_core::data::types::{
    ArrayDataType, BuiltInDataType, BuiltInDataTypeWrapper, DataType,
    EnumDataType, FunctionDefinitionDataType, PointerDataType,
    StructureDataType, TypedefDataType, UnionDataType,
};

/// Type alias for Arc<dyn DataType>.
pub type DataTypeRef = Arc<dyn DataType>;

// ============================================================================
// DW_TAG Constants -- 70+ DIE type tags
// ============================================================================

pub mod dw_tag {
    pub const ARRAY_TYPE: u16 = 0x01;
    pub const CLASS_TYPE: u16 = 0x02;
    pub const ENTRY_POINT: u16 = 0x03;
    pub const ENUMERATION_TYPE: u16 = 0x04;
    pub const FORMAL_PARAMETER: u16 = 0x05;
    pub const IMPORTED_DECLARATION: u16 = 0x08;
    pub const LABEL: u16 = 0x0a;
    pub const LEXICAL_BLOCK: u16 = 0x0b;
    pub const MEMBER: u16 = 0x0d;
    pub const POINTER_TYPE: u16 = 0x0f;
    pub const REFERENCE_TYPE: u16 = 0x10;
    pub const COMPILATION_UNIT: u16 = 0x11;
    pub const STRING_TYPE: u16 = 0x12;
    pub const STRUCTURE_TYPE: u16 = 0x13;
    pub const SUBROUTINE_TYPE: u16 = 0x15;
    pub const TYPEDEF: u16 = 0x16;
    pub const UNION_TYPE: u16 = 0x17;
    pub const UNSPECIFIED_PARAMETERS: u16 = 0x18;
    pub const VARIANT: u16 = 0x19;
    pub const COMMON_BLOCK: u16 = 0x1a;
    pub const COMMON_INCLUSION: u16 = 0x1b;
    pub const INHERITANCE: u16 = 0x1c;
    pub const INLINED_SUBROUTINE: u16 = 0x1d;
    pub const MODULE: u16 = 0x1e;
    pub const PTR_TO_MEMBER_TYPE: u16 = 0x1f;
    pub const SET_TYPE: u16 = 0x20;
    pub const SUBRANGE_TYPE: u16 = 0x21;
    pub const WITH_STMT: u16 = 0x22;
    pub const ACCESS_DECLARATION: u16 = 0x23;
    pub const BASE_TYPE: u16 = 0x24;
    pub const CATCH_BLOCK: u16 = 0x25;
    pub const CONST_TYPE: u16 = 0x26;
    pub const CONSTANT: u16 = 0x27;
    pub const ENUMERATOR: u16 = 0x28;
    pub const FILE_TYPE: u16 = 0x29;
    pub const FRIEND: u16 = 0x2a;
    pub const NAMELIST: u16 = 0x2b;
    pub const NAMELIST_ITEM: u16 = 0x2c;
    pub const PACKED_TYPE: u16 = 0x2d;
    pub const SUBPROGRAM: u16 = 0x2e;
    pub const TEMPLATE_TYPE_PARAMETER: u16 = 0x2f;
    pub const TEMPLATE_VALUE_PARAMETER: u16 = 0x30;
    pub const THROWN_TYPE: u16 = 0x31;
    pub const TRY_BLOCK: u16 = 0x32;
    pub const VARIANT_PART: u16 = 0x33;
    pub const VARIABLE: u16 = 0x34;
    pub const VOLATILE_TYPE: u16 = 0x35;
    pub const DWARF_PROCEDURE: u16 = 0x36;
    pub const RESTRICT_TYPE: u16 = 0x37;
    pub const INTERFACE_TYPE: u16 = 0x38;
    pub const NAMESPACE: u16 = 0x39;
    pub const IMPORTED_MODULE: u16 = 0x3a;
    pub const UNSPECIFIED_TYPE: u16 = 0x3b;
    pub const PARTIAL_UNIT: u16 = 0x3c;
    pub const IMPORTED_UNIT: u16 = 0x3d;
    pub const MUTABLE_TYPE: u16 = 0x3e;
    pub const CONDITION: u16 = 0x3f;
    pub const SHARED_TYPE: u16 = 0x40;
    pub const TYPE_UNIT: u16 = 0x41;
    pub const RVALUE_REFERENCE_TYPE: u16 = 0x42;
    pub const TEMPLATE_ALIAS: u16 = 0x43;
    pub const COARRAY_TYPE: u16 = 0x44;
    pub const GENERIC_SUBRANGE: u16 = 0x45;
    pub const DYNAMIC_TYPE: u16 = 0x46;
    pub const ATOMIC_TYPE: u16 = 0x47;
    pub const CALL_SITE: u16 = 0x48;
    pub const CALL_SITE_PARAMETER: u16 = 0x49;
    pub const SKELETON_UNIT: u16 = 0x4a;
    pub const IMMUTABLE_TYPE: u16 = 0x4b;
    pub const LO_USER: u16 = 0x4080;
    pub const HI_USER: u16 = 0xFFFF;
}

/// Map a DW_TAG_* constant to its canonical string name.
pub fn tag_name(tag: u16) -> &'static str {
    match tag {
        dw_tag::ARRAY_TYPE => "DW_TAG_array_type",
        dw_tag::CLASS_TYPE => "DW_TAG_class_type",
        dw_tag::ENTRY_POINT => "DW_TAG_entry_point",
        dw_tag::ENUMERATION_TYPE => "DW_TAG_enumeration_type",
        dw_tag::FORMAL_PARAMETER => "DW_TAG_formal_parameter",
        dw_tag::IMPORTED_DECLARATION => "DW_TAG_imported_declaration",
        dw_tag::LABEL => "DW_TAG_label",
        dw_tag::LEXICAL_BLOCK => "DW_TAG_lexical_block",
        dw_tag::MEMBER => "DW_TAG_member",
        dw_tag::POINTER_TYPE => "DW_TAG_pointer_type",
        dw_tag::REFERENCE_TYPE => "DW_TAG_reference_type",
        dw_tag::COMPILATION_UNIT => "DW_TAG_compilation_unit",
        dw_tag::STRING_TYPE => "DW_TAG_string_type",
        dw_tag::STRUCTURE_TYPE => "DW_TAG_structure_type",
        dw_tag::SUBROUTINE_TYPE => "DW_TAG_subroutine_type",
        dw_tag::TYPEDEF => "DW_TAG_typedef",
        dw_tag::UNION_TYPE => "DW_TAG_union_type",
        dw_tag::UNSPECIFIED_PARAMETERS => "DW_TAG_unspecified_parameters",
        dw_tag::VARIANT => "DW_TAG_variant",
        dw_tag::COMMON_BLOCK => "DW_TAG_common_block",
        dw_tag::COMMON_INCLUSION => "DW_TAG_common_inclusion",
        dw_tag::INHERITANCE => "DW_TAG_inheritance",
        dw_tag::INLINED_SUBROUTINE => "DW_TAG_inlined_subroutine",
        dw_tag::MODULE => "DW_TAG_module",
        dw_tag::PTR_TO_MEMBER_TYPE => "DW_TAG_ptr_to_member_type",
        dw_tag::SET_TYPE => "DW_TAG_set_type",
        dw_tag::SUBRANGE_TYPE => "DW_TAG_subrange_type",
        dw_tag::WITH_STMT => "DW_TAG_with_stmt",
        dw_tag::ACCESS_DECLARATION => "DW_TAG_access_declaration",
        dw_tag::BASE_TYPE => "DW_TAG_base_type",
        dw_tag::CATCH_BLOCK => "DW_TAG_catch_block",
        dw_tag::CONST_TYPE => "DW_TAG_const_type",
        dw_tag::CONSTANT => "DW_TAG_constant",
        dw_tag::ENUMERATOR => "DW_TAG_enumerator",
        dw_tag::FILE_TYPE => "DW_TAG_file_type",
        dw_tag::FRIEND => "DW_TAG_friend",
        dw_tag::NAMELIST => "DW_TAG_namelist",
        dw_tag::NAMELIST_ITEM => "DW_TAG_namelist_item",
        dw_tag::PACKED_TYPE => "DW_TAG_packed_type",
        dw_tag::SUBPROGRAM => "DW_TAG_subprogram",
        dw_tag::TEMPLATE_TYPE_PARAMETER => "DW_TAG_template_type_parameter",
        dw_tag::TEMPLATE_VALUE_PARAMETER => "DW_TAG_template_value_parameter",
        dw_tag::THROWN_TYPE => "DW_TAG_thrown_type",
        dw_tag::TRY_BLOCK => "DW_TAG_try_block",
        dw_tag::VARIANT_PART => "DW_TAG_variant_part",
        dw_tag::VARIABLE => "DW_TAG_variable",
        dw_tag::VOLATILE_TYPE => "DW_TAG_volatile_type",
        dw_tag::DWARF_PROCEDURE => "DW_TAG_dwarf_procedure",
        dw_tag::RESTRICT_TYPE => "DW_TAG_restrict_type",
        dw_tag::INTERFACE_TYPE => "DW_TAG_interface_type",
        dw_tag::NAMESPACE => "DW_TAG_namespace",
        dw_tag::IMPORTED_MODULE => "DW_TAG_imported_module",
        dw_tag::UNSPECIFIED_TYPE => "DW_TAG_unspecified_type",
        dw_tag::PARTIAL_UNIT => "DW_TAG_partial_unit",
        dw_tag::IMPORTED_UNIT => "DW_TAG_imported_unit",
        dw_tag::MUTABLE_TYPE => "DW_TAG_mutable_type",
        dw_tag::CONDITION => "DW_TAG_condition",
        dw_tag::SHARED_TYPE => "DW_TAG_shared_type",
        dw_tag::TYPE_UNIT => "DW_TAG_type_unit",
        dw_tag::RVALUE_REFERENCE_TYPE => "DW_TAG_rvalue_reference_type",
        dw_tag::TEMPLATE_ALIAS => "DW_TAG_template_alias",
        dw_tag::COARRAY_TYPE => "DW_TAG_coarray_type",
        dw_tag::GENERIC_SUBRANGE => "DW_TAG_generic_subrange",
        dw_tag::DYNAMIC_TYPE => "DW_TAG_dynamic_type",
        dw_tag::ATOMIC_TYPE => "DW_TAG_atomic_type",
        dw_tag::CALL_SITE => "DW_TAG_call_site",
        dw_tag::CALL_SITE_PARAMETER => "DW_TAG_call_site_parameter",
        dw_tag::SKELETON_UNIT => "DW_TAG_skeleton_unit",
        dw_tag::IMMUTABLE_TYPE => "DW_TAG_immutable_type",
        dw_tag::LO_USER => "DW_TAG_lo_user",
        dw_tag::HI_USER => "DW_TAG_hi_user",
        _ => "DW_TAG_<unknown>",
    }
}

// ============================================================================
// DW_AT Constants -- 100+ attribute name constants
// ============================================================================

pub mod dw_at {
    pub const SIBLING: u16 = 0x01;
    pub const LOCATION: u16 = 0x02;
    pub const NAME: u16 = 0x03;
    pub const ORDERING: u16 = 0x09;
    pub const BYTE_SIZE: u16 = 0x0b;
    pub const BIT_OFFSET: u16 = 0x0c;
    pub const BIT_SIZE: u16 = 0x0d;
    pub const STMT_LIST: u16 = 0x10;
    pub const LOW_PC: u16 = 0x11;
    pub const HIGH_PC: u16 = 0x12;
    pub const LANGUAGE: u16 = 0x13;
    pub const DISCR: u16 = 0x15;
    pub const DISCR_VALUE: u16 = 0x16;
    pub const VISIBILITY: u16 = 0x17;
    pub const IMPORT: u16 = 0x18;
    pub const STRING_LENGTH: u16 = 0x19;
    pub const COMMON_REFERENCE: u16 = 0x1a;
    pub const COMP_DIR: u16 = 0x1b;
    pub const CONST_VALUE: u16 = 0x1c;
    pub const CONTAINING_TYPE: u16 = 0x1d;
    pub const DEFAULT_VALUE: u16 = 0x1e;
    pub const INLINE: u16 = 0x20;
    pub const IS_OPTIONAL: u16 = 0x21;
    pub const LOWER_BOUND: u16 = 0x22;
    pub const PRODUCER: u16 = 0x25;
    pub const PROTOTYPED: u16 = 0x27;
    pub const RETURN_ADDR: u16 = 0x2a;
    pub const START_SCOPE: u16 = 0x2c;
    pub const BIT_STRIDE: u16 = 0x2e;
    pub const UPPER_BOUND: u16 = 0x2f;
    pub const ABSTRACT_ORIGIN: u16 = 0x31;
    pub const ACCESSIBILITY: u16 = 0x32;
    pub const ADDRESS_CLASS: u16 = 0x33;
    pub const ARTIFICIAL: u16 = 0x34;
    pub const BASE_TYPES: u16 = 0x35;
    pub const CALLING_CONVENTION: u16 = 0x36;
    pub const COUNT: u16 = 0x37;
    pub const DATA_MEMBER_LOCATION: u16 = 0x38;
    pub const DECL_COLUMN: u16 = 0x39;
    pub const DECL_FILE: u16 = 0x3a;
    pub const DECL_LINE: u16 = 0x3b;
    pub const DECLARATION: u16 = 0x3c;
    pub const DISCR_LIST: u16 = 0x3d;
    pub const ENCODING: u16 = 0x3e;
    pub const EXTERNAL: u16 = 0x3f;
    pub const FRAME_BASE: u16 = 0x40;
    pub const FRIEND: u16 = 0x41;
    pub const IDENTIFIER_CASE: u16 = 0x42;
    pub const MACRO_INFO: u16 = 0x43;
    pub const NAMELIST_ITEM: u16 = 0x44;
    pub const PRIORITY: u16 = 0x45;
    pub const SEGMENT: u16 = 0x46;
    pub const SPECIFICATION: u16 = 0x47;
    pub const STATIC_LINK: u16 = 0x48;
    pub const TYPE: u16 = 0x49;
    pub const USE_LOCATION: u16 = 0x4a;
    pub const VARIABLE_PARAMETER: u16 = 0x4b;
    pub const VIRTUALITY: u16 = 0x4c;
    pub const VTABLE_ELEM_LOCATION: u16 = 0x4d;
    pub const ALLOCATED: u16 = 0x4e;
    pub const ASSOCIATED: u16 = 0x4f;
    pub const DATA_LOCATION: u16 = 0x50;
    pub const BYTE_STRIDE: u16 = 0x51;
    pub const ENTRY_PC: u16 = 0x52;
    pub const USE_UTF8: u16 = 0x53;
    pub const EXTENSION: u16 = 0x54;
    pub const RANGES: u16 = 0x55;
    pub const TRAMPOLINE: u16 = 0x56;
    pub const CALL_COLUMN: u16 = 0x57;
    pub const CALL_FILE: u16 = 0x58;
    pub const CALL_LINE: u16 = 0x59;
    pub const DESCRIPTION: u16 = 0x5a;
    pub const BINARY_SCALE: u16 = 0x5b;
    pub const DECIMAL_SCALE: u16 = 0x5c;
    pub const SMALL: u16 = 0x5d;
    pub const DECIMAL_SIGN: u16 = 0x5e;
    pub const DIGIT_COUNT: u16 = 0x5f;
    pub const PICTURE_STRING: u16 = 0x60;
    pub const MUTABLE: u16 = 0x61;
    pub const THREADS_SCALED: u16 = 0x62;
    pub const EXPLICIT: u16 = 0x63;
    pub const OBJECT_POINTER: u16 = 0x64;
    pub const ENDIANITY: u16 = 0x65;
    pub const ELEMENTAL: u16 = 0x66;
    pub const PURE: u16 = 0x67;
    pub const RECURSIVE: u16 = 0x68;
    pub const SIGNATURE: u16 = 0x69;
    pub const MAIN_SUBPROGRAM: u16 = 0x6a;
    pub const DATA_BIT_OFFSET: u16 = 0x6b;
    pub const CONST_EXPR: u16 = 0x6c;
    pub const ENUM_CLASS: u16 = 0x6d;
    pub const LINKAGE_NAME: u16 = 0x6e;
    pub const STRING_LENGTH_BIT_SIZE: u16 = 0x6f;
    pub const STRING_LENGTH_BYTE_SIZE: u16 = 0x70;
    pub const RANK: u16 = 0x71;
    pub const STR_OFFSETS_BASE: u16 = 0x72;
    pub const ADDR_BASE: u16 = 0x73;
    pub const RNGLISTS_BASE: u16 = 0x74;
    pub const DWO_ID: u16 = 0x75;
    pub const DWO_NAME: u16 = 0x76;
    pub const REFERENCE: u16 = 0x77;
    pub const RVALUE_REFERENCE: u16 = 0x78;
    pub const MACROS: u16 = 0x79;
    pub const CALL_ALL_CALLS: u16 = 0x7a;
    pub const CALL_ALL_SOURCE_CALLS: u16 = 0x7b;
    pub const CALL_ALL_TAIL_CALLS: u16 = 0x7c;
    pub const CALL_RETURN_PC: u16 = 0x7d;
    pub const CALL_VALUE: u16 = 0x7e;
    pub const CALL_ORIGIN: u16 = 0x7f;
    pub const CALL_PARAMETER: u16 = 0x80;
    pub const CALL_PC: u16 = 0x81;
    pub const CALL_TAIL_CALL: u16 = 0x82;
    pub const CALL_TARGET: u16 = 0x83;
    pub const CALL_TARGET_CLOBBERED: u16 = 0x84;
    pub const CALL_DATA_LOCATION: u16 = 0x85;
    pub const CALL_DATA_VALUE: u16 = 0x86;
    pub const NORETURN: u16 = 0x87;
    pub const ALIGNMENT: u16 = 0x88;
    pub const EXPORT_SYMBOLS: u16 = 0x89;
    pub const DELETED: u16 = 0x8a;
    pub const DEFAULTED: u16 = 0x8b;
    pub const LOCLISTS_BASE: u16 = 0x8c;
}

/// Map a DW_AT_* constant to its canonical string name.
pub fn attr_name(at: u16) -> &'static str {
    match at {
        dw_at::SIBLING => "DW_AT_sibling",
        dw_at::LOCATION => "DW_AT_location",
        dw_at::NAME => "DW_AT_name",
        dw_at::ORDERING => "DW_AT_ordering",
        dw_at::BYTE_SIZE => "DW_AT_byte_size",
        dw_at::BIT_OFFSET => "DW_AT_bit_offset",
        dw_at::BIT_SIZE => "DW_AT_bit_size",
        dw_at::STMT_LIST => "DW_AT_stmt_list",
        dw_at::LOW_PC => "DW_AT_low_pc",
        dw_at::HIGH_PC => "DW_AT_high_pc",
        dw_at::LANGUAGE => "DW_AT_language",
        dw_at::DISCR => "DW_AT_discr",
        dw_at::DISCR_VALUE => "DW_AT_discr_value",
        dw_at::VISIBILITY => "DW_AT_visibility",
        dw_at::IMPORT => "DW_AT_import",
        dw_at::STRING_LENGTH => "DW_AT_string_length",
        dw_at::COMMON_REFERENCE => "DW_AT_common_reference",
        dw_at::COMP_DIR => "DW_AT_comp_dir",
        dw_at::CONST_VALUE => "DW_AT_const_value",
        dw_at::CONTAINING_TYPE => "DW_AT_containing_type",
        dw_at::DEFAULT_VALUE => "DW_AT_default_value",
        dw_at::INLINE => "DW_AT_inline",
        dw_at::IS_OPTIONAL => "DW_AT_is_optional",
        dw_at::LOWER_BOUND => "DW_AT_lower_bound",
        dw_at::PRODUCER => "DW_AT_producer",
        dw_at::PROTOTYPED => "DW_AT_prototyped",
        dw_at::RETURN_ADDR => "DW_AT_return_addr",
        dw_at::START_SCOPE => "DW_AT_start_scope",
        dw_at::BIT_STRIDE => "DW_AT_bit_stride",
        dw_at::UPPER_BOUND => "DW_AT_upper_bound",
        dw_at::ABSTRACT_ORIGIN => "DW_AT_abstract_origin",
        dw_at::ACCESSIBILITY => "DW_AT_accessibility",
        dw_at::ADDRESS_CLASS => "DW_AT_address_class",
        dw_at::ARTIFICIAL => "DW_AT_artificial",
        dw_at::BASE_TYPES => "DW_AT_base_types",
        dw_at::CALLING_CONVENTION => "DW_AT_calling_convention",
        dw_at::COUNT => "DW_AT_count",
        dw_at::DATA_MEMBER_LOCATION => "DW_AT_data_member_location",
        dw_at::DECL_COLUMN => "DW_AT_decl_column",
        dw_at::DECL_FILE => "DW_AT_decl_file",
        dw_at::DECL_LINE => "DW_AT_decl_line",
        dw_at::DECLARATION => "DW_AT_declaration",
        dw_at::DISCR_LIST => "DW_AT_discr_list",
        dw_at::ENCODING => "DW_AT_encoding",
        dw_at::EXTERNAL => "DW_AT_external",
        dw_at::FRAME_BASE => "DW_AT_frame_base",
        dw_at::FRIEND => "DW_AT_friend",
        dw_at::IDENTIFIER_CASE => "DW_AT_identifier_case",
        dw_at::MACRO_INFO => "DW_AT_macro_info",
        dw_at::NAMELIST_ITEM => "DW_AT_namelist_item",
        dw_at::PRIORITY => "DW_AT_priority",
        dw_at::SEGMENT => "DW_AT_segment",
        dw_at::SPECIFICATION => "DW_AT_specification",
        dw_at::STATIC_LINK => "DW_AT_static_link",
        dw_at::TYPE => "DW_AT_type",
        dw_at::USE_LOCATION => "DW_AT_use_location",
        dw_at::VARIABLE_PARAMETER => "DW_AT_variable_parameter",
        dw_at::VIRTUALITY => "DW_AT_virtuality",
        dw_at::VTABLE_ELEM_LOCATION => "DW_AT_vtable_elem_location",
        dw_at::ALLOCATED => "DW_AT_allocated",
        dw_at::ASSOCIATED => "DW_AT_associated",
        dw_at::DATA_LOCATION => "DW_AT_data_location",
        dw_at::BYTE_STRIDE => "DW_AT_byte_stride",
        dw_at::ENTRY_PC => "DW_AT_entry_pc",
        dw_at::USE_UTF8 => "DW_AT_use_utf8",
        dw_at::EXTENSION => "DW_AT_extension",
        dw_at::RANGES => "DW_AT_ranges",
        dw_at::TRAMPOLINE => "DW_AT_trampoline",
        dw_at::CALL_COLUMN => "DW_AT_call_column",
        dw_at::CALL_FILE => "DW_AT_call_file",
        dw_at::CALL_LINE => "DW_AT_call_line",
        dw_at::DESCRIPTION => "DW_AT_description",
        dw_at::BINARY_SCALE => "DW_AT_binary_scale",
        dw_at::DECIMAL_SCALE => "DW_AT_decimal_scale",
        dw_at::SMALL => "DW_AT_small",
        dw_at::DECIMAL_SIGN => "DW_AT_decimal_sign",
        dw_at::DIGIT_COUNT => "DW_AT_digit_count",
        dw_at::PICTURE_STRING => "DW_AT_picture_string",
        dw_at::MUTABLE => "DW_AT_mutable",
        dw_at::THREADS_SCALED => "DW_AT_threads_scaled",
        dw_at::EXPLICIT => "DW_AT_explicit",
        dw_at::OBJECT_POINTER => "DW_AT_object_pointer",
        dw_at::ENDIANITY => "DW_AT_endianity",
        dw_at::ELEMENTAL => "DW_AT_elemental",
        dw_at::PURE => "DW_AT_pure",
        dw_at::RECURSIVE => "DW_AT_recursive",
        dw_at::SIGNATURE => "DW_AT_signature",
        dw_at::MAIN_SUBPROGRAM => "DW_AT_main_subprogram",
        dw_at::DATA_BIT_OFFSET => "DW_AT_data_bit_offset",
        dw_at::CONST_EXPR => "DW_AT_const_expr",
        dw_at::ENUM_CLASS => "DW_AT_enum_class",
        dw_at::LINKAGE_NAME => "DW_AT_linkage_name",
        dw_at::STRING_LENGTH_BIT_SIZE => "DW_AT_string_length_bit_size",
        dw_at::STRING_LENGTH_BYTE_SIZE => "DW_AT_string_length_byte_size",
        dw_at::RANK => "DW_AT_rank",
        dw_at::STR_OFFSETS_BASE => "DW_AT_str_offsets_base",
        dw_at::ADDR_BASE => "DW_AT_addr_base",
        dw_at::RNGLISTS_BASE => "DW_AT_rnglists_base",
        dw_at::DWO_ID => "DW_AT_dwo_id",
        dw_at::DWO_NAME => "DW_AT_dwo_name",
        dw_at::REFERENCE => "DW_AT_reference",
        dw_at::RVALUE_REFERENCE => "DW_AT_rvalue_reference",
        dw_at::MACROS => "DW_AT_macros",
        dw_at::CALL_ALL_CALLS => "DW_AT_call_all_calls",
        dw_at::CALL_ALL_SOURCE_CALLS => "DW_AT_call_all_source_calls",
        dw_at::CALL_ALL_TAIL_CALLS => "DW_AT_call_all_tail_calls",
        dw_at::CALL_RETURN_PC => "DW_AT_call_return_pc",
        dw_at::CALL_VALUE => "DW_AT_call_value",
        dw_at::CALL_ORIGIN => "DW_AT_call_origin",
        dw_at::CALL_PARAMETER => "DW_AT_call_parameter",
        dw_at::CALL_PC => "DW_AT_call_pc",
        dw_at::CALL_TAIL_CALL => "DW_AT_call_tail_call",
        dw_at::CALL_TARGET => "DW_AT_call_target",
        dw_at::CALL_TARGET_CLOBBERED => "DW_AT_call_target_clobbered",
        dw_at::CALL_DATA_LOCATION => "DW_AT_call_data_location",
        dw_at::CALL_DATA_VALUE => "DW_AT_call_data_value",
        dw_at::NORETURN => "DW_AT_noreturn",
        dw_at::ALIGNMENT => "DW_AT_alignment",
        dw_at::EXPORT_SYMBOLS => "DW_AT_export_symbols",
        dw_at::DELETED => "DW_AT_deleted",
        dw_at::DEFAULTED => "DW_AT_defaulted",
        dw_at::LOCLISTS_BASE => "DW_AT_loclists_base",
        _ => "DW_AT_<unknown>",
    }
}

// ============================================================================
// DW_FORM Constants -- 40+ attribute value encoding forms
// ============================================================================

pub mod dw_form {
    pub const ADDR: u16 = 0x01;
    pub const BLOCK2: u16 = 0x03;
    pub const BLOCK4: u16 = 0x04;
    pub const DATA2: u16 = 0x05;
    pub const DATA4: u16 = 0x06;
    pub const DATA8: u16 = 0x07;
    pub const STRING: u16 = 0x08;
    pub const BLOCK: u16 = 0x09;
    pub const BLOCK1: u16 = 0x0a;
    pub const DATA1: u16 = 0x0b;
    pub const FLAG: u16 = 0x0c;
    pub const SDATA: u16 = 0x0d;
    pub const STRP: u16 = 0x0e;
    pub const UDATA: u16 = 0x0f;
    pub const REF_ADDR: u16 = 0x10;
    pub const REF1: u16 = 0x11;
    pub const REF2: u16 = 0x12;
    pub const REF4: u16 = 0x13;
    pub const REF8: u16 = 0x14;
    pub const REF_UDATA: u16 = 0x15;
    pub const INDIRECT: u16 = 0x16;
    pub const SEC_OFFSET: u16 = 0x17;
    pub const EXPRLOC: u16 = 0x18;
    pub const FLAG_PRESENT: u16 = 0x19;
    pub const STRX: u16 = 0x1a;
    pub const ADDRX: u16 = 0x1b;
    pub const REF_SUP4: u16 = 0x1c;
    pub const STRP_SUP: u16 = 0x1d;
    pub const DATA16: u16 = 0x1e;
    pub const LINE_STRP: u16 = 0x1f;
    pub const REF_SIG8: u16 = 0x20;
    pub const IMPLICIT_CONST: u16 = 0x21;
    pub const LOCLISTX: u16 = 0x22;
    pub const RNGLISTX: u16 = 0x23;
    pub const REF_SUP8: u16 = 0x24;
    pub const STRX1: u16 = 0x25;
    pub const STRX2: u16 = 0x26;
    pub const STRX3: u16 = 0x27;
    pub const STRX4: u16 = 0x28;
    pub const ADDRX1: u16 = 0x29;
    pub const ADDRX2: u16 = 0x2a;
    pub const ADDRX3: u16 = 0x2b;
    pub const ADDRX4: u16 = 0x2c;
}

/// Map a DW_FORM_* constant to its canonical string name.
pub fn form_name(form: u16) -> &'static str {
    match form {
        dw_form::ADDR => "DW_FORM_addr",
        dw_form::BLOCK2 => "DW_FORM_block2",
        dw_form::BLOCK4 => "DW_FORM_block4",
        dw_form::DATA2 => "DW_FORM_data2",
        dw_form::DATA4 => "DW_FORM_data4",
        dw_form::DATA8 => "DW_FORM_data8",
        dw_form::STRING => "DW_FORM_string",
        dw_form::BLOCK => "DW_FORM_block",
        dw_form::BLOCK1 => "DW_FORM_block1",
        dw_form::DATA1 => "DW_FORM_data1",
        dw_form::FLAG => "DW_FORM_flag",
        dw_form::SDATA => "DW_FORM_sdata",
        dw_form::STRP => "DW_FORM_strp",
        dw_form::UDATA => "DW_FORM_udata",
        dw_form::REF_ADDR => "DW_FORM_ref_addr",
        dw_form::REF1 => "DW_FORM_ref1",
        dw_form::REF2 => "DW_FORM_ref2",
        dw_form::REF4 => "DW_FORM_ref4",
        dw_form::REF8 => "DW_FORM_ref8",
        dw_form::REF_UDATA => "DW_FORM_ref_udata",
        dw_form::INDIRECT => "DW_FORM_indirect",
        dw_form::SEC_OFFSET => "DW_FORM_sec_offset",
        dw_form::EXPRLOC => "DW_FORM_exprloc",
        dw_form::FLAG_PRESENT => "DW_FORM_flag_present",
        dw_form::STRX => "DW_FORM_strx",
        dw_form::ADDRX => "DW_FORM_addrx",
        dw_form::REF_SUP4 => "DW_FORM_ref_sup4",
        dw_form::STRP_SUP => "DW_FORM_strp_sup",
        dw_form::DATA16 => "DW_FORM_data16",
        dw_form::LINE_STRP => "DW_FORM_line_strp",
        dw_form::REF_SIG8 => "DW_FORM_ref_sig8",
        dw_form::IMPLICIT_CONST => "DW_FORM_implicit_const",
        dw_form::LOCLISTX => "DW_FORM_loclistx",
        dw_form::RNGLISTX => "DW_FORM_rnglistx",
        dw_form::REF_SUP8 => "DW_FORM_ref_sup8",
        dw_form::STRX1 => "DW_FORM_strx1",
        dw_form::STRX2 => "DW_FORM_strx2",
        dw_form::STRX3 => "DW_FORM_strx3",
        dw_form::STRX4 => "DW_FORM_strx4",
        dw_form::ADDRX1 => "DW_FORM_addrx1",
        dw_form::ADDRX2 => "DW_FORM_addrx2",
        dw_form::ADDRX3 => "DW_FORM_addrx3",
        dw_form::ADDRX4 => "DW_FORM_addrx4",
        _ => "DW_FORM_<unknown>",
    }
}

// ============================================================================
// DW_OP Constants -- 70+ expression operation codes
// ============================================================================

pub mod dw_op {
    pub const ADDR: u8                = 0x03;
    pub const DEREF: u8               = 0x06;
    pub const CONST1U: u8             = 0x08;
    pub const CONST1S: u8             = 0x09;
    pub const CONST2U: u8             = 0x0a;
    pub const CONST2S: u8             = 0x0b;
    pub const CONST4U: u8             = 0x0c;
    pub const CONST4S: u8             = 0x0d;
    pub const CONST8U: u8             = 0x0e;
    pub const CONST8S: u8             = 0x0f;
    pub const CONSTU: u8              = 0x10;
    pub const CONSTS: u8              = 0x11;
    pub const DUP: u8                 = 0x12;
    pub const DROP: u8                = 0x13;
    pub const OVER: u8                = 0x14;
    pub const PICK: u8                = 0x15;
    pub const SWAP: u8                = 0x16;
    pub const ROT: u8                 = 0x17;
    pub const XDEREF: u8              = 0x18;
    pub const ABS: u8                 = 0x19;
    pub const AND: u8                 = 0x1a;
    pub const DIV: u8                 = 0x1b;
    pub const MINUS: u8               = 0x1c;
    pub const MOD: u8                 = 0x1d;
    pub const MUL: u8                 = 0x1e;
    pub const NEG: u8                 = 0x1f;
    pub const NOT: u8                 = 0x20;
    pub const OR: u8                  = 0x21;
    pub const PLUS: u8                = 0x22;
    pub const PLUS_UCONST: u8         = 0x23;
    pub const SHL: u8                 = 0x24;
    pub const SHR: u8                 = 0x25;
    pub const SHRA: u8                = 0x26;
    pub const XOR: u8                 = 0x27;
    pub const BRA: u8                 = 0x28;
    pub const EQ: u8                  = 0x29;
    pub const GE: u8                  = 0x2a;
    pub const GT: u8                  = 0x2b;
    pub const LE: u8                  = 0x2c;
    pub const LT: u8                  = 0x2d;
    pub const NE: u8                  = 0x2e;
    pub const SKIP: u8                = 0x2f;
    pub const LIT0: u8              = 0x30;
    pub const LIT1: u8              = 0x31;
    pub const LIT2: u8              = 0x32;
    pub const LIT3: u8              = 0x33;
    pub const LIT4: u8              = 0x34;
    pub const LIT5: u8              = 0x35;
    pub const LIT6: u8              = 0x36;
    pub const LIT7: u8              = 0x37;
    pub const LIT8: u8              = 0x38;
    pub const LIT9: u8              = 0x39;
    pub const LIT10: u8              = 0x3a;
    pub const LIT11: u8              = 0x3b;
    pub const LIT12: u8              = 0x3c;
    pub const LIT13: u8              = 0x3d;
    pub const LIT14: u8              = 0x3e;
    pub const LIT15: u8              = 0x3f;
    pub const LIT16: u8              = 0x40;
    pub const LIT17: u8              = 0x41;
    pub const LIT18: u8              = 0x42;
    pub const LIT19: u8              = 0x43;
    pub const LIT20: u8              = 0x44;
    pub const LIT21: u8              = 0x45;
    pub const LIT22: u8              = 0x46;
    pub const LIT23: u8              = 0x47;
    pub const LIT24: u8              = 0x48;
    pub const LIT25: u8              = 0x49;
    pub const LIT26: u8              = 0x4a;
    pub const LIT27: u8              = 0x4b;
    pub const LIT28: u8              = 0x4c;
    pub const LIT29: u8              = 0x4d;
    pub const LIT30: u8              = 0x4e;
    pub const LIT31: u8              = 0x4f;
    pub const REG0: u8              = 0x50;
    pub const REG1: u8              = 0x51;
    pub const REG2: u8              = 0x52;
    pub const REG3: u8              = 0x53;
    pub const REG4: u8              = 0x54;
    pub const REG5: u8              = 0x55;
    pub const REG6: u8              = 0x56;
    pub const REG7: u8              = 0x57;
    pub const REG8: u8              = 0x58;
    pub const REG9: u8              = 0x59;
    pub const REG10: u8              = 0x5a;
    pub const REG11: u8              = 0x5b;
    pub const REG12: u8              = 0x5c;
    pub const REG13: u8              = 0x5d;
    pub const REG14: u8              = 0x5e;
    pub const REG15: u8              = 0x5f;
    pub const REG16: u8              = 0x60;
    pub const REG17: u8              = 0x61;
    pub const REG18: u8              = 0x62;
    pub const REG19: u8              = 0x63;
    pub const REG20: u8              = 0x64;
    pub const REG21: u8              = 0x65;
    pub const REG22: u8              = 0x66;
    pub const REG23: u8              = 0x67;
    pub const REG24: u8              = 0x68;
    pub const REG25: u8              = 0x69;
    pub const REG26: u8              = 0x6a;
    pub const REG27: u8              = 0x6b;
    pub const REG28: u8              = 0x6c;
    pub const REG29: u8              = 0x6d;
    pub const REG30: u8              = 0x6e;
    pub const REG31: u8              = 0x6f;
    pub const BREG0: u8             = 0x70;
    pub const BREG1: u8             = 0x71;
    pub const BREG2: u8             = 0x72;
    pub const BREG3: u8             = 0x73;
    pub const BREG4: u8             = 0x74;
    pub const BREG5: u8             = 0x75;
    pub const BREG6: u8             = 0x76;
    pub const BREG7: u8             = 0x77;
    pub const BREG8: u8             = 0x78;
    pub const BREG9: u8             = 0x79;
    pub const BREG10: u8             = 0x7a;
    pub const BREG11: u8             = 0x7b;
    pub const BREG12: u8             = 0x7c;
    pub const BREG13: u8             = 0x7d;
    pub const BREG14: u8             = 0x7e;
    pub const BREG15: u8             = 0x7f;
    pub const BREG16: u8             = 0x80;
    pub const BREG17: u8             = 0x81;
    pub const BREG18: u8             = 0x82;
    pub const BREG19: u8             = 0x83;
    pub const BREG20: u8             = 0x84;
    pub const BREG21: u8             = 0x85;
    pub const BREG22: u8             = 0x86;
    pub const BREG23: u8             = 0x87;
    pub const BREG24: u8             = 0x88;
    pub const BREG25: u8             = 0x89;
    pub const BREG26: u8             = 0x8a;
    pub const BREG27: u8             = 0x8b;
    pub const BREG28: u8             = 0x8c;
    pub const BREG29: u8             = 0x8d;
    pub const BREG30: u8             = 0x8e;
    pub const BREG31: u8             = 0x8f;
    pub const REGX: u8                = 0x90;
    pub const FBREG: u8               = 0x91;
    pub const BREGX: u8               = 0x92;
    pub const PIECE: u8               = 0x93;
    pub const DEREF_SIZE: u8          = 0x94;
    pub const XDEREF_SIZE: u8         = 0x95;
    pub const NOP: u8                 = 0x96;
    pub const PUSH_OBJECT_ADDRESS: u8 = 0x97;
    pub const CALL2: u8               = 0x98;
    pub const CALL4: u8               = 0x99;
    pub const CALL_REF: u8            = 0x9a;
    pub const FORM_TLS_ADDRESS: u8    = 0x9b;
    pub const CALL_FRAME_CFA: u8      = 0x9c;
    pub const BIT_PIECE: u8           = 0x9d;
    pub const IMPLICIT_VALUE: u8      = 0x9e;
    pub const STACK_VALUE: u8         = 0x9f;
    pub const IMPLICIT_POINTER: u8    = 0xa0;
    pub const ADDRX: u8               = 0xa1;
    pub const CONSTX: u8              = 0xa2;
    pub const ENTRY_VALUE: u8         = 0xa3;
    pub const CONST_TYPE: u8          = 0xa4;
    pub const REGVAL_TYPE: u8         = 0xa5;
    pub const DEREF_TYPE: u8          = 0xa6;
    pub const XDEREF_TYPE: u8         = 0xa7;
    pub const CONVERT: u8             = 0xa8;
    pub const REINTERPRET: u8         = 0xa9;

    /// Check if an opcode is a literal (DW_OP_lit0..DW_OP_lit31).
    pub fn is_lit(op: u8) -> bool { (0x30..=0x4f).contains(&op) }
    /// Get the literal value from a DW_OP_litN opcode.
    pub fn lit_value(op: u8) -> u64 { (op - 0x30) as u64 }
    /// Check if an opcode is a register (DW_OP_reg0..DW_OP_reg31).
    pub fn is_reg(op: u8) -> bool { (0x50..=0x6f).contains(&op) }
    /// Get the register number from a DW_OP_regN opcode.
    pub fn reg_value(op: u8) -> u16 { (op - 0x50) as u16 }
    /// Check if an opcode is a based register (DW_OP_breg0..DW_OP_breg31).
    pub fn is_breg(op: u8) -> bool { (0x70..=0x8f).contains(&op) }
    /// Get the base register number from a DW_OP_bregN opcode.
    pub fn breg_value(op: u8) -> u16 { (op - 0x70) as u16 }
}

/// Map a DW_OP_* opcode to its canonical string name.
pub fn op_name(op: u8) -> &'static str {
    match op {
        dw_op::ADDR => "DW_OP_addr",
        dw_op::DEREF => "DW_OP_deref",
        dw_op::CONST1U => "DW_OP_const1u",
        dw_op::CONST1S => "DW_OP_const1s",
        dw_op::CONST2U => "DW_OP_const2u",
        dw_op::CONST2S => "DW_OP_const2s",
        dw_op::CONST4U => "DW_OP_const4u",
        dw_op::CONST4S => "DW_OP_const4s",
        dw_op::CONST8U => "DW_OP_const8u",
        dw_op::CONST8S => "DW_OP_const8s",
        dw_op::CONSTU => "DW_OP_constu",
        dw_op::CONSTS => "DW_OP_consts",
        dw_op::DUP => "DW_OP_dup",
        dw_op::DROP => "DW_OP_drop",
        dw_op::OVER => "DW_OP_over",
        dw_op::PICK => "DW_OP_pick",
        dw_op::SWAP => "DW_OP_swap",
        dw_op::ROT => "DW_OP_rot",
        dw_op::XDEREF => "DW_OP_xderef",
        dw_op::ABS => "DW_OP_abs",
        dw_op::AND => "DW_OP_and",
        dw_op::DIV => "DW_OP_div",
        dw_op::MINUS => "DW_OP_minus",
        dw_op::MOD => "DW_OP_mod",
        dw_op::MUL => "DW_OP_mul",
        dw_op::NEG => "DW_OP_neg",
        dw_op::NOT => "DW_OP_not",
        dw_op::OR => "DW_OP_or",
        dw_op::PLUS => "DW_OP_plus",
        dw_op::PLUS_UCONST => "DW_OP_plus_uconst",
        dw_op::SHL => "DW_OP_shl",
        dw_op::SHR => "DW_OP_shr",
        dw_op::SHRA => "DW_OP_shra",
        dw_op::XOR => "DW_OP_xor",
        dw_op::BRA => "DW_OP_bra",
        dw_op::EQ => "DW_OP_eq",
        dw_op::GE => "DW_OP_ge",
        dw_op::GT => "DW_OP_gt",
        dw_op::LE => "DW_OP_le",
        dw_op::LT => "DW_OP_lt",
        dw_op::NE => "DW_OP_ne",
        dw_op::SKIP => "DW_OP_skip",
        dw_op::REGX => "DW_OP_regx",
        dw_op::FBREG => "DW_OP_fbreg",
        dw_op::BREGX => "DW_OP_bregx",
        dw_op::PIECE => "DW_OP_piece",
        dw_op::DEREF_SIZE => "DW_OP_deref_size",
        dw_op::XDEREF_SIZE => "DW_OP_xderef_size",
        dw_op::NOP => "DW_OP_nop",
        dw_op::PUSH_OBJECT_ADDRESS => "DW_OP_push_object_address",
        dw_op::CALL2 => "DW_OP_call2",
        dw_op::CALL4 => "DW_OP_call4",
        dw_op::CALL_REF => "DW_OP_call_ref",
        dw_op::FORM_TLS_ADDRESS => "DW_OP_form_tls_address",
        dw_op::CALL_FRAME_CFA => "DW_OP_call_frame_cfa",
        dw_op::BIT_PIECE => "DW_OP_bit_piece",
        dw_op::IMPLICIT_VALUE => "DW_OP_implicit_value",
        dw_op::STACK_VALUE => "DW_OP_stack_value",
        dw_op::IMPLICIT_POINTER => "DW_OP_implicit_pointer",
        dw_op::ADDRX => "DW_OP_addrx",
        dw_op::CONSTX => "DW_OP_constx",
        dw_op::ENTRY_VALUE => "DW_OP_entry_value",
        dw_op::CONST_TYPE => "DW_OP_const_type",
        dw_op::REGVAL_TYPE => "DW_OP_regval_type",
        dw_op::DEREF_TYPE => "DW_OP_deref_type",
        dw_op::XDEREF_TYPE => "DW_OP_xderef_type",
        dw_op::CONVERT => "DW_OP_convert",
        dw_op::REINTERPRET => "DW_OP_reinterpret",
        _ if dw_op::is_lit(op) => "DW_OP_lit<n>",
        _ if dw_op::is_reg(op) => "DW_OP_reg<n>",
        _ if dw_op::is_breg(op) => "DW_OP_breg<n>",
        _ => "DW_OP_<unknown>",
    }
}

// ============================================================================
// DW_LNS_*, DW_LNE_*, DW_CFA_*, DW_ATE_*, DW_LANG_*, DW_LNCT_*, DW_UT_*
// ============================================================================

pub mod dw_lns {
    pub const COPY: u8             = 1;
    pub const ADVANCE_PC: u8       = 2;
    pub const ADVANCE_LINE: u8     = 3;
    pub const SET_FILE: u8         = 4;
    pub const SET_COLUMN: u8       = 5;
    pub const NEGATE_STMT: u8      = 6;
    pub const SET_BASIC_BLOCK: u8  = 7;
    pub const CONST_ADD_PC: u8     = 8;
    pub const FIXED_ADVANCE_PC: u8 = 9;
    pub const SET_PROLOGUE_END: u8 = 10;
    pub const SET_EPILOGUE_BEGIN: u8 = 11;
    pub const SET_ISA: u8          = 12;
}

pub mod dw_lne {
    pub const END_SEQUENCE: u8     = 1;
    pub const SET_ADDRESS: u8      = 2;
    pub const DEFINE_FILE: u8      = 3;
    pub const SET_DISCRIMINATOR: u8 = 4;
}

pub mod dw_cfa {
    pub const NOP: u8               = 0x00;
    pub const ADVANCE_LOC: u8       = 0x01;
    pub const OFFSET: u8            = 0x02;
    pub const RESTORE: u8           = 0x03;
    pub const ADVANCE_LOC1: u8      = 0x02;
    pub const ADVANCE_LOC2: u8      = 0x03;
    pub const ADVANCE_LOC4: u8      = 0x04;
    pub const OFFSET_EXTENDED: u8   = 0x05;
    pub const RESTORE_EXTENDED: u8  = 0x06;
    pub const UNDEFINED: u8         = 0x07;
    pub const SAME_VALUE: u8        = 0x08;
    pub const REGISTER: u8          = 0x09;
    pub const REMEMBER_STATE: u8    = 0x0a;
    pub const RESTORE_STATE: u8     = 0x0b;
    pub const DEF_CFA: u8           = 0x0c;
    pub const DEF_CFA_REGISTER: u8  = 0x0d;
    pub const DEF_CFA_OFFSET: u8    = 0x0e;
    pub const DEF_CFA_EXPRESSION: u8 = 0x0f;
    pub const EXPRESSION: u8        = 0x10;
    pub const OFFSET_EXTENDED_SF: u8 = 0x11;
    pub const DEF_CFA_SF: u8        = 0x12;
    pub const DEF_CFA_OFFSET_SF: u8 = 0x13;
    pub const VAL_OFFSET: u8        = 0x14;
    pub const VAL_OFFSET_SF: u8     = 0x15;
    pub const VAL_EXPRESSION: u8    = 0x16;
    pub const LO_USER: u8           = 0x1c;
    pub const HI_USER: u8           = 0x3f;
}

pub mod dw_ate {
    pub const ADDRESS: u8 = 1;
    pub const BOOLEAN: u8 = 2;
    pub const COMPLEX_FLOAT: u8 = 3;
    pub const FLOAT: u8 = 4;
    pub const SIGNED: u8 = 5;
    pub const SIGNED_CHAR: u8 = 6;
    pub const UNSIGNED: u8 = 7;
    pub const UNSIGNED_CHAR: u8 = 8;
    pub const IMAGINARY_FLOAT: u8 = 9;
    pub const PACKED_DECIMAL: u8 = 10;
    pub const NUMERIC_STRING: u8 = 11;
    pub const EDITED: u8 = 12;
    pub const SIGNED_FIXED: u8 = 13;
    pub const UNSIGNED_FIXED: u8 = 14;
    pub const DECIMAL_FLOAT: u8 = 15;
    pub const UTF: u8 = 16;
    pub const UCS: u8 = 17;
    pub const ASCII: u8 = 18;
}

pub mod dw_lang {
    pub const C89: u16 = 0x1;
    pub const C: u16 = 0x2;
    pub const ADA83: u16 = 0x3;
    pub const C_PLUS_PLUS: u16 = 0x4;
    pub const COBOL74: u16 = 0x5;
    pub const COBOL85: u16 = 0x6;
    pub const FORTRAN77: u16 = 0x7;
    pub const FORTRAN90: u16 = 0x8;
    pub const PASCAL83: u16 = 0x9;
    pub const MODULA2: u16 = 0xa;
    pub const JAVA: u16 = 0xb;
    pub const C99: u16 = 0xc;
    pub const ADA95: u16 = 0xd;
    pub const FORTRAN95: u16 = 0xe;
    pub const PLI: u16 = 0xf;
    pub const OBJC: u16 = 0x10;
    pub const OBJC_PLUS_PLUS: u16 = 0x11;
    pub const UPC: u16 = 0x12;
    pub const D: u16 = 0x13;
    pub const PYTHON: u16 = 0x14;
    pub const OPENCL: u16 = 0x15;
    pub const GO: u16 = 0x16;
    pub const MODULA3: u16 = 0x17;
    pub const HASKELL: u16 = 0x18;
    pub const C_PLUS_PLUS_03: u16 = 0x19;
    pub const C_PLUS_PLUS_11: u16 = 0x1a;
    pub const OCAML: u16 = 0x1b;
    pub const RUST: u16 = 0x1c;
    pub const C11: u16 = 0x1d;
    pub const SWIFT: u16 = 0x1e;
    pub const JULIA: u16 = 0x1f;
    pub const DYLANG: u16 = 0x20;
    pub const C_PLUS_PLUS_14: u16 = 0x21;
    pub const FORTRAN03: u16 = 0x22;
    pub const FORTRAN08: u16 = 0x23;
    pub const RENDERSCRIPT: u16 = 0x24;
    pub const BLISS: u16 = 0x25;
    pub const KOTLIN: u16 = 0x26;
    pub const ZIG: u16 = 0x27;
    pub const CRYSTAL: u16 = 0x28;
    pub const C_PLUS_PLUS_17: u16 = 0x2a;
    pub const C_PLUS_PLUS_20: u16 = 0x2b;
    pub const C17: u16 = 0x2c;
    pub const FORTRAN18: u16 = 0x2d;
    pub const ADA2005: u16 = 0x2e;
    pub const ADA2012: u16 = 0x2f;
    pub const MOJO: u16 = 0x31;
    pub const LO_USER: u16 = 0x8000;
    pub const HI_USER: u16 = 0xffff;
}

pub mod dw_lnct {
    pub const PATH: u64            = 1;
    pub const DIRECTORY_INDEX: u64 = 2;
    pub const TIMESTAMP: u64       = 3;
    pub const SIZE: u64            = 4;
    pub const MD5: u64             = 5;
    pub const LO_USER: u64         = 0x2000;
    pub const HI_USER: u64         = 0x3FFF;
}

pub mod dw_ut {
    pub const COMPILE: u8       = 0x01;
    pub const TYPE: u8          = 0x02;
    pub const PARTIAL: u8       = 0x03;
    pub const SKELETON: u8      = 0x04;
    pub const SPLIT_COMPILE: u8 = 0x05;
    pub const SPLIT_TYPE: u8    = 0x06;
    pub const LO_USER: u8       = 0x80;
    pub const HI_USER: u8       = 0xFF;
}

pub mod dw_ds {
    pub const UNSIGNED: u8            = 0x01;
    pub const LEADING_OVERPUNCH: u8   = 0x02;
    pub const TRAILING_OVERPUNCH: u8  = 0x03;
    pub const LEADING_SEPARATE: u8    = 0x04;
    pub const TRAILING_SEPARATE: u8   = 0x05;
}

pub mod dw_cc {
    pub const NORMAL: u8        = 0x01;
    pub const PROGRAM: u8       = 0x02;
    pub const NOCALL: u8        = 0x03;
    pub const PASS_BY_REFERENCE: u8 = 0x04;
    pub const PASS_BY_VALUE: u8 = 0x05;
}

pub mod dw_vis {
    pub const LOCAL: u8   = 0x01;
    pub const EXPORTED: u8 = 0x02;
    pub const QUALIFIED: u8 = 0x03;
}

pub mod dw_inl {
    pub const NOT_INLINED: u8         = 0x00;
    pub const INLINED: u8             = 0x01;
    pub const DECLARED_NOT_INLINED: u8 = 0x02;
    pub const DECLARED_INLINED: u8    = 0x03;
}

pub mod dw_id {
    pub const CASE_SENSITIVE: u8   = 0x00;
    pub const UP_CASE: u8          = 0x01;
    pub const DOWN_CASE: u8        = 0x02;
    pub const CASE_INSENSITIVE: u8 = 0x03;
}

pub mod dw_virtuality {
    pub const NONE: u8         = 0x00;
    pub const VIRTUAL: u8      = 0x01;
    pub const PURE_VIRTUAL: u8 = 0x02;
}

pub mod dw_access {
    pub const PUBLIC: u8    = 0x01;
    pub const PROTECTED: u8 = 0x02;
    pub const PRIVATE: u8   = 0x03;
}

pub mod dw_ord {
    pub const ROW_MAJOR: u8    = 0x00;
    pub const COL_MAJOR: u8    = 0x01;
}

pub mod dw_lle {
    pub const END_OF_LIST: u8    = 0x00;
    pub const BASE_ADDRESSX: u8  = 0x01;
    pub const STARTX_ENDX: u8    = 0x02;
    pub const STARTX_LENGTH: u8  = 0x03;
    pub const OFFSET_PAIR: u8    = 0x04;
    pub const DEFAULT_LOC: u8    = 0x05;
    pub const BASE_ADDRESS: u8   = 0x06;
    pub const START_END: u8      = 0x07;
    pub const START_LENGTH: u8   = 0x08;
}

pub mod dw_rle {
    pub const END_OF_LIST: u8    = 0x00;
    pub const BASE_ADDRESSX: u8  = 0x01;
    pub const STARTX_ENDX: u8    = 0x02;
    pub const STARTX_LENGTH: u8  = 0x03;
    pub const OFFSET_PAIR: u8    = 0x04;
    pub const BASE_ADDRESS: u8   = 0x05;
    pub const START_END: u8      = 0x06;
    pub const START_LENGTH: u8   = 0x07;
}

// ============================================================================
// Error Type
// ============================================================================

/// Errors that can occur during DWARF parsing.
#[derive(Debug, Clone)]
pub enum DwarfError {
    /// Unexpected end of data.
    UnexpectedEof,
    /// Invalid or unsupported DWARF format.
    InvalidFormat(String),
    /// Unsupported DWARF version.
    UnsupportedVersion(u16),
    /// Unknown abbreviation code.
    UnknownAbbreviation(u64),
    /// Unknown attribute form.
    UnknownForm(u16),
    /// Unknown DW_OP opcode.
    UnknownOpcode(u8),
    /// Section not found.
    SectionNotFound(String),
    /// Invalid string offset.
    InvalidStringOffset(u64),
    /// Invalid range list entry.
    InvalidRangeEntry,
    /// Type resolution failure.
    TypeResolutionError(String),
    /// Generic parse error.
    ParseError(String),
}

impl fmt::Display for DwarfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "Unexpected end of DWARF data"),
            Self::InvalidFormat(s) => write!(f, "Invalid DWARF format: {}", s),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported DWARF version: {}", v),
            Self::UnknownAbbreviation(c) => write!(f, "Unknown abbreviation code: {}", c),
            Self::UnknownForm(frm) => write!(f, "Unknown attribute form: 0x{:x}", frm),
            Self::UnknownOpcode(op) => write!(f, "Unknown DW_OP opcode: 0x{:x}", op),
            Self::SectionNotFound(s) => write!(f, "Section not found: {}", s),
            Self::InvalidStringOffset(o) => write!(f, "Invalid string offset: {}", o),
            Self::InvalidRangeEntry => write!(f, "Invalid range list entry"),
            Self::TypeResolutionError(s) => write!(f, "Type resolution error: {}", s),
            Self::ParseError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for DwarfError {}

/// Result alias for DWARF operations.
pub type DwarfResult<T> = Result<T, DwarfError>;

// ============================================================================
// LEB128 Variable-Length Integer Encoding
// ============================================================================

/// Read an unsigned LEB128-encoded integer from the byte slice.
/// Returns (value, bytes_consumed).
pub fn read_uleb128(data: &[u8]) -> DwarfResult<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut pos: usize = 0;
    loop {
        if pos >= data.len() { return Err(DwarfError::UnexpectedEof); }
        let byte = data[pos]; pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 { break; }
        shift += 7;
        if shift >= 64 { return Err(DwarfError::ParseError("ULEB128 too large".into())); }
    }
    Ok((result, pos))
}

/// Read a signed LEB128-encoded integer from the byte slice.
/// Returns (value, bytes_consumed).
pub fn read_sleb128(data: &[u8]) -> DwarfResult<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut pos: usize = 0;
    let size = 64i32;
    loop {
        if pos >= data.len() { return Err(DwarfError::UnexpectedEof); }
        let byte = data[pos]; pos += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < (size as u32) && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            break;
        }
        if shift >= 64 { return Err(DwarfError::ParseError("SLEB128 too large".into())); }
    }
    Ok((result, pos))
}

// ============================================================================
// Low-level reading helpers
// ============================================================================

pub fn read_u8(data: &[u8], offset: &mut usize) -> DwarfResult<u8> {
    if *offset >= data.len() { return Err(DwarfError::UnexpectedEof); }
    let val = data[*offset]; *offset += 1;
    Ok(val)
}

pub fn read_u16(data: &[u8], offset: &mut usize) -> DwarfResult<u16> {
    if *offset + 2 > data.len() { return Err(DwarfError::UnexpectedEof); }
    let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    *offset += 2;
    Ok(val)
}

pub fn read_u32(data: &[u8], offset: &mut usize) -> DwarfResult<u32> {
    if *offset + 4 > data.len() { return Err(DwarfError::UnexpectedEof); }
    let val = u32::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]]);
    *offset += 4;
    Ok(val)
}

pub fn read_u64(data: &[u8], offset: &mut usize) -> DwarfResult<u64> {
    if *offset + 8 > data.len() { return Err(DwarfError::UnexpectedEof); }
    let val = u64::from_le_bytes([
        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3],
        data[*offset + 4], data[*offset + 5], data[*offset + 6], data[*offset + 7],
    ]);
    *offset += 8;
    Ok(val)
}

pub fn read_bytes(data: &[u8], offset: &mut usize, n: usize) -> DwarfResult<Vec<u8>> {
    if *offset + n > data.len() { return Err(DwarfError::UnexpectedEof); }
    let bytes = data[*offset..*offset + n].to_vec();
    *offset += n;
    Ok(bytes)
}

pub fn align_offset(offset: usize, align: usize) -> usize {
    if align == 0 { return offset; }
    (offset + align - 1) & !(align - 1)
}

fn read_address(data: &[u8], offset: &mut usize, addr_size: u8) -> DwarfResult<u64> {
    match addr_size {
        4 => read_u32(data, offset).map(|v| v as u64),
        8 => read_u64(data, offset),
        _ => Err(DwarfError::ParseError(format!("Unsupported address size: {}", addr_size))),
    }
}

// ============================================================================
// Core Data Types
// ============================================================================

/// The value of a DWARF attribute, decoded according to its form.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    Addr(u64),
    Block(Vec<u8>),
    Data(Vec<u8>),
    SData(i64),
    String(String),
    Flag(bool),
    SecOffset(u64),
    Ref(u64),
    ExprLoc(Vec<u8>),
    LocListPtr(u64),
    RangeListPtr(u64),
    StrOffset(u64),
    StrxIndex(u64),
    AddrxIndex(u64),
}

impl AttributeValue {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Addr(v) | Self::SecOffset(v) | Self::Ref(v)
            | Self::StrOffset(v) | Self::LocListPtr(v) | Self::RangeListPtr(v)
            | Self::StrxIndex(v) | Self::AddrxIndex(v) => Some(*v),
            Self::Data(d) if d.len() <= 8 => {
                let mut arr = [0u8; 8];
                arr[..d.len()].copy_from_slice(d);
                Some(u64::from_le_bytes(arr))
            }
            Self::Flag(b) => Some(if *b { 1 } else { 0 }),
            _ => None,
        }
    }
    pub fn as_string(&self) -> Option<&str> {
        match self { Self::String(s) => Some(s), _ => None }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self { Self::Flag(b) => Some(*b), _ => None }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Block(b) | Self::Data(b) | Self::ExprLoc(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_sdata(&self) -> Option<i64> {
        match self { Self::SData(v) => Some(*v), _ => None }
    }
}

impl fmt::Display for AttributeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addr(v) => write!(f, "0x{:016x}", v),
            Self::Block(b) => write!(f, "block[{}]", b.len()),
            Self::Data(d) => write!(f, "data[{}]", d.len()),
            Self::SData(v) => write!(f, "{}", v),
            Self::String(s) => write!(f, "\"{}\"", s),
            Self::Flag(v) => write!(f, "{}", v),
            Self::SecOffset(v) => write!(f, "sec_offset(0x{:x})", v),
            Self::Ref(v) => write!(f, "ref(0x{:x})", v),
            Self::ExprLoc(e) => write!(f, "exprloc[{}]", e.len()),
            Self::LocListPtr(v) => write!(f, "loclist_ptr(0x{:x})", v),
            Self::RangeListPtr(v) => write!(f, "rnglist_ptr(0x{:x})", v),
            Self::StrOffset(v) => write!(f, "strp(0x{:x})", v),
            Self::StrxIndex(v) => write!(f, "strx[{}]", v),
            Self::AddrxIndex(v) => write!(f, "addrx[{}]", v),
        }
    }
}

/// A single attribute within a DIE.
#[derive(Debug, Clone)]
pub struct Attribute {
    pub name: u16,
    pub form: u16,
    pub value: AttributeValue,
}

impl Attribute {
    pub fn new(name: u16, form: u16, value: AttributeValue) -> Self {
        Self { name, form, value }
    }
    pub fn name_str(&self) -> &'static str { attr_name(self.name) }
    pub fn form_str(&self) -> &'static str { form_name(self.form) }
}

/// A Debugging Information Entry (DIE). Represents one program entity.
#[derive(Debug, Clone)]
pub struct DieEntry {
    pub tag: u16,
    pub attributes: Vec<Attribute>,
    pub children: Vec<DieEntry>,
}

impl DieEntry {
    pub fn new(tag: u16) -> Self {
        Self { tag, attributes: Vec::new(), children: Vec::new() }
    }
    pub fn tag_name(&self) -> &'static str { tag_name(self.tag) }
    pub fn attr(&self, name: u16) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }
    pub fn attr_value(&self, name: u16) -> Option<&AttributeValue> {
        self.attr(name).map(|a| &a.value)
    }
    pub fn name(&self) -> Option<&str> {
        self.attr_value(dw_at::NAME).and_then(|v| v.as_string())
    }
    pub fn low_pc(&self) -> Option<u64> {
        self.attr_value(dw_at::LOW_PC).and_then(|v| v.as_u64())
    }
    pub fn high_pc(&self) -> Option<u64> {
        self.attr_value(dw_at::HIGH_PC).and_then(|v| v.as_u64())
    }
    pub fn type_ref(&self) -> Option<u64> {
        self.attr_value(dw_at::TYPE).and_then(|v| v.as_u64())
    }
    pub fn linkage_name(&self) -> Option<&str> {
        self.attr_value(dw_at::LINKAGE_NAME).and_then(|v| v.as_string())
    }
    pub fn byte_size(&self) -> Option<u64> {
        self.attr_value(dw_at::BYTE_SIZE).and_then(|v| v.as_u64())
    }
    pub fn find_all(&self, tag: u16) -> Vec<&DieEntry> {
        let mut result = Vec::new();
        self.collect_by_tag(tag, &mut result);
        result
    }
    fn collect_by_tag<'a>(&'a self, tag: u16, result: &mut Vec<&'a DieEntry>) {
        if self.tag == tag { result.push(self); }
        for child in &self.children { child.collect_by_tag(tag, result); }
    }
}

impl fmt::Display for DieEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_depth(f, 0)
    }
}

impl DieEntry {
    fn fmt_depth(&self, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
        let indent = "  ".repeat(depth);
        writeln!(f, "{}<{}>", indent, tag_name(self.tag))?;
        for attr in &self.attributes {
            writeln!(f, "{}  {} [{}] = {}", indent, attr_name(attr.name), form_name(attr.form), attr.value)?;
        }
        for child in &self.children { child.fmt_depth(f, depth + 1)?; }
        Ok(())
    }
}

// ============================================================================
// Abbreviation Table Types and Parser
// ============================================================================

#[derive(Debug, Clone)]
pub struct AbbrevAttrDecl {
    pub attr: u16,
    pub form: u16,
    pub implicit_const: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AbbrevDecl {
    pub code: u64,
    pub tag: u16,
    pub has_children: bool,
    pub attributes: Vec<AbbrevAttrDecl>,
}

/// Parse an abbreviation table from .debug_abbrev data at the given offset.
pub fn parse_abbrev_table(data: &[u8], offset: u64) -> DwarfResult<HashMap<u64, AbbrevDecl>> {
    let mut table = HashMap::new();
    let mut pos = offset as usize;
    if pos >= data.len() { return Ok(table); }
    loop {
        let (code, consumed) = read_uleb128(&data[pos..])?;
        pos += consumed;
        if code == 0 { break; }
        let (tag, consumed) = read_uleb128(&data[pos..])?;
        pos += consumed;
        if pos >= data.len() { return Err(DwarfError::UnexpectedEof); }
        let has_children = data[pos] != 0; pos += 1;
        let mut attrs = Vec::new();
        loop {
            let (attr, c1) = read_uleb128(&data[pos..])?; pos += c1;
            let (form, c2) = read_uleb128(&data[pos..])?; pos += c2;
            if attr == 0 && form == 0 { break; }
            let implicit_const = if form as u16 == dw_form::IMPLICIT_CONST {
                let (val, c3) = read_sleb128(&data[pos..])?; pos += c3;
                Some(val)
            } else { None };
            attrs.push(AbbrevAttrDecl { attr: attr as u16, form: form as u16, implicit_const });
        }
        table.insert(code, AbbrevDecl { code, tag: tag as u16, has_children, attributes: attrs });
    }
    Ok(table)
}

// ============================================================================
// Compilation Unit Types and Parser
// ============================================================================

#[derive(Debug, Clone)]
pub struct CompilationUnit {
    pub offset: u64,
    pub length: u64,
    pub version: u16,
    pub unit_type: u8,
    pub address_size: u8,
    pub debug_abbrev_offset: u64,
    pub dwo_id: Option<u64>,
    pub entries: Vec<DieEntry>,
}

impl CompilationUnit {
    pub fn find_all(&self, tag: u16) -> Vec<&DieEntry> {
        let mut result = Vec::new();
        for entry in &self.entries { result.extend(entry.find_all(tag)); }
        result
    }
    pub fn source_file(&self) -> Option<&str> {
        self.entries.first().and_then(|e| e.name())
    }
    pub fn comp_dir(&self) -> Option<&str> {
        self.entries.first().and_then(|e| e.attr_value(dw_at::COMP_DIR)).and_then(|v| v.as_string())
    }
    pub fn producer(&self) -> Option<&str> {
        self.entries.first().and_then(|e| e.attr_value(dw_at::PRODUCER)).and_then(|v| v.as_string())
    }
}

/// Parse a single compilation unit from .debug_info at the current position.
pub fn parse_compilation_unit_at(
    data: &[u8], base_offset: u64, debug_abbrev: &[u8],
) -> DwarfResult<CompilationUnit> {
    let mut pos = 0usize;
    let length_raw = read_u32(data, &mut pos)?;
    let (length, is_64bit) = if length_raw == 0xffffffff {
        (read_u64(data, &mut pos)?, true)
    } else if length_raw >= 0xfffffff0 {
        return Err(DwarfError::InvalidFormat(format!("Reserved length: 0x{:x}", length_raw)));
    } else {
        (length_raw as u64, false)
    };
    let cu_end = pos + length as usize;
    let version = read_u16(data, &mut pos)?;

    let (unit_type, address_size, debug_abbrev_offset) = if version >= 5 {
        let ut = read_u8(data, &mut pos)?;
        let asz = read_u8(data, &mut pos)?;
        let abbr_off = if is_64bit { read_u64(data, &mut pos)? } else { read_u32(data, &mut pos)? as u64 };
        (ut, asz, abbr_off)
    } else {
        let abbr_off = if is_64bit { read_u64(data, &mut pos)? } else { read_u32(data, &mut pos)? as u64 };
        let asz = read_u8(data, &mut pos)?;
        (0u8, asz, abbr_off)
    };

    let dwo_id = if version >= 5 {
        match unit_type {
            dw_ut::SKELETON | dw_ut::SPLIT_COMPILE => Some(read_u64(data, &mut pos)?),
            _ => None,
        }
    } else { None };

    let abbrev = parse_abbrev_table(debug_abbrev, debug_abbrev_offset)?;
    let entries = parse_die_children(data, &mut pos, cu_end, &abbrev)?;

    Ok(CompilationUnit {
        offset: base_offset, length, version, unit_type,
        address_size, debug_abbrev_offset, dwo_id, entries,
    })
}

/// Recursively parse DIE children.
fn parse_die_children(
    data: &[u8], offset: &mut usize, end: usize,
    abbrev_table: &HashMap<u64, AbbrevDecl>,
) -> DwarfResult<Vec<DieEntry>> {
    let mut dies = Vec::new();
    while *offset < end {
        let (abbrev_code, consumed) = read_uleb128(&data[*offset..])?;
        *offset += consumed;
        if abbrev_code == 0 { break; }
        let decl = abbrev_table.get(&abbrev_code)
            .ok_or(DwarfError::UnknownAbbreviation(abbrev_code))?;
        let mut attributes = Vec::new();
        for attr_decl in &decl.attributes {
            let value = read_attribute_value(data, offset, attr_decl.form, attr_decl.implicit_const)?;
            attributes.push(Attribute { name: attr_decl.attr, form: attr_decl.form, value });
        }
        let mut die = DieEntry { tag: decl.tag, attributes, children: Vec::new() };
        if decl.has_children {
            die.children = parse_die_children(data, offset, end, abbrev_table)?;
        }
        dies.push(die);
    }
    Ok(dies)
}

// ============================================================================
// Attribute Value Parser -- Complete DW_FORM_* handling
// ============================================================================

/// Read a single attribute value according to its form.
pub fn read_attribute_value(
    data: &[u8], pos: &mut usize, form: u16, implicit_const: Option<i64>,
) -> DwarfResult<AttributeValue> {
    match form {
        dw_form::ADDR => {
            let v = read_u64(data, pos)?;
            Ok(AttributeValue::Addr(v))
        }
        dw_form::BLOCK1 => {
            let len = read_u8(data, pos)? as usize;
            let bytes = read_bytes(data, pos, len)?;
            Ok(AttributeValue::Block(bytes))
        }
        dw_form::BLOCK2 => {
            let len = read_u16(data, pos)? as usize;
            let bytes = read_bytes(data, pos, len)?;
            Ok(AttributeValue::Block(bytes))
        }
        dw_form::BLOCK4 => {
            let len = read_u32(data, pos)? as usize;
            let bytes = read_bytes(data, pos, len)?;
            Ok(AttributeValue::Block(bytes))
        }
        dw_form::BLOCK => {
            let (len, consumed) = read_uleb128(&data[*pos..])?;
            *pos += consumed;
            let bytes = read_bytes(data, pos, len as usize)?;
            Ok(AttributeValue::Block(bytes))
        }
        dw_form::EXPRLOC => {
            let (len, consumed) = read_uleb128(&data[*pos..])?;
            *pos += consumed;
            let bytes = read_bytes(data, pos, len as usize)?;
            Ok(AttributeValue::ExprLoc(bytes))
        }
        dw_form::DATA1 => { let v = read_u8(data, pos)?; Ok(AttributeValue::Data(vec![v])) }
        dw_form::DATA2 => { let v = read_u16(data, pos)?; Ok(AttributeValue::Data(v.to_le_bytes().to_vec())) }
        dw_form::DATA4 => { let v = read_u32(data, pos)?; Ok(AttributeValue::Data(v.to_le_bytes().to_vec())) }
        dw_form::DATA8 => { let v = read_u64(data, pos)?; Ok(AttributeValue::Data(v.to_le_bytes().to_vec())) }
        dw_form::DATA16 => { let bytes = read_bytes(data, pos, 16)?; Ok(AttributeValue::Data(bytes)) }
        dw_form::SDATA => {
            let (val, consumed) = read_sleb128(&data[*pos..])?;
            *pos += consumed;
            Ok(AttributeValue::SData(val))
        }
        dw_form::UDATA => {
            let (val, consumed) = read_uleb128(&data[*pos..])?;
            *pos += consumed;
            Ok(AttributeValue::Data(val.to_le_bytes().to_vec()))
        }
        dw_form::STRING => {
            let start = *pos;
            while *pos < data.len() && data[*pos] != 0 { *pos += 1; }
            if *pos >= data.len() { return Err(DwarfError::UnexpectedEof); }
            let s = std::str::from_utf8(&data[start..*pos])
                .map_err(|e| DwarfError::ParseError(format!("Invalid UTF-8: {}", e)))?;
            *pos += 1;
            Ok(AttributeValue::String(s.to_string()))
        }
        dw_form::STRP => {
            let off = read_u32(data, pos)? as u64;
            Ok(AttributeValue::StrOffset(off))
        }
        dw_form::STRP_SUP => {
            let off = read_u32(data, pos)? as u64;
            Ok(AttributeValue::StrOffset(off))
        }
        dw_form::LINE_STRP => {
            let off = read_u32(data, pos)? as u64;
            Ok(AttributeValue::StrOffset(off))
        }
        dw_form::FLAG => {
            let b = read_u8(data, pos)? != 0;
            Ok(AttributeValue::Flag(b))
        }
        dw_form::FLAG_PRESENT => { Ok(AttributeValue::Flag(true)) }
        dw_form::REF1 => { let v = read_u8(data, pos)? as u64; Ok(AttributeValue::Ref(v)) }
        dw_form::REF2 => { let v = read_u16(data, pos)? as u64; Ok(AttributeValue::Ref(v)) }
        dw_form::REF4 => { let v = read_u32(data, pos)? as u64; Ok(AttributeValue::Ref(v)) }
        dw_form::REF8 => { let v = read_u64(data, pos)?; Ok(AttributeValue::Ref(v)) }
        dw_form::REF_UDATA => {
            let (val, consumed) = read_uleb128(&data[*pos..])?;
            *pos += consumed;
            Ok(AttributeValue::Ref(val))
        }
        dw_form::REF_ADDR => {
            let v = read_u64(data, pos)?;
            Ok(AttributeValue::Ref(v))
        }
        dw_form::REF_SIG8 => { let _ = read_u64(data, pos)?; Ok(AttributeValue::Ref(0)) }
        dw_form::REF_SUP4 => { let v = read_u32(data, pos)? as u64; Ok(AttributeValue::Ref(v)) }
        dw_form::REF_SUP8 => { let v = read_u64(data, pos)?; Ok(AttributeValue::Ref(v)) }
        dw_form::SEC_OFFSET => {
            let off = read_u32(data, pos)? as u64;
            Ok(AttributeValue::SecOffset(off))
        }
        dw_form::STRX | dw_form::STRX1 | dw_form::STRX2 | dw_form::STRX3 | dw_form::STRX4 => {
            let idx = match form {
                dw_form::STRX1 => read_u8(data, pos)? as u64,
                dw_form::STRX2 => read_u16(data, pos)? as u64,
                dw_form::STRX3 => {
                    let b1 = read_u8(data, pos)? as u64;
                    let b2 = read_u8(data, pos)? as u64;
                    let b3 = read_u8(data, pos)? as u64;
                    b1 | (b2 << 8) | (b3 << 16)
                }
                dw_form::STRX4 => read_u32(data, pos)? as u64,
                _ => { let (v, c) = read_uleb128(&data[*pos..])?; *pos += c; v }
            };
            Ok(AttributeValue::StrxIndex(idx))
        }
        dw_form::ADDRX | dw_form::ADDRX1 | dw_form::ADDRX2 | dw_form::ADDRX3 | dw_form::ADDRX4 => {
            let idx = match form {
                dw_form::ADDRX1 => read_u8(data, pos)? as u64,
                dw_form::ADDRX2 => read_u16(data, pos)? as u64,
                dw_form::ADDRX3 => {
                    let b1 = read_u8(data, pos)? as u64;
                    let b2 = read_u8(data, pos)? as u64;
                    let b3 = read_u8(data, pos)? as u64;
                    b1 | (b2 << 8) | (b3 << 16)
                }
                dw_form::ADDRX4 => read_u32(data, pos)? as u64,
                _ => { let (v, c) = read_uleb128(&data[*pos..])?; *pos += c; v }
            };
            Ok(AttributeValue::AddrxIndex(idx))
        }
        dw_form::IMPLICIT_CONST => {
            Ok(AttributeValue::SData(implicit_const.unwrap_or(0)))
        }
        dw_form::LOCLISTX => {
            let (idx, consumed) = read_uleb128(&data[*pos..])?;
            *pos += consumed;
            Ok(AttributeValue::LocListPtr(idx))
        }
        dw_form::RNGLISTX => {
            let (idx, consumed) = read_uleb128(&data[*pos..])?;
            *pos += consumed;
            Ok(AttributeValue::RangeListPtr(idx))
        }
        dw_form::INDIRECT => {
            let (actual_form, consumed) = read_uleb128(&data[*pos..])?;
            *pos += consumed;
            read_attribute_value(data, pos, actual_form as u16, None)
        }
        _ => Err(DwarfError::UnknownForm(form)),
    }
}

// ============================================================================
// Line Number Program
// ============================================================================

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub directory_index: u32,
    pub last_modified: u64,
    pub length: u64,
}

#[derive(Debug, Clone)]
pub struct LineProgramHeader {
    pub unit_length: u64,
    pub version: u16,
    pub header_length: u64,
    pub min_insn_length: u8,
    pub max_ops_per_insn: u8,
    pub default_is_stmt: bool,
    pub line_base: i8,
    pub line_range: u8,
    pub opcode_base: u8,
    pub std_opcode_lengths: Vec<u8>,
    pub directories: Vec<String>,
    pub file_names: Vec<FileEntry>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LineEntry {
    pub address: u64,
    pub file_index: u32,
    pub line: u32,
    pub column: u32,
    pub is_stmt: bool,
    pub basic_block: bool,
    pub end_sequence: bool,
    pub prologue_end: bool,
    pub epilogue_begin: bool,
}

#[derive(Debug, Clone)]
struct LineState {
    address: u64,
    op_index: u64,
    file: u64,
    line: u64,
    column: u64,
    is_stmt: bool,
    basic_block: bool,
    end_sequence: bool,
    prologue_end: bool,
    epilogue_begin: bool,
    isa: u64,
    discriminator: u64,
}

impl LineState {
    fn new(default_is_stmt: bool) -> Self {
        Self { address: 0, op_index: 0, file: 1, line: 1, column: 0,
               is_stmt: default_is_stmt, basic_block: false, end_sequence: false,
               prologue_end: false, epilogue_begin: false, isa: 0, discriminator: 0 }
    }
    fn reset(&mut self, default_is_stmt: bool) {
        self.address = 0; self.op_index = 0; self.file = 1; self.line = 1;
        self.column = 0; self.is_stmt = default_is_stmt; self.basic_block = false;
        self.end_sequence = false; self.prologue_end = false;
        self.epilogue_begin = false; self.isa = 0; self.discriminator = 0;
    }
    fn to_entry(&self) -> LineEntry {
        LineEntry {
            address: self.address, file_index: self.file as u32,
            line: self.line as u32, column: self.column as u32,
            is_stmt: self.is_stmt, basic_block: self.basic_block,
            end_sequence: self.end_sequence, prologue_end: self.prologue_end,
            epilogue_begin: self.epilogue_begin,
        }
    }
}

/// Parse the header of a line number program from .debug_line data.
pub fn parse_line_program_header(data: &[u8]) -> DwarfResult<(LineProgramHeader, usize)> {
    let mut pos = 0usize;
    let length_raw = read_u32(data, &mut pos)?;
    let (unit_length, is_64bit) = if length_raw == 0xFFFF_FFFF {
        (read_u64(data, &mut pos)?, true)
    } else { (length_raw as u64, false) };
    let version = read_u16(data, &mut pos)?;
    let header_length = if is_64bit { read_u64(data, &mut pos)? } else { read_u32(data, &mut pos)? as u64 };
    let program_start = pos + header_length as usize;
    let min_insn_length = read_u8(data, &mut pos)?;
    let max_ops_per_insn = if version >= 4 { read_u8(data, &mut pos)? } else { 1u8 };
    let default_is_stmt = read_u8(data, &mut pos)? != 0;
    let line_base = read_u8(data, &mut pos)? as i8;
    let line_range = read_u8(data, &mut pos)?;
    let opcode_base = read_u8(data, &mut pos)?;
    let mut std_opcode_lengths = Vec::new();
    for _ in 1..opcode_base { std_opcode_lengths.push(read_u8(data, &mut pos)?); }

    let mut directories = Vec::new();
    if version >= 5 {
        let dir_fmt_count = read_u8(data, &mut pos)?;
        for _ in 0..dir_fmt_count {
            let _ = read_uleb128(&data[pos..])?; pos += 1;
            let _ = read_uleb128(&data[pos..])?; pos += 1;
        }
        let dir_count = read_uleb128(&data[pos..])?.0 as usize; pos += 1;
        for _ in 0..dir_count {
            let s = read_null_str(data, &mut pos)?;
            directories.push(s);
        }
    } else {
        while pos < data.len() && data[pos] != 0 {
            let s = read_null_str(data, &mut pos)?;
            directories.push(s);
        }
        if pos < data.len() { pos += 1; }
    }

    let mut file_names = Vec::new();
    if version >= 5 {
        let file_fmt_count = read_u8(data, &mut pos)?;
        for _ in 0..file_fmt_count {
            let _ = read_uleb128(&data[pos..])?; pos += 1;
            let _ = read_uleb128(&data[pos..])?; pos += 1;
        }
        let file_count = read_uleb128(&data[pos..])?.0 as usize; pos += 1;
        for _ in 0..file_count {
            let name = read_null_str(data, &mut pos)?;
            let (dir_idx, c1) = read_uleb128(&data[pos..])?; pos += c1;
            let (_mtime, c2) = read_uleb128(&data[pos..])?; pos += c2;
            let (_len, c3) = read_uleb128(&data[pos..])?; pos += c3;
            file_names.push(FileEntry { name, directory_index: dir_idx as u32, last_modified: 0, length: 0 });
        }
    } else {
        while pos < data.len() && data[pos] != 0 {
            let name = read_null_str(data, &mut pos)?;
            let (dir_idx, _) = read_uleb128(&data[pos..])?;
            let (mod_time, _) = read_uleb128(&data[pos..])?;
            let (length, _) = read_uleb128(&data[pos..])?;
            file_names.push(FileEntry { name, directory_index: dir_idx as u32, last_modified: mod_time, length });
        }
        if pos < data.len() { pos += 1; let _ = pos; }
    }

    Ok((LineProgramHeader { unit_length, version, header_length, min_insn_length,
        max_ops_per_insn, default_is_stmt, line_base, line_range, opcode_base,
        std_opcode_lengths, directories, file_names }, program_start))
}

fn read_null_str(data: &[u8], pos: &mut usize) -> DwarfResult<String> {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 { *pos += 1; }
    if *pos >= data.len() { return Err(DwarfError::UnexpectedEof); }
    let s = std::str::from_utf8(&data[start..*pos])
        .map_err(|e| DwarfError::ParseError(format!("Invalid UTF-8: {}", e)))?;
    *pos += 1;
    Ok(s.to_string())
}

/// Execute a DWARF line number program and produce a line number matrix.
pub fn execute_line_program(header: &LineProgramHeader, data: &[u8]) -> DwarfResult<Vec<LineEntry>> {
    let mut matrix = Vec::new();
    let mut state = LineState::new(header.default_is_stmt);
    let mut offset = 0usize;
    while offset < data.len() {
        let opcode = data[offset]; offset += 1;
        if opcode == 0 {
            let (length, consumed) = read_uleb128(&data[offset..])?;
            offset += consumed;
            let ext_end = offset + length as usize;
            if offset >= data.len() { break; }
            let ext_op = data[offset]; offset += 1;
            match ext_op {
                dw_lne::END_SEQUENCE => {
                    state.end_sequence = true;
                    matrix.push(state.to_entry());
                    state.reset(header.default_is_stmt);
                }
                dw_lne::SET_ADDRESS => {
                    state.address = read_u64(data, &mut offset)?;
                    state.op_index = 0;
                }
                dw_lne::DEFINE_FILE => {
                    let _ = read_null_str(data, &mut offset);
                    let _ = read_uleb128(&data[offset..]);
                    let _ = read_uleb128(&data[offset..]);
                    let _ = read_uleb128(&data[offset..]);
                }
                dw_lne::SET_DISCRIMINATOR => {
                    let (val, c) = read_uleb128(&data[offset..])?;
                    let _ = c; state.discriminator = val;
                }
                _ => {}
            }
            offset = ext_end;
        } else if opcode < header.opcode_base {
            match opcode {
                dw_lns::COPY => {
                    matrix.push(state.to_entry());
                    state.basic_block = false; state.prologue_end = false;
                    state.epilogue_begin = false; state.discriminator = 0;
                }
                dw_lns::ADVANCE_PC => {
                    let (adv, c) = read_uleb128(&data[offset..])?; offset += c;
                    state.address += adv * header.min_insn_length as u64;
                }
                dw_lns::ADVANCE_LINE => {
                    let (adv, c) = read_sleb128(&data[offset..])?; offset += c;
                    state.line = ((state.line as i64) + adv) as u64;
                }
                dw_lns::SET_FILE => {
                    let (f, c) = read_uleb128(&data[offset..])?; offset += c;
                    state.file = f;
                }
                dw_lns::SET_COLUMN => {
                    let (col, c) = read_uleb128(&data[offset..])?; offset += c;
                    state.column = col;
                }
                dw_lns::NEGATE_STMT => { state.is_stmt = !state.is_stmt; }
                dw_lns::SET_BASIC_BLOCK => { state.basic_block = true; }
                dw_lns::CONST_ADD_PC => {
                    let adjust = ((255 - header.opcode_base) / header.line_range) as u64;
                    state.address += adjust * header.min_insn_length as u64;
                }
                dw_lns::FIXED_ADVANCE_PC => {
                    let adv = read_u16(data, &mut offset)? as u64;
                    state.address += adv; state.op_index = 0;
                }
                dw_lns::SET_PROLOGUE_END => { state.prologue_end = true; }
                dw_lns::SET_EPILOGUE_BEGIN => { state.epilogue_begin = true; }
                dw_lns::SET_ISA => {
                    let (v, c) = read_uleb128(&data[offset..])?; offset += c;
                    state.isa = v;
                }
                _ => {
                    if (opcode as usize) > 0 && (opcode as usize) <= header.std_opcode_lengths.len() {
                        let skip = header.std_opcode_lengths[(opcode - 1) as usize] as usize;
                        for _ in 0..skip { let _ = read_uleb128(&data[offset..]); }
                    }
                }
            }
        } else {
            let adjusted = (opcode - header.opcode_base) as u64;
            let addr_inc = (adjusted / header.line_range as u64) * header.min_insn_length as u64;
            let line_inc = header.line_base as i64 + (adjusted % header.line_range as u64) as i64;
            state.address += addr_inc;
            state.line = ((state.line as i64) + line_inc) as u64;
            state.op_index = 0;
            matrix.push(state.to_entry());
            state.basic_block = false; state.prologue_end = false;
            state.epilogue_begin = false; state.discriminator = 0;
        }
    }
    Ok(matrix)
}

// ============================================================================
// Call Frame Information (CIE / FDE)
// ============================================================================

#[derive(Debug, Clone)]
pub struct CieEntry {
    pub offset: u64,
    pub length: u64,
    pub cie_id: u64,
    pub version: u8,
    pub augmentation: String,
    pub address_size: u8,
    pub segment_size: u8,
    pub code_alignment_factor: u64,
    pub data_alignment_factor: i64,
    pub return_address_register: u64,
    pub initial_instructions: Vec<u8>,
    pub pointer_encoding: Option<u8>,
    pub lsda_encoding: Option<u8>,
    pub personality: Option<u64>,
    pub fde_encoding: Option<u8>,
    pub is_64bit: bool,
}

#[derive(Debug, Clone)]
pub struct FdeEntry {
    pub offset: u64,
    pub length: u64,
    pub cie_offset: u64,
    pub initial_location: u64,
    pub address_range: u64,
    pub instructions: Vec<u8>,
    pub augmentation_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum RegisterRule {
    Offset(i64),
    Register(u64),
    Expression(Vec<u8>),
    SameValue,
    Undefined,
    ValOffset(i64),
    ValExpression(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct FrameTableRow {
    pub pc: u64,
    pub cfa_register: u64,
    pub cfa_offset: i64,
    pub cfa_expression: Option<Vec<u8>>,
    pub register_rules: HashMap<u64, RegisterRule>,
}

/// Parse a CIE from .debug_frame section data.
pub fn parse_cie(data: &[u8]) -> DwarfResult<CieEntry> {
    let mut pos = 0usize;
    let length = read_u32(data, &mut pos)? as u64;
    if length == 0xFFFFFFFF { return Err(DwarfError::UnsupportedVersion(0)); }
    let end_entry = pos + length as usize;
    let cie_id = read_u32(data, &mut pos)? as u64;
    let version = read_u8(data, &mut pos)?;
    let aug_start = pos;
    while pos < data.len() && data[pos] != 0 { pos += 1; }
    let augmentation = std::str::from_utf8(&data[aug_start..pos]).unwrap_or("").to_string();
    if pos < data.len() { pos += 1; }

    let (address_size, segment_size) = if version >= 4 {
        (read_u8(data, &mut pos)?, read_u8(data, &mut pos)?)
    } else { (8u8, 0u8) };

    let (code_alignment_factor, c1) = read_uleb128(&data[pos..])?; pos += c1;
    let (data_alignment_factor, c2) = read_sleb128(&data[pos..])?; pos += c2;
    let return_address_register = if version >= 3 {
        let (rar, c3) = read_uleb128(&data[pos..])?; pos += c3; rar
    } else { read_u8(data, &mut pos)? as u64 };

    let mut pointer_encoding = None;
    let mut lsda_encoding = None;
    let mut personality = None;
    let fde_encoding = None;

    let aug_bytes = augmentation.as_bytes();
    if aug_bytes.first() == Some(&b'z') {
        let (aug_len, c4) = read_uleb128(&data[pos..])?; pos += c4;
        let aug_data_end = pos + aug_len as usize;
        for &ch in &aug_bytes[1..] {
            match ch {
                b'R' => { if pos < data.len() { pointer_encoding = Some(data[pos]); pos += 1; } }
                b'L' => { if pos < data.len() { lsda_encoding = Some(data[pos]); pos += 1; } }
                b'P' => {
                    if pos < data.len() {
                        let enc = data[pos]; pos += 1;
                        personality = Some(read_encoded_ptr(data, &mut pos, enc)?);
                    }
                }
                _ => {}
            }
        }
        pos = aug_data_end;
    }

    let initial_instructions = if pos < end_entry && end_entry <= data.len() {
        data[pos..end_entry].to_vec()
    } else { Vec::new() };

    Ok(CieEntry {
        offset: 0, length, cie_id, version, augmentation,
        address_size, segment_size, code_alignment_factor,
        data_alignment_factor, return_address_register,
        initial_instructions, pointer_encoding, lsda_encoding,
        personality, fde_encoding, is_64bit: false,
    })
}

/// Parse an FDE from .debug_frame data, using the CIE table for lookups.
pub fn parse_fde(data: &[u8], cies: &HashMap<u64, CieEntry>) -> DwarfResult<FdeEntry> {
    let mut pos = 0usize;
    let length = read_u32(data, &mut pos)? as u64;
    if length == 0xFFFFFFFF { return Err(DwarfError::UnsupportedVersion(0)); }
    let end_offset = pos + length as usize;
    let cie_pointer = read_u32(data, &mut pos)? as u64;
    let cie = cies.get(&cie_pointer)
        .ok_or_else(|| DwarfError::ParseError(format!("FDE references unknown CIE at 0x{:x}", cie_pointer)))?;
    let addr_size = cie.address_size;
    let initial_location = read_address(data, &mut pos, addr_size)?;
    let address_range = read_address(data, &mut pos, addr_size)?;

    let mut aug_data = None;
    if cie.augmentation.as_bytes().first() == Some(&b'z') {
        let (aug_len, c3) = read_uleb128(&data[pos..])?; pos += c3;
        aug_data = Some(data[pos..pos + aug_len as usize].to_vec());
        pos += aug_len as usize;
    }

    let instructions = if pos < end_offset && end_offset <= data.len() {
        data[pos..end_offset].to_vec()
    } else { Vec::new() };

    Ok(FdeEntry {
        offset: 0, length, cie_offset: cie_pointer,
        initial_location, address_range, instructions, augmentation_data: aug_data,
    })
}

fn read_encoded_ptr(data: &[u8], pos: &mut usize, encoding: u8) -> DwarfResult<u64> {
    let format = encoding & 0x0f;
    let application = encoding & 0x70;
    let base = match application {
        0x10 => *pos as u64,
        0x20 | 0x30 | 0x40 | 0x50 => 0,
        _ => 0,
    };
    let val = match format {
        0x00 => 0u64,
        0x01 => { let (v, c) = read_uleb128(&data[*pos..])?; *pos += c; v }
        0x02 => read_u16(data, pos)? as u64,
        0x03 => read_u32(data, pos)? as u64,
        0x04 => read_u64(data, pos)?,
        0x09 => { let (v, c) = read_sleb128(&data[*pos..])?; *pos += c; v as u64 }
        0x0a => read_u16(data, pos)? as u64,
        0x0b => read_u32(data, pos)? as u64,
        0x0c => read_u64(data, pos)?,
        _ => return Err(DwarfError::ParseError("Unknown pointer encoding".into())),
    };
    Ok(base.wrapping_add(val))
}

// ============================================================================
// DWARF Expression Evaluator
// ============================================================================

/// Evaluate a DWARF expression, returning computed pieces as (value, size_in_bytes).
pub fn evaluate_dwarf_expression(
    ops: &[u8], frame_base: u64, registers: &HashMap<u16, u64>,
) -> DwarfResult<Vec<(u64, u64)>> {
    let mut pos = 0usize;
    let mut pieces: Vec<(u64, u64)> = Vec::new();
    let mut stack: Vec<u64> = Vec::new();
    while pos < ops.len() {
        let opcode = ops[pos]; pos += 1;
        match opcode {
            dw_op::ADDR => {
                let addr = read_u64(ops, &mut pos)?;
                stack.push(addr);
            }
            dw_op::DEREF => {
                let addr = stack.pop().unwrap_or(0);
                stack.push(addr);
            }
            dw_op::CONST1U => { if pos < ops.len() { stack.push(ops[pos] as u64); pos += 1; } }
            dw_op::CONST1S => { if pos < ops.len() { stack.push(ops[pos] as i8 as u64); pos += 1; } }
            dw_op::CONST2U => {
                if pos + 2 <= ops.len() {
                    stack.push(u16::from_le_bytes([ops[pos], ops[pos+1]]) as u64); pos += 2;
                }
            }
            dw_op::CONST4U => {
                if pos + 4 <= ops.len() {
                    stack.push(u32::from_le_bytes(ops[pos..pos+4].try_into().unwrap()) as u64); pos += 4;
                }
            }
            dw_op::CONST8U => {
                if pos + 8 <= ops.len() {
                    stack.push(u64::from_le_bytes(ops[pos..pos+8].try_into().unwrap())); pos += 8;
                }
            }
            dw_op::CONSTU => {
                let (val, consumed) = read_uleb128(&ops[pos..])?;
                pos += consumed; stack.push(val);
            }
            dw_op::CONSTS => {
                let (val, consumed) = read_sleb128(&ops[pos..])?;
                pos += consumed; stack.push(val as u64);
            }
            dw_op::DUP => { if let Some(&top) = stack.last() { stack.push(top); } }
            dw_op::DROP => { stack.pop(); }
            dw_op::OVER => {
                if stack.len() >= 2 { let v = stack[stack.len() - 2]; stack.push(v); }
            }
            dw_op::PICK => {
                if pos < ops.len() {
                    let idx = ops[pos] as usize; pos += 1;
                    if idx < stack.len() { let v = stack[stack.len() - 1 - idx]; stack.push(v); }
                }
            }
            dw_op::SWAP => {
                let len = stack.len();
                if len >= 2 { stack.swap(len - 1, len - 2); }
            }
            dw_op::ROT => {
                let len = stack.len();
                if len >= 3 {
                    let a = stack[len - 3]; let b = stack[len - 2]; let c = stack[len - 1];
                    stack[len - 3] = b; stack[len - 2] = c; stack[len - 1] = a;
                }
            }
            dw_op::ABS => { if let Some(v) = stack.pop() { stack.push(v); } }
            dw_op::AND => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(a & b); } }
            dw_op::DIV => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(if b != 0 { (a as i64 / b as i64) as u64 } else { 0 }); } }
            dw_op::MINUS => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(a.wrapping_sub(b)); } }
            dw_op::MOD => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(if b != 0 { a % b } else { 0 }); } }
            dw_op::MUL => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(a.wrapping_mul(b)); } }
            dw_op::NEG => { if let Some(v) = stack.pop() { stack.push(v.wrapping_neg()); } }
            dw_op::NOT => { if let Some(v) = stack.pop() { stack.push(!v); } }
            dw_op::OR => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(a | b); } }
            dw_op::PLUS => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(a.wrapping_add(b)); } }
            dw_op::PLUS_UCONST => { if let Some(v) = stack.pop() { let (cst, c) = read_uleb128(&ops[pos..])?; pos += c; stack.push(v.wrapping_add(cst)); } }
            dw_op::SHL => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(a.wrapping_shl(b as u32)); } }
            dw_op::SHR => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(a.wrapping_shr(b as u32)); } }
            dw_op::SHRA => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap() as i64; stack.push(a.wrapping_shr(b as u32) as u64); } }
            dw_op::XOR => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(a ^ b); } }
            dw_op::BRA => {
                if pos + 2 > ops.len() { return Err(DwarfError::UnexpectedEof); }
                let target = i16::from_le_bytes([ops[pos], ops[pos + 1]]);
                if let Some(v) = stack.pop() {
                    if v != 0 { pos = ((pos as i64) + target as i64) as usize - 2; }
                }
                pos += 2;
            }
            dw_op::EQ => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(if a == b { 1 } else { 0 }); } }
            dw_op::GE => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(if a >= b { 1 } else { 0 }); } }
            dw_op::GT => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(if a > b { 1 } else { 0 }); } }
            dw_op::LE => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(if a <= b { 1 } else { 0 }); } }
            dw_op::LT => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(if a < b { 1 } else { 0 }); } }
            dw_op::NE => { if stack.len() >= 2 { let b = stack.pop().unwrap(); let a = stack.pop().unwrap(); stack.push(if a != b { 1 } else { 0 }); } }
            dw_op::SKIP => {
                if pos + 2 > ops.len() { return Err(DwarfError::UnexpectedEof); }
                let target = i16::from_le_bytes([ops[pos], ops[pos + 1]]);
                pos = ((pos as i64) + target as i64) as usize - 2;
                pos += 2;
            }
            dw_op::REGX => {
                let (reg, consumed) = read_uleb128(&ops[pos..])?; pos += consumed;
                let val = registers.get(&(reg as u16)).copied().unwrap_or(0);
                stack.push(val);
            }
            dw_op::FBREG => {
                let (off, consumed) = read_sleb128(&ops[pos..])?; pos += consumed;
                stack.push((frame_base as i64 + off) as u64);
            }
            dw_op::BREGX => {
                let (reg, c1) = read_uleb128(&ops[pos..])?; pos += c1;
                let (off, c2) = read_sleb128(&ops[pos..])?; pos += c2;
                let base = registers.get(&(reg as u16)).copied().unwrap_or(0);
                stack.push((base as i64 + off) as u64);
            }
            dw_op::PIECE => {
                let (size, consumed) = read_uleb128(&ops[pos..])?; pos += consumed;
                if let Some(addr) = stack.pop() { pieces.push((addr, size)); }
            }
            dw_op::BIT_PIECE => {
                let (size, c1) = read_uleb128(&ops[pos..])?; pos += c1;
                let (off_bits, c2) = read_uleb128(&ops[pos..])?; pos += c2;
                if let Some(addr) = stack.pop() { pieces.push((addr, size * 8 + off_bits)); }
            }
            dw_op::NOP => {}
            dw_op::PUSH_OBJECT_ADDRESS => { stack.push(0); }
            dw_op::CALL2 => { pos += 2; }
            dw_op::CALL4 => { pos += 4; }
            dw_op::CALL_REF => { pos += 4; }
            dw_op::FORM_TLS_ADDRESS => { if let Some(v) = stack.pop() { stack.push(v); } }
            dw_op::CALL_FRAME_CFA => { stack.push(frame_base); }
            dw_op::IMPLICIT_VALUE => {
                let (len, consumed) = read_uleb128(&ops[pos..])?; pos += consumed;
                pos += len as usize;
            }
            dw_op::STACK_VALUE => {
                if let Some(val) = stack.pop() { pieces.push((val, 0)); }
            }
            dw_op::IMPLICIT_POINTER => {
                let _ = read_u64(ops, &mut pos)?;
                let (_, c) = read_sleb128(&ops[pos..])?; pos += c;
            }
            dw_op::ADDRX => {
                let (idx, c) = read_uleb128(&ops[pos..])?; pos += c;
                stack.push(idx);
            }
            dw_op::CONSTX => {
                let (_, c) = read_uleb128(&ops[pos..])?; pos += c;
            }
            dw_op::ENTRY_VALUE => {
                let (len, c) = read_uleb128(&ops[pos..])?; pos += c;
                pos += len as usize;
            }
            _ if dw_op::is_lit(opcode) => { stack.push(dw_op::lit_value(opcode)); }
            _ if dw_op::is_reg(opcode) => {
                let reg = dw_op::reg_value(opcode);
                if let Some(&val) = registers.get(&reg) { stack.push(val); }
                else { stack.push(0); }
            }
            _ if dw_op::is_breg(opcode) => {
                let reg = dw_op::breg_value(opcode);
                let (off, c) = read_sleb128(&ops[pos..])?; pos += c;
                let base = registers.get(&reg).copied().unwrap_or(0);
                stack.push((base as i64 + off) as u64);
            }
            _ => {}
        }
    }
    // If the expression didn't produce explicit pieces (PIECE/STACK_VALUE),
    // the result is whatever remains on the stack.
    if pieces.is_empty() {
        if let Some(&val) = stack.last() {
            let size = stack.len() as u64;
            pieces.push((val, size));
        }
    }
    Ok(pieces)
}

// ============================================================================
// Section-specific Data Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct RangeEntry { pub begin: u64, pub end: u64 }

#[derive(Debug, Clone)]
pub struct ArangeEntry { pub cu_offset: u64, pub ranges: Vec<RangeEntry> }

#[derive(Debug, Clone)]
pub struct ArangeTable {
    pub unit_length: u64,
    pub version: u16,
    pub debug_info_offset: u64,
    pub address_size: u8,
    pub segment_size: u8,
    pub entries: Vec<ArangeEntry>,
}

#[derive(Debug, Clone)]
pub struct LocationListEntry { pub begin: u64, pub end: u64, pub expression: Vec<u8> }

#[derive(Debug, Clone)]
pub struct LocList { pub entries: Vec<LocationListEntry> }

#[derive(Debug, Clone)]
pub enum MacroEntry {
    Define { line: u64, name: String, value: String },
    Undef { line: u64, name: String },
    StartFile { line: u64, file: u64 },
    EndFile,
    Include { line: u64, file: u64 },
    Import { offset: u64 },
}

#[derive(Debug, Clone)]
pub struct PubnamesEntry { pub cu_offset: u64, pub die_offset: u64, pub name: String }

// ============================================================================
// .debug_ranges (DWARF 4)
// ============================================================================

/// Parse .debug_ranges data at the given offset with the given address size.
pub fn parse_debug_ranges(data: &[u8], offset: u64, address_size: u8) -> DwarfResult<Vec<RangeEntry>> {
    let mut ranges = Vec::new();
    let mut pos = offset as usize;
    let asz = address_size as usize;
    loop {
        if pos + asz * 2 > data.len() { break; }
        let begin = match asz { 4 => u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64, 8 => u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()), _ => break }; pos += asz;
        let end = match asz { 4 => u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64, 8 => u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()), _ => break }; pos += asz;
        if begin == 0 && end == 0 { break; }
        if begin == u64::MAX { continue; }
        ranges.push(RangeEntry { begin, end });
    }
    Ok(ranges)
}

// ============================================================================
// .debug_rnglists (DWARF 5)
// ============================================================================

pub fn parse_debug_rnglists(data: &[u8], offset: u64, address_size: u8) -> DwarfResult<Vec<RangeEntry>> {
    let mut ranges = Vec::new();
    let mut pos = offset as usize;
    let mut base: u64 = 0;
    let asz = address_size as usize;
    loop {
        if pos >= data.len() { break; }
        let kind = data[pos]; pos += 1;
        match kind {
            dw_rle::END_OF_LIST => break,
            dw_rle::BASE_ADDRESSX => { let (idx, c) = read_uleb128(&data[pos..])?; pos += c; base = idx; }
            dw_rle::STARTX_ENDX => {
                let (s, c1) = read_uleb128(&data[pos..])?; pos += c1;
                let (e, c2) = read_uleb128(&data[pos..])?; pos += c2;
                ranges.push(RangeEntry { begin: s, end: e });
            }
            dw_rle::STARTX_LENGTH => {
                let (s, c1) = read_uleb128(&data[pos..])?; pos += c1;
                let (len, c2) = read_uleb128(&data[pos..])?; pos += c2;
                ranges.push(RangeEntry { begin: s, end: s + len });
            }
            dw_rle::OFFSET_PAIR => {
                let (so, c1) = read_uleb128(&data[pos..])?; pos += c1;
                let (eo, c2) = read_uleb128(&data[pos..])?; pos += c2;
                ranges.push(RangeEntry { begin: base + so, end: base + eo });
            }
            dw_rle::BASE_ADDRESS => {
                base = match asz { 4 => u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64, 8 => u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()), _ => break, }; pos += asz;
            }
            dw_rle::START_END => {
                let b = match asz { 4 => u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64, 8 => u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()), _ => break, }; pos += asz;
                let e = match asz { 4 => u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64, 8 => u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()), _ => break, }; pos += asz;
                ranges.push(RangeEntry { begin: b, end: e });
            }
            dw_rle::START_LENGTH => {
                let b = match asz { 4 => u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64, 8 => u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()), _ => break, }; pos += asz;
                let (len, c) = read_uleb128(&data[pos..])?; pos += c;
                ranges.push(RangeEntry { begin: b, end: b + len });
            }
            _ => break,
        }
    }
    Ok(ranges)
}

// ============================================================================
// .debug_aranges
// ============================================================================

pub fn parse_debug_aranges(data: &[u8]) -> DwarfResult<Vec<ArangeTable>> {
    let mut tables = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= data.len() {
        let length32 = read_u32(data, &mut pos)?;
        if length32 == 0 { break; }
        let unit_length = if length32 == 0xffffffff { read_u64(data, &mut pos)? } else { length32 as u64 };
        let table_end = pos + unit_length as usize;
        let version = read_u16(data, &mut pos)?;
        let debug_info_offset = if length32 == 0xffffffff { read_u64(data, &mut pos)? } else { read_u32(data, &mut pos)? as u64 };
        let address_size = read_u8(data, &mut pos)?;
        let segment_size = read_u8(data, &mut pos)?;
        pos = align_offset(pos, address_size as usize * 2);
        let asz = address_size as usize;
        let mut entries = Vec::new();
        let mut current_ranges = Vec::new();
        while pos + asz * 2 <= table_end {
            if segment_size > 0 { let _ = read_u32(data, &mut pos)?; }
            let addr = match asz { 4 => read_u32(data, &mut pos)? as u64, 8 => read_u64(data, &mut pos)?, _ => break };
            let len = match asz { 4 => read_u32(data, &mut pos)? as u64, 8 => read_u64(data, &mut pos)?, _ => break };
            if addr == 0 && len == 0 {
                if !current_ranges.is_empty() { entries.push(ArangeEntry { cu_offset: debug_info_offset, ranges: current_ranges.clone() }); }
                break;
            }
            current_ranges.push(RangeEntry { begin: addr, end: addr + len });
        }
        tables.push(ArangeTable { unit_length, version, debug_info_offset, address_size, segment_size, entries });
        pos = table_end;
    }
    Ok(tables)
}

// ============================================================================
// .debug_loc (DWARF 4) and .debug_loclists (DWARF 5)
// ============================================================================

pub fn parse_debug_loc(data: &[u8], offset: u64, addr_size: u8) -> DwarfResult<LocList> {
    let mut entries = Vec::new();
    let mut pos = offset as usize;
    let asz = addr_size as usize;
    loop {
        if pos + asz * 2 + 2 > data.len() { break; }
        let begin = if asz == 4 { u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64 } else { u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()) }; pos += asz;
        let end = if asz == 4 { u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64 } else { u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()) }; pos += asz;
        if begin == 0 && end == 0 { break; }
        let expr_len = u16::from_le_bytes([data[pos], data[pos+1]]) as usize; pos += 2;
        if pos + expr_len > data.len() { break; }
        let expression = data[pos..pos+expr_len].to_vec(); pos += expr_len;
        entries.push(LocationListEntry { begin, end, expression });
    }
    Ok(LocList { entries })
}

pub fn parse_debug_loclists(data: &[u8], offset: u64, addr_size: u8) -> DwarfResult<LocList> {
    let mut entries = Vec::new();
    let mut pos = offset as usize;
    let mut base: u64 = 0;
    let asz = addr_size as usize;
    loop {
        if pos >= data.len() { break; }
        let kind = data[pos]; pos += 1;
        match kind {
            dw_lle::END_OF_LIST => break,
            dw_lle::BASE_ADDRESSX => { let (idx, c) = read_uleb128(&data[pos..])?; pos += c; base = idx; }
            dw_lle::STARTX_ENDX => {
                let (s, c1) = read_uleb128(&data[pos..])?; pos += c1;
                let (e, c2) = read_uleb128(&data[pos..])?; pos += c2;
                let (el, c3) = read_uleb128(&data[pos..])?; pos += c3;
                let expr = read_bytes(data, &mut pos, el as usize)?;
                entries.push(LocationListEntry { begin: s, end: e, expression: expr });
            }
            dw_lle::STARTX_LENGTH => {
                let (s, c1) = read_uleb128(&data[pos..])?; pos += c1;
                let (len, c2) = read_uleb128(&data[pos..])?; pos += c2;
                let (el, c3) = read_uleb128(&data[pos..])?; pos += c3;
                let expr = read_bytes(data, &mut pos, el as usize)?;
                entries.push(LocationListEntry { begin: s, end: s + len, expression: expr });
            }
            dw_lle::OFFSET_PAIR => {
                let (so, c1) = read_uleb128(&data[pos..])?; pos += c1;
                let (eo, c2) = read_uleb128(&data[pos..])?; pos += c2;
                let (el, c3) = read_uleb128(&data[pos..])?; pos += c3;
                let expr = read_bytes(data, &mut pos, el as usize)?;
                entries.push(LocationListEntry { begin: base + so, end: base + eo, expression: expr });
            }
            dw_lle::DEFAULT_LOC => {
                let (el, c) = read_uleb128(&data[pos..])?; pos += c;
                let expr = read_bytes(data, &mut pos, el as usize)?;
                entries.push(LocationListEntry { begin: 0, end: u64::MAX, expression: expr });
            }
            dw_lle::BASE_ADDRESS => {
                base = if asz == 4 { u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64 } else { u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()) }; pos += asz;
            }
            dw_lle::START_END => {
                let b = if asz == 4 { u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64 } else { u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()) }; pos += asz;
                let e = if asz == 4 { u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64 } else { u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()) }; pos += asz;
                let (el, c) = read_uleb128(&data[pos..])?; pos += c;
                let expr = read_bytes(data, &mut pos, el as usize)?;
                entries.push(LocationListEntry { begin: b, end: e, expression: expr });
            }
            dw_lle::START_LENGTH => {
                let b = if asz == 4 { u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64 } else { u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()) }; pos += asz;
                let (len, c1) = read_uleb128(&data[pos..])?; pos += c1;
                let (el, c2) = read_uleb128(&data[pos..])?; pos += c2;
                let expr = read_bytes(data, &mut pos, el as usize)?;
                entries.push(LocationListEntry { begin: b, end: b + len, expression: expr });
            }
            _ => break,
        }
    }
    Ok(LocList { entries })
}

// ============================================================================
// .debug_frame / .eh_frame complete parser
// ============================================================================

pub fn parse_debug_frame_full(data: &[u8]) -> DwarfResult<Vec<(CieEntry, Vec<FdeEntry>)>> {
    let mut result = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= data.len() {
        let length32 = read_u32(data, &mut pos)?;
        if length32 == 0 { break; }
        let (length, is_64bit) = if length32 == 0xffffffff {
            (read_u64(data, &mut pos)?, true)
        } else { (length32 as u64, false) };
        let entry_end = pos + length as usize;
        let saved_offset = pos - (if is_64bit { 12 } else { 4 });
        let cie_id = if is_64bit { read_u64(data, &mut pos)? } else { read_u32(data, &mut pos)? as u64 };

        if (is_64bit && cie_id == 0xffffffffffffffff) || (!is_64bit && cie_id == 0xffffffff) {
            let version = read_u8(data, &mut pos)?;
            let aug_start = pos;
            while pos < data.len() && data[pos] != 0 { pos += 1; }
            let augmentation = std::str::from_utf8(&data[aug_start..pos]).unwrap_or("").to_string();
            pos += 1;
            let (code_align, c1) = read_uleb128(&data[pos..])?; pos += c1;
            let (data_align, c2) = read_sleb128(&data[pos..])?; pos += c2;
            let ret_addr_reg = if version >= 3 { let (r, c3) = read_uleb128(&data[pos..])?; pos += c3; r } else { read_u8(data, &mut pos)? as u64 };
            let (addr_sz, seg_sz) = if version >= 4 { (read_u8(data, &mut pos)?, read_u8(data, &mut pos)?) } else { (8u8, 0u8) };
            let aug_bytes = augmentation.as_bytes();
            if aug_bytes.first() == Some(&b'z') {
                let (aug_len, c4) = read_uleb128(&data[pos..])?; pos += c4;
                pos += aug_len as usize;
            }
            let init_instructions = data[pos..entry_end].to_vec();
            pos = entry_end;
            let cie = CieEntry { offset: saved_offset as u64, length, cie_id, version, augmentation, address_size: addr_sz, segment_size: seg_sz, code_alignment_factor: code_align, data_alignment_factor: data_align, return_address_register: ret_addr_reg, initial_instructions: init_instructions, pointer_encoding: None, lsda_encoding: None, personality: None, fde_encoding: None, is_64bit };


            let mut fdes = Vec::new();
            while pos + 4 <= data.len() {
                let fde_len32 = read_u32(data, &mut pos)?;
                if fde_len32 == 0 || fde_len32 == 0xffffffff { break; }
                let fde_len = if fde_len32 == 0xffffffff { read_u64(data, &mut pos)? } else { fde_len32 as u64 };
                let fde_end = pos + fde_len as usize;
                let fde_cie_id = if is_64bit { read_u64(data, &mut pos)? } else { read_u32(data, &mut pos)? as u64 };
                if (is_64bit && fde_cie_id == 0xffffffffffffffff) || (!is_64bit && fde_cie_id == 0xffffffff) {
                    pos -= if is_64bit { 20 } else { 12 }; break;
                }
                let init_loc = read_u64(data, &mut pos)?;
                let addr_range = read_u64(data, &mut pos)?;
                let fde_instructions = data[pos..fde_end].to_vec();
                pos = fde_end;
                fdes.push(FdeEntry { offset: (pos - fde_len as usize - if is_64bit { 12 } else { 4 }) as u64, length: fde_len, cie_offset: cie.offset, initial_location: init_loc, address_range: addr_range, instructions: fde_instructions, augmentation_data: None });
            }
            result.push((cie, fdes));
        } else {
            pos = entry_end;
        }
    }
    Ok(result)
}

// ============================================================================
// .debug_macro (DWARF 5)
// ============================================================================

pub fn parse_debug_macro(data: &[u8]) -> DwarfResult<Vec<MacroEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    let _version = read_u16(data, &mut pos)?;
    let _flags = read_u8(data, &mut pos)?;
    while pos < data.len() {
        let opcode = data[pos]; pos += 1;
        match opcode {
            0x00 => break,
            0x01 => {
                let (line, c) = read_uleb128(&data[pos..])?; pos += c;
                let mut end1 = pos; while end1 < data.len() && data[end1] != 0 { end1 += 1; }
                let name = std::str::from_utf8(&data[pos..end1]).unwrap_or("").to_string();
                pos = end1 + 1;
                let mut end2 = pos; while end2 < data.len() && data[end2] != 0 { end2 += 1; }
                let value = std::str::from_utf8(&data[pos..end2]).unwrap_or("").to_string();
                pos = end2 + 1;
                entries.push(MacroEntry::Define { line, name, value });
            }
            0x02 => {
                let (line, c) = read_uleb128(&data[pos..])?; pos += c;
                let mut end1 = pos; while end1 < data.len() && data[end1] != 0 { end1 += 1; }
                let name = std::str::from_utf8(&data[pos..end1]).unwrap_or("").to_string();
                pos = end1 + 1;
                entries.push(MacroEntry::Undef { line, name });
            }
            0x03 => {
                let (line, c) = read_uleb128(&data[pos..])?; pos += c;
                let (file, c2) = read_uleb128(&data[pos..])?; pos += c2;
                entries.push(MacroEntry::StartFile { line, file });
            }
            0x04 => { entries.push(MacroEntry::EndFile); }
            0x05 => {
                let (offset, c) = read_uleb128(&data[pos..])?; pos += c;
                entries.push(MacroEntry::Import { offset });
            }
            _ => break,
        }
    }
    Ok(entries)
}

// ============================================================================
// .debug_pubnames / .debug_pubtypes
// ============================================================================

pub fn parse_pubnames(data: &[u8]) -> DwarfResult<Vec<PubnamesEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos + 14 <= data.len() {
        let length = read_u32(data, &mut pos)? as usize;
        if length == 0 { break; }
        let _end = pos + length;
        let _version = read_u16(data, &mut pos)?;
        let cu_offset = read_u32(data, &mut pos)? as u64;
        let _cu_length = read_u32(data, &mut pos)?;
        while pos < data.len() {
            let die_offset = read_u32(data, &mut pos)?;
            if die_offset == 0 { break; }
            let s = read_null_str(data, &mut pos)?;
            entries.push(PubnamesEntry { cu_offset, die_offset: die_offset as u64, name: s });
        }
    }
    Ok(entries)
}

// ============================================================================
// DwarfInfo -- Top-level parsed DWARF container
// ============================================================================

#[derive(Debug, Clone)]
pub struct DwarfInfo {
    pub compilation_units: Vec<CompilationUnit>,
    pub debug_str: Vec<u8>,
    pub debug_line_str: Vec<u8>,
    pub debug_line: Option<Vec<LineEntry>>,
    pub debug_line_programs: Vec<(LineProgramHeader, Vec<LineEntry>)>,
    pub debug_ranges: Option<Vec<Vec<RangeEntry>>>,
    pub debug_rnglists: Option<Vec<Vec<RangeEntry>>>,
    pub debug_aranges: Option<Vec<ArangeTable>>,
    pub debug_loc: Option<Vec<LocList>>,
    pub debug_loclists: Option<Vec<LocList>>,
    pub debug_frame: Option<Vec<(CieEntry, Vec<FdeEntry>)>>,
    pub debug_macro: Option<Vec<MacroEntry>>,
    pub debug_addr: Option<Vec<u8>>,
    pub debug_str_offsets: Option<Vec<u8>>,
    pub debug_pubnames: Option<Vec<PubnamesEntry>>,
    pub debug_pubtypes: Option<Vec<PubnamesEntry>>,
}

impl DwarfInfo {
    pub fn new() -> Self {
        Self {
            compilation_units: Vec::new(),
            debug_str: Vec::new(),
            debug_line_str: Vec::new(),
            debug_line: None,
            debug_line_programs: Vec::new(),
            debug_ranges: None,
            debug_rnglists: None,
            debug_aranges: None,
            debug_loc: None,
            debug_loclists: None,
            debug_frame: None,
            debug_macro: None,
            debug_addr: None,
            debug_str_offsets: None,
            debug_pubnames: None,
            debug_pubtypes: None,
        }
    }

    pub fn find_cu_by_offset(&self, offset: u64) -> Option<&CompilationUnit> {
        self.compilation_units.iter().find(|cu| cu.offset == offset)
    }

    pub fn find_entry_in_cu<'a>(&self, cu: &'a CompilationUnit, offset: u64) -> Option<&'a DieEntry> {
        find_entry_in_entries(&cu.entries, offset)
    }

    pub fn read_debug_str(&self, offset: u64) -> DwarfResult<&str> {
        let off = offset as usize;
        if off >= self.debug_str.len() {
            return Err(DwarfError::InvalidStringOffset(offset));
        }
        let end = self.debug_str[off..].iter().position(|&b| b == 0).map(|p| off + p).unwrap_or(self.debug_str.len());
        std::str::from_utf8(&self.debug_str[off..end]).map_err(|e| DwarfError::ParseError(format!("UTF-8: {}", e)))
    }

    pub fn get_addr_from_index(&self, index: u64, address_size: u8) -> DwarfResult<u64> {
        let addr_data = self.debug_addr.as_ref().ok_or_else(|| DwarfError::SectionNotFound(".debug_addr".into()))?;
        let byte_offset = (index as usize) * (address_size as usize);
        if byte_offset + (address_size as usize) > addr_data.len() { return Err(DwarfError::ParseError("Address index out of bounds".into())); }
        match address_size {
            4 => Ok(u32::from_le_bytes(addr_data[byte_offset..byte_offset+4].try_into().unwrap()) as u64),
            8 => Ok(u64::from_le_bytes(addr_data[byte_offset..byte_offset+8].try_into().unwrap())),
            _ => Err(DwarfError::ParseError(format!("Unsupported address size: {}", address_size))),
        }
    }

    pub fn lookup_pubname(&self, name: &str) -> Option<&PubnamesEntry> {
        self.debug_pubnames.as_ref().and_then(|e| e.iter().find(|p| p.name == name))
    }

    pub fn find_line(&self, address: u64) -> Option<&LineEntry> {
        for (_, entries) in &self.debug_line_programs {
            let idx = entries.partition_point(|e| e.address <= address);
            if idx > 0 {
                let entry = &entries[idx - 1];
                if entry.address <= address && !entry.end_sequence { return Some(entry); }
            }
        }
        if let Some(ref entries) = self.debug_line {
            let idx = entries.partition_point(|e| e.address <= address);
            if idx > 0 {
                let entry = &entries[idx - 1];
                if entry.address <= address && !entry.end_sequence { return Some(entry); }
            }
        }
        None
    }

    pub fn source_location(&self, address: u64) -> Option<(String, u32, u32)> {
        for (header, entries) in &self.debug_line_programs {
            let idx = entries.partition_point(|e| e.address <= address);
            if idx > 0 {
                let entry = &entries[idx - 1];
                if entry.address <= address && !entry.end_sequence {
                    let file = header.file_names.get((entry.file_index as usize).saturating_sub(1));
                    let filename = file.map(|f| {
                        if f.directory_index == 0 { f.name.clone() }
                        else {
                            let dir = header.directories.get((f.directory_index as usize).saturating_sub(1)).cloned().unwrap_or_default();
                            format!("{}/{}", dir, f.name)
                        }
                    }).unwrap_or_else(|| "unknown".to_string());
                    return Some((filename, entry.line, entry.column));
                }
            }
        }
        None
    }
}

impl Default for DwarfInfo { fn default() -> Self { Self::new() } }

pub fn find_entry_in_entries(entries: &[DieEntry], offset: u64) -> Option<&DieEntry> {
    for entry in entries {
        for child in &entry.children {
            if let Some(found) = find_entry_in_entries_recurse(child, offset) { return Some(found); }
        }
    }
    None
}

fn find_entry_in_entries_recurse(entry: &DieEntry, offset: u64) -> Option<&DieEntry> {
    if entry.attr_value(dw_at::TYPE).and_then(|v| v.as_u64()) == Some(offset) { return Some(entry); }
    for child in &entry.children {
        if let Some(found) = find_entry_in_entries_recurse(child, offset) { return Some(found); }
    }
    None
}

// ============================================================================
// parse_dwarf -- Main entry point for parsing all DWARF sections
// ============================================================================

pub fn parse_dwarf(sections: &HashMap<String, &[u8]>) -> DwarfResult<DwarfInfo> {
    let mut dwarf = DwarfInfo::new();
    if let Some(data) = sections.get(".debug_str") { dwarf.debug_str = data.to_vec(); }
    if let Some(data) = sections.get(".debug_line_str") { dwarf.debug_line_str = data.to_vec(); }
    if let Some(data) = sections.get(".debug_addr") { dwarf.debug_addr = Some(data.to_vec()); }
    if let Some(data) = sections.get(".debug_str_offsets") { dwarf.debug_str_offsets = Some(data.to_vec()); }

    let abbrev_data = sections.get(".debug_abbrev").copied();
    if let Some(info_data) = sections.get(".debug_info") {
        if let Some(abbrev) = abbrev_data {
            let mut pos = 0usize;
            while pos < info_data.len() {
                if info_data[pos] == 0 { pos += 1; continue; }
                match parse_compilation_unit_at(info_data, pos as u64, abbrev) {
                    Ok(cu) => {
                        let cu_size = 4 + cu.length as usize;
                        pos += cu_size;
                        dwarf.compilation_units.push(cu);
                    }
                    Err(_) => break,
                }
            }
        }
    }

    if let Some(line_data) = sections.get(".debug_line") {
        if line_data.len() > 4 {
            let mut pos = 0usize;
            while pos < line_data.len() {
                let slice = &line_data[pos..];
                match parse_line_program_header(slice) {
                    Ok((header, prog_start)) => {
                        let entries = if prog_start < slice.len() { execute_line_program(&header, &slice[prog_start..]).unwrap_or_default() } else { Vec::new() };
                        dwarf.debug_line_programs.push((header, entries));
                        let prog_size = 4 + slice[..4].iter().fold(0u64, |acc, &b| acc | ((b as u64) << 8)) as usize;
                        pos += if prog_size == 0 { 4 } else { std::cmp::max(4, prog_size) };
                    }
                    Err(_) => break,
                }
            }
        }
    }

    if let Some(aranges_data) = sections.get(".debug_aranges") {
        dwarf.debug_aranges = parse_debug_aranges(aranges_data).ok();
    }
    if let Some(frame_data) = sections.get(".debug_frame") {
        dwarf.debug_frame = parse_debug_frame_full(frame_data).ok();
    }
    if let Some(macro_data) = sections.get(".debug_macro") {
        dwarf.debug_macro = parse_debug_macro(macro_data).ok();
    }
    if let Some(pubnames_data) = sections.get(".debug_pubnames") {
        dwarf.debug_pubnames = parse_pubnames(pubnames_data).ok();
    }
    if let Some(pubtypes_data) = sections.get(".debug_pubtypes") {
        dwarf.debug_pubtypes = parse_pubnames(pubtypes_data).ok();
    }
    Ok(dwarf)
}


// ============================================================================
// DWARF-to-Ghidra DataType Conversion
// ============================================================================

/// Convert a DWARF DIE to a Ghidra DataType.
/// Maps DW_TAG_* entries to the appropriate Ghidra type system types.
pub fn dwarf_type_to_ghidra(entry: &DieEntry, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    match entry.tag {
        dw_tag::BASE_TYPE => make_base_type(entry),
        dw_tag::TYPEDEF => make_typedef(entry, dwarf),
        dw_tag::POINTER_TYPE => make_pointer(entry, dwarf),
        dw_tag::REFERENCE_TYPE | dw_tag::RVALUE_REFERENCE_TYPE => make_reference(entry, dwarf),
        dw_tag::CONST_TYPE => make_const(entry, dwarf),
        dw_tag::VOLATILE_TYPE => make_volatile(entry, dwarf),
        dw_tag::RESTRICT_TYPE => make_restrict(entry, dwarf),
        dw_tag::ARRAY_TYPE => make_array(entry, dwarf),
        dw_tag::STRUCTURE_TYPE | dw_tag::CLASS_TYPE => make_structure(entry, dwarf),
        dw_tag::UNION_TYPE => make_union(entry, dwarf),
        dw_tag::ENUMERATION_TYPE => make_enum(entry, dwarf),
        dw_tag::SUBPROGRAM | dw_tag::SUBROUTINE_TYPE => make_function(entry, dwarf),
        dw_tag::STRING_TYPE => make_string_type(entry),
        _ => {
            let size = entry.byte_size().unwrap_or(1) as usize;
            Ok(Arc::new(BuiltInDataTypeWrapper::new(match size {
                1 => BuiltInDataType::Undefined1,
                2 => BuiltInDataType::Undefined2,
                4 => BuiltInDataType::Undefined4,
                8 => BuiltInDataType::Undefined8,
                _ => BuiltInDataType::Undefined1,
            })))
        }
    }
}

fn make_base_type(entry: &DieEntry) -> DwarfResult<DataTypeRef> {
    let name = entry.name().unwrap_or("unnamed").to_string();
    let byte_size = entry.byte_size().unwrap_or(4) as usize;
    let encoding = entry.attr_value(dw_at::ENCODING).and_then(|v| v.as_u64()).unwrap_or(0) as u8;
    match encoding {
        dw_ate::ADDRESS => {
            let ptr = Arc::new(PointerDataType::new(Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Void))));
            Ok(Arc::new(TypedefDataType::new(name, ptr)))
        }
        dw_ate::BOOLEAN => Ok(Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Bool))),
        dw_ate::FLOAT | dw_ate::DECIMAL_FLOAT => Ok(make_generic_float(byte_size)),
        dw_ate::SIGNED | dw_ate::SIGNED_CHAR => Ok(make_signed_int(byte_size)),
        dw_ate::UNSIGNED | dw_ate::UNSIGNED_CHAR => Ok(make_unsigned_int(byte_size)),
        dw_ate::COMPLEX_FLOAT | dw_ate::IMAGINARY_FLOAT => Ok(make_generic_float(byte_size * 2)),
        dw_ate::UTF | dw_ate::ASCII | dw_ate::UCS => {
            Ok(Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char)))
        }
        _ => Ok(make_unsigned_int(byte_size)),
    }
}

fn make_generic_float(size: usize) -> DataTypeRef {
    match size {
        4 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Float)),
        8 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Double)),
        _ => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::LongDouble)),
    }
}

fn make_signed_int(size: usize) -> DataTypeRef {
    match size {
        1 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char)),
        2 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Short)),
        4 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int)),
        8 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Long)),
        _ => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Undefined1)),
    }
}

fn make_unsigned_int(size: usize) -> DataTypeRef {
    match size {
        1 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Bool)),
        2 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::UShort)),
        4 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::UInt)),
        8 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::ULong)),
        _ => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Undefined1)),
    }
}

fn make_string_type(entry: &DieEntry) -> DwarfResult<DataTypeRef> {
    let size = entry.byte_size().unwrap_or(1) as usize;
    Ok(match size {
        1 => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::String)),
        _ => Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::UnicodeString)),
    })
}

fn make_typedef(entry: &DieEntry, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    let name = entry.name().unwrap_or("unnamed_typedef").to_string();
    let base_type = if let Some(type_ref) = entry.type_ref() {
        resolve_type_by_offset(dwarf, type_ref)?
    } else {
        Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Undefined1))
    };
    Ok(Arc::new(TypedefDataType::new(name, base_type)))
}

fn make_pointer(entry: &DieEntry, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    let size = entry.byte_size().unwrap_or(8) as usize;
    let pointed = if let Some(type_ref) = entry.type_ref() {
        resolve_type_by_offset(dwarf, type_ref)?
    } else {
        Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Void))
    };
    Ok(Arc::new(PointerDataType::with_size(pointed, size)))
}

fn make_reference(entry: &DieEntry, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    make_pointer(entry, dwarf)
}
fn make_const(entry: &DieEntry, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    if let Some(type_ref) = entry.type_ref() {
        resolve_type_by_offset(dwarf, type_ref)
    } else {
        Ok(Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Undefined1)))
    }
}
fn make_volatile(entry: &DieEntry, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    make_const(entry, dwarf)
}
fn make_restrict(entry: &DieEntry, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    make_const(entry, dwarf)
}

fn make_array(entry: &DieEntry, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    let element_type = if let Some(type_ref) = entry.type_ref() {
        resolve_type_by_offset(dwarf, type_ref)?
    } else {
        Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Undefined1))
    };
    let count = get_array_count(entry);
    Ok(Arc::new(ArrayDataType::new(element_type, if count > 0 { count } else { 0 })))
}

fn get_array_count(entry: &DieEntry) -> usize {
    if let Some(count) = entry.attr_value(dw_at::COUNT).and_then(|v| v.as_u64()) {
        return count as usize;
    }
    if let Some(upper) = entry.attr_value(dw_at::UPPER_BOUND).and_then(|v| v.as_u64()) {
        let lower = entry.attr_value(dw_at::LOWER_BOUND).and_then(|v| v.as_u64()).unwrap_or(0);
        return ((upper + 1).saturating_sub(lower)) as usize;
    }
    0
}

fn make_structure(entry: &DieEntry, _dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    let name = entry.name().unwrap_or("unnamed_struct").to_string();
    let size = entry.byte_size().unwrap_or(0) as usize;
    let mut s = StructureDataType::new(name);
    if size > 0 { s.size = size; s.is_defined = true; }
    if entry.attr_value(dw_at::DECLARATION).and_then(|v| v.as_bool()).unwrap_or(false) {
        s.is_defined = false;
    }
    Ok(Arc::new(s))
}

fn make_union(entry: &DieEntry, _dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    let name = entry.name().unwrap_or("unnamed_union").to_string();
    let size = entry.byte_size().unwrap_or(0) as usize;
    let mut u = UnionDataType::new(name);
    if size > 0 { u.size = size; u.is_defined = true; }
    if entry.attr_value(dw_at::DECLARATION).and_then(|v| v.as_bool()).unwrap_or(false) {
        u.is_defined = false;
    }
    Ok(Arc::new(u))
}

fn make_enum(entry: &DieEntry, _dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    let name = entry.name().unwrap_or("unnamed_enum").to_string();
    let size = entry.byte_size().unwrap_or(4) as usize;
    let sz = match size { 1 | 2 | 4 | 8 => size, _ => 4 };
    Ok(Arc::new(EnumDataType::new(name, sz)))
}

fn make_function(entry: &DieEntry, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    let name = entry.name().unwrap_or("unnamed_function").to_string();
    let return_type = if let Some(type_ref) = entry.type_ref() {
        resolve_type_by_offset(dwarf, type_ref)?
    } else {
        Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Void))
    };
    Ok(Arc::new(FunctionDefinitionDataType::new(name, return_type)))
}

// ============================================================================
// Type Resolution
// ============================================================================

pub fn resolve_type_by_offset(dwarf: &DwarfInfo, offset: u64) -> DwarfResult<DataTypeRef> {
    for cu in &dwarf.compilation_units {
        for entry in &cu.entries {
            if let Some(found) = find_die_at_offset(entry, offset) {
                return dwarf_type_to_ghidra(found, dwarf);
            }
        }
    }
    Err(DwarfError::TypeResolutionError(format!("DIE at offset 0x{:x} not found", offset)))
}

fn find_die_at_offset(entry: &DieEntry, target: u64) -> Option<&DieEntry> {
    if entry.attr_value(dw_at::TYPE).and_then(|v| v.as_u64()) == Some(target) {
        return Some(entry);
    }
    for child in &entry.children {
        if let Some(found) = find_die_at_offset(child, target) {
            return Some(found);
        }
    }
    None
}

pub fn build_type_map(dwarf: &DwarfInfo) -> HashMap<String, DataTypeRef> {
    let mut type_map = HashMap::new();
    for cu in &dwarf.compilation_units {
        for entry in &cu.entries {
            collect_named_types(entry, dwarf, &mut type_map);
        }
    }
    type_map
}

fn collect_named_types(
    entry: &DieEntry, dwarf: &DwarfInfo, type_map: &mut HashMap<String, DataTypeRef>,
) {
    if let Some(name) = entry.name() {
        match entry.tag {
            dw_tag::BASE_TYPE | dw_tag::STRUCTURE_TYPE | dw_tag::CLASS_TYPE
            | dw_tag::UNION_TYPE | dw_tag::ENUMERATION_TYPE | dw_tag::TYPEDEF
            | dw_tag::POINTER_TYPE | dw_tag::ARRAY_TYPE | dw_tag::CONST_TYPE
            | dw_tag::VOLATILE_TYPE | dw_tag::SUBROUTINE_TYPE | dw_tag::STRING_TYPE => {
                if let Ok(dt) = dwarf_type_to_ghidra(entry, dwarf) {
                    type_map.entry(name.to_string()).or_insert(dt);
                }
            }
            _ => {}
        }
    }
    for child in &entry.children {
        collect_named_types(child, dwarf, type_map);
    }
}

pub fn build_full_type(name: &str, dwarf: &DwarfInfo) -> DwarfResult<DataTypeRef> {
    let type_map = build_type_map(dwarf);
    type_map.get(name).cloned().ok_or_else(|| DwarfError::TypeResolutionError(format!("Type '{}' not found", name)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn test_uleb128_one() { let (v, l) = read_uleb128(&[0x2a]).unwrap(); assert_eq!(v, 42); assert_eq!(l, 1); }
    #[test] fn test_uleb128_two() { let (v, l) = read_uleb128(&[0x80, 0x01]).unwrap(); assert_eq!(v, 128); assert_eq!(l, 2); }
    #[test] fn test_uleb128_max() {
        let data = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        let (v, l) = read_uleb128(&data).unwrap(); assert_eq!(v, u64::MAX); assert_eq!(l, 10);
    }
    #[test] fn test_uleb128_zero() { let (v, _) = read_uleb128(&[0x00]).unwrap(); assert_eq!(v, 0); }
    #[test] fn test_sleb128_zero() { let (v, _) = read_sleb128(&[0x00]).unwrap(); assert_eq!(v, 0); }
    #[test] fn test_sleb128_neg_one() { let (v, _) = read_sleb128(&[0x7f]).unwrap(); assert_eq!(v, -1); }
    #[test] fn test_sleb128_neg_128() { let (v, _) = read_sleb128(&[0x80, 0x7f]).unwrap(); assert_eq!(v, -128); }
    #[test] fn test_sleb128_positive() { let (v, _) = read_sleb128(&[0x2a]).unwrap(); assert_eq!(v, 42); }
    #[test] fn test_uleb128_eof() { assert!(read_uleb128(&[0x80]).is_err()); }

    #[test] fn test_tag_name() {
        assert_eq!(tag_name(dw_tag::COMPILATION_UNIT), "DW_TAG_compilation_unit");
        assert_eq!(tag_name(dw_tag::SUBPROGRAM), "DW_TAG_subprogram");
        assert_eq!(tag_name(dw_tag::VARIABLE), "DW_TAG_variable");
        assert_eq!(tag_name(dw_tag::BASE_TYPE), "DW_TAG_base_type");
        assert_eq!(tag_name(dw_tag::POINTER_TYPE), "DW_TAG_pointer_type");
        assert_eq!(tag_name(dw_tag::STRUCTURE_TYPE), "DW_TAG_structure_type");
        assert_eq!(tag_name(dw_tag::TYPEDEF), "DW_TAG_typedef");
        assert_eq!(tag_name(dw_tag::RVALUE_REFERENCE_TYPE), "DW_TAG_rvalue_reference_type");
        assert_eq!(tag_name(0x9999), "DW_TAG_<unknown>");
    }

    #[test] fn test_attr_name() {
        assert_eq!(attr_name(dw_at::NAME), "DW_AT_name");
        assert_eq!(attr_name(dw_at::TYPE), "DW_AT_type");
        assert_eq!(attr_name(dw_at::LOW_PC), "DW_AT_low_pc");
        assert_eq!(attr_name(dw_at::HIGH_PC), "DW_AT_high_pc");
        assert_eq!(attr_name(dw_at::BYTE_SIZE), "DW_AT_byte_size");
        assert_eq!(attr_name(dw_at::LINKAGE_NAME), "DW_AT_linkage_name");
        assert_eq!(attr_name(dw_at::COMP_DIR), "DW_AT_comp_dir");
    }

    #[test] fn test_form_name() {
        assert_eq!(form_name(dw_form::ADDR), "DW_FORM_addr");
        assert_eq!(form_name(dw_form::STRING), "DW_FORM_string");
        assert_eq!(form_name(dw_form::UDATA), "DW_FORM_udata");
        assert_eq!(form_name(dw_form::FLAG_PRESENT), "DW_FORM_flag_present");
        assert_eq!(form_name(dw_form::EXPRLOC), "DW_FORM_exprloc");
        assert_eq!(form_name(dw_form::IMPLICIT_CONST), "DW_FORM_implicit_const");
    }

    #[test] fn test_op_name() {
        assert_eq!(op_name(dw_op::ADDR), "DW_OP_addr");
        assert_eq!(op_name(dw_op::PLUS), "DW_OP_plus");
        assert_eq!(op_name(dw_op::NOP), "DW_OP_nop");
        assert_eq!(op_name(dw_op::CALL_FRAME_CFA), "DW_OP_call_frame_cfa");
        assert_eq!(op_name(dw_op::DUP), "DW_OP_dup");
        assert_eq!(op_name(dw_op::STACK_VALUE), "DW_OP_stack_value");
    }

    #[test] fn test_dw_op_lit() {
        assert!(dw_op::is_lit(0x30)); assert!(dw_op::is_lit(0x4f)); assert!(!dw_op::is_lit(0x50));
        assert_eq!(dw_op::lit_value(0x35), 5);
    }

    #[test] fn test_dw_op_reg() {
        assert!(dw_op::is_reg(0x50)); assert!(!dw_op::is_reg(0x30));
        assert_eq!(dw_op::reg_value(0x56), 6);
    }

    #[test] fn test_dw_op_breg() {
        assert!(dw_op::is_breg(0x70)); assert!(!dw_op::is_breg(0x50));
        assert_eq!(dw_op::breg_value(0x7a), 10);
    }

    #[test] fn test_parse_abbrev_table() {
        let mut data = Vec::new();
        data.push(0x01); data.push(0x11); data.push(0x00);
        data.push(0x03); data.push(0x08);
        data.push(0x00); data.push(0x00);
        data.push(0x00);
        let table = parse_abbrev_table(&data, 0).unwrap();
        assert_eq!(table.len(), 1);
        let e = table.get(&1).unwrap();
        assert_eq!(e.tag, dw_tag::COMPILATION_UNIT);
        assert!(!e.has_children);
        assert_eq!(e.attributes.len(), 1);
        assert_eq!(e.attributes[0].attr, dw_at::NAME);
        assert_eq!(e.attributes[0].form, dw_form::STRING);
    }

    #[test] fn test_read_attribute_value_string() {
        let data = b"hello\0"; let mut p = 0;
        let v = read_attribute_value(data, &mut p, dw_form::STRING, None).unwrap();
        assert_eq!(v, AttributeValue::String("hello".to_string()));
    }

    #[test] fn test_read_attribute_value_flag_present() {
        let mut p = 0;
        let v = read_attribute_value(&[], &mut p, dw_form::FLAG_PRESENT, None).unwrap();
        assert_eq!(v, AttributeValue::Flag(true));
    }

    #[test] fn test_read_attribute_value_sdata() {
        let data = [0x7fu8]; let mut p = 0;
        let v = read_attribute_value(&data, &mut p, dw_form::SDATA, None).unwrap();
        assert_eq!(v, AttributeValue::SData(-1));
    }

    #[test] fn test_read_attribute_value_flag() {
        let data = [1u8]; let mut p = 0;
        let v = read_attribute_value(&data, &mut p, dw_form::FLAG, None).unwrap();
        assert_eq!(v, AttributeValue::Flag(true));
    }

    #[test] fn test_read_attribute_value_sec_offset() {
        let data = [0x78, 0x56, 0x34, 0x12]; let mut p = 0;
        let v = read_attribute_value(&data, &mut p, dw_form::SEC_OFFSET, None).unwrap();
        assert_eq!(v, AttributeValue::SecOffset(0x12345678));
    }

    #[test] fn test_attribute_value_as_u64() {
        assert_eq!(AttributeValue::Addr(0x1000).as_u64(), Some(0x1000));
        assert_eq!(AttributeValue::Flag(true).as_u64(), Some(1));
        assert_eq!(AttributeValue::Flag(false).as_u64(), Some(0));
    }

    #[test] fn test_attribute_value_as_string() {
        assert_eq!(AttributeValue::String("hello".into()).as_string(), Some("hello"));
        assert_eq!(AttributeValue::Addr(0x1000).as_string(), None);
    }

    #[test] fn test_die_entry_find_all() {
        let root = DieEntry {
            tag: dw_tag::COMPILATION_UNIT, attributes: vec![],
            children: vec![DieEntry {
                tag: dw_tag::SUBPROGRAM, attributes: vec![],
                children: vec![DieEntry { tag: dw_tag::VARIABLE, attributes: vec![], children: vec![] }],
            }],
        };
        assert_eq!(root.find_all(dw_tag::VARIABLE).len(), 1);
        assert_eq!(root.find_all(dw_tag::SUBPROGRAM).len(), 1);
    }

    #[test] fn test_die_entry_name() {
        let die = DieEntry { tag: dw_tag::VARIABLE,
            attributes: vec![Attribute::new(dw_at::NAME, dw_form::STRING, AttributeValue::String("my_var".into()))],
            children: vec![] };
        assert_eq!(die.name(), Some("my_var"));
    }

    #[test] fn test_die_entry_type_ref() {
        let die = DieEntry { tag: dw_tag::POINTER_TYPE,
            attributes: vec![Attribute::new(dw_at::TYPE, dw_form::REF4, AttributeValue::Ref(0x1234))],
            children: vec![] };
        assert_eq!(die.type_ref(), Some(0x1234));
    }

    #[test] fn test_line_program_simple() {
        let header = LineProgramHeader {
            unit_length: 0, version: 4, header_length: 0,
            min_insn_length: 1, max_ops_per_insn: 1, default_is_stmt: true,
            line_base: -5, line_range: 14, opcode_base: 13,
            std_opcode_lengths: vec![0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1],
            directories: vec![],
            file_names: vec![FileEntry { name: "test.c".into(), directory_index: 0, last_modified: 0, length: 0 }],
        };
        let mut prog = Vec::new();
        prog.push(0x00); prog.push(0x09); prog.push(0x02);
        prog.extend_from_slice(&0x1000u64.to_le_bytes());
        prog.push(dw_lns::COPY);
        let matrix = execute_line_program(&header, &prog).unwrap();
        assert!(!matrix.is_empty());
        assert_eq!(matrix[0].address, 0x1000);
        assert!(!matrix[0].end_sequence);
    }

    #[test] fn test_expr_lit_add() {
        let ops = [dw_op::LIT3, dw_op::LIT4, dw_op::PLUS];
        let result = evaluate_dwarf_expression(&ops, 0, &HashMap::new()).unwrap();
        assert!(!result.is_empty()); assert_eq!(result[0].0, 7);
    }

    #[test] fn test_expr_dup_add() {
        let ops = [dw_op::LIT5, dw_op::DUP, dw_op::PLUS];
        let result = evaluate_dwarf_expression(&ops, 0, &HashMap::new()).unwrap();
        assert_eq!(result[0].0, 10);
    }

    #[test] fn test_expr_minus() {
        let ops = [dw_op::LIT10, dw_op::LIT3, dw_op::MINUS];
        let result = evaluate_dwarf_expression(&ops, 0, &HashMap::new()).unwrap();
        assert_eq!(result[0].0, 7);
    }

    #[test] fn test_expr_nop() {
        let result = evaluate_dwarf_expression(&[dw_op::NOP], 0, &HashMap::new()).unwrap();
        assert!(result.is_empty());
    }

    #[test] fn test_expr_fbreg() {
        let data = [dw_op::FBREG, 0x10];
        let result = evaluate_dwarf_expression(&data, 0x1000, &HashMap::new()).unwrap();
        assert_eq!(result[0].0, 0x1010);
    }

    #[test] fn test_parse_cie_minimal() {
        let mut data = Vec::new();
        let body = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x04, b'z', b'R', 0x00, 0x08, 0x00, 0x01, 0x0c, 0x10, 0x00];
        data.extend_from_slice(&(body.len() as u32).to_le_bytes());
        data.extend_from_slice(&body);
        let cie = parse_cie(&data).unwrap();
        assert_eq!(cie.version, 4);
        assert_eq!(cie.augmentation, "zR");
        assert_eq!(cie.code_alignment_factor, 1);
    }

    #[test] fn test_parse_debug_ranges() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x2000u64.to_le_bytes());
        data.extend_from_slice(&0x0000u64.to_le_bytes());
        data.extend_from_slice(&0x0000u64.to_le_bytes());
        let ranges = parse_debug_ranges(&data, 0, 8).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].begin, 0x1000);
        assert_eq!(ranges[0].end, 0x2000);
    }

    #[test] fn test_parse_debug_aranges() {
        let mut data = Vec::new();
        let body_len = 2 + 4 + 1 + 1 + 8 + 8 + 8 + 8;
        data.extend_from_slice(&(body_len as u32).to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(8); data.push(0);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x500u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        let tables = parse_debug_aranges(&data).unwrap();
        assert!(!tables.is_empty());
    }

    #[test] fn test_parse_dwarf_empty() {
        let sections: HashMap<String, &[u8]> = HashMap::new();
        let info = parse_dwarf(&sections).unwrap();
        assert!(info.compilation_units.is_empty());
    }

    #[test] fn test_compile_error_display() {
        assert_eq!(format!("{}", DwarfError::UnexpectedEof), "Unexpected end of DWARF data");
        assert_eq!(format!("{}", DwarfError::UnsupportedVersion(7)), "Unsupported DWARF version: 7");
    }
}
