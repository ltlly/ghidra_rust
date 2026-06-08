//! DEX (Dalvik Executable) format parser — full spec implementation.
//!
//! Parses Android `.dex` bytecode files into a structured representation
//! suitable for analysis, decompilation, and smali-like disassembly.
//!
//! # References
//!
//! - Dalvik Executable Format: <https://source.android.com/docs/core/runtime/dex-format>
//! - AOSP: `dalvik/libdex/DexFile.h`
//! - smali/baksmali assembler/disassembler

// =============================================================================
// Modules
// =============================================================================

// =============================================================================
// Imports
// =============================================================================

use nom::bytes::complete::take;
use nom::number::complete::{le_u32, le_u8};
use nom::sequence::tuple;
use nom::IResult;
use std::fmt;

// =============================================================================
// Constants
// =============================================================================

/// DEX magic prefix: "dex\n"
pub const DEX_MAGIC: [u8; 4] = [0x64, 0x65, 0x78, 0x0a];

/// Size of the DEX magic field (8 bytes).
pub const DEX_MAGIC_SIZE: usize = 8;

/// Size of the DEX signature field (SHA-1, 20 bytes).
pub const DEX_SIGNATURE_SIZE: usize = 20;

/// Expected DEX header size (0x70 = 112 bytes).
pub const DEX_HEADER_SIZE: usize = 0x70;

/// Maximum allowed entries in any table to prevent DoS.
const MAX_TABLE_ENTRIES: u32 = 65536;

/// Little-endian endian tag used by all standard DEX files.
pub const ENDIAN_CONSTANT: u32 = 0x12345678;

/// Reversed endian tag (big-endian, rare).
pub const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

/// No-index sentinel value.
pub const NO_INDEX: u32 = 0xFFFFFFFF;

// =============================================================================
// Map item types
// =============================================================================

/// Map item type codes identifying different sections within a DEX file.
pub enum MapItemType {
    HeaderItem = 0x0000,
    StringIdItem = 0x0001,
    TypeIdItem = 0x0002,
    ProtoIdItem = 0x0003,
    FieldIdItem = 0x0004,
    MethodIdItem = 0x0005,
    ClassDefItem = 0x0006,
    CallSiteIdItem = 0x0007,
    MethodHandleItem = 0x0008,
    MapList = 0x1000,
    TypeList = 0x1001,
    AnnotationSetRefList = 0x1002,
    AnnotationSetItem = 0x1003,
    ClassDataItem = 0x2000,
    CodeItem = 0x2001,
    StringDataItem = 0x2002,
    DebugInfoItem = 0x2003,
    AnnotationItem = 0x2004,
    EncodedArrayItem = 0x2005,
    AnnotationsDirectoryItem = 0x2006,
    HiddenapiClassDataItem = 0xF000,
}

// =============================================================================
// Access flags
// =============================================================================

pub const ACC_PUBLIC: u32 = 0x0001;
pub const ACC_PRIVATE: u32 = 0x0002;
pub const ACC_PROTECTED: u32 = 0x0004;
pub const ACC_STATIC: u32 = 0x0008;
pub const ACC_FINAL: u32 = 0x0010;
pub const ACC_SYNCHRONIZED: u32 = 0x0020;
pub const ACC_VOLATILE: u32 = 0x0040;
pub const ACC_BRIDGE: u32 = 0x0040;
pub const ACC_TRANSIENT: u32 = 0x0080;
pub const ACC_VARARGS: u32 = 0x0080;
pub const ACC_NATIVE: u32 = 0x0100;
pub const ACC_INTERFACE: u32 = 0x0200;
pub const ACC_ABSTRACT: u32 = 0x0400;
pub const ACC_STRICT: u32 = 0x0800;
pub const ACC_SYNTHETIC: u32 = 0x1000;
pub const ACC_ANNOTATION: u32 = 0x2000;
pub const ACC_ENUM: u32 = 0x4000;
pub const ACC_CONSTRUCTOR: u32 = 0x00010000;
pub const ACC_DECLARED_SYNCHRONIZED: u32 = 0x00020000;

/// Return a human-readable list of access flag names.
pub fn access_flag_names(flags: u32) -> Vec<&'static str> {
    let mut names = Vec::new();
    if flags & ACC_PUBLIC != 0 {
        names.push("public");
    }
    if flags & ACC_PRIVATE != 0 {
        names.push("private");
    }
    if flags & ACC_PROTECTED != 0 {
        names.push("protected");
    }
    if flags & ACC_STATIC != 0 {
        names.push("static");
    }
    if flags & ACC_FINAL != 0 {
        names.push("final");
    }
    if flags & ACC_SYNCHRONIZED != 0 {
        names.push("synchronized");
    }
    if flags & ACC_VOLATILE != 0 {
        names.push("volatile");
    }
    if flags & ACC_BRIDGE != 0 {
        names.push("bridge");
    }
    if flags & ACC_TRANSIENT != 0 {
        names.push("transient");
    }
    if flags & ACC_VARARGS != 0 {
        names.push("varargs");
    }
    if flags & ACC_NATIVE != 0 {
        names.push("native");
    }
    if flags & ACC_INTERFACE != 0 {
        names.push("interface");
    }
    if flags & ACC_ABSTRACT != 0 {
        names.push("abstract");
    }
    if flags & ACC_STRICT != 0 {
        names.push("strict");
    }
    if flags & ACC_SYNTHETIC != 0 {
        names.push("synthetic");
    }
    if flags & ACC_ANNOTATION != 0 {
        names.push("annotation");
    }
    if flags & ACC_ENUM != 0 {
        names.push("enum");
    }
    if flags & ACC_CONSTRUCTOR != 0 {
        names.push("constructor");
    }
    if flags & ACC_DECLARED_SYNCHRONIZED != 0 {
        names.push("declared_synchronized");
    }
    names
}

// =============================================================================
// Error types
// =============================================================================

/// Errors that can occur during DEX parsing.
#[derive(Debug, Clone)]
pub enum DexError {
    /// Input data too small.
    TruncatedInput { expected: usize, actual: usize },
    /// Invalid magic bytes.
    InvalidMagic(Vec<u8>),
    /// Unsupported DEX version string.
    UnsupportedVersion(String),
    /// Table entries exceed safety limit.
    TableTooLarge { table: &'static str, count: u32, max: u32 },
    /// Offset out of range.
    OffsetOutOfRange { offset: u32, file_size: usize },
    /// Invalid string index.
    InvalidStringIndex(u32),
    /// Invalid type index.
    InvalidTypeIndex(u32),
    /// Invalid field index.
    InvalidFieldIndex(u32),
    /// Invalid method index.
    InvalidMethodIndex(u32),
    /// Invalid proto index.
    InvalidProtoIndex(u32),
    /// Nom parser error.
    NomError(String),
    /// I/O error wrapper.
    IoError(String),
}

impl fmt::Display for DexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DexError::TruncatedInput { expected, actual } => {
                write!(f, "DEX truncated: expected {} bytes, got {}", expected, actual)
            }
            DexError::InvalidMagic(bytes) => {
                write!(f, "DEX invalid magic: {:02X?}", bytes)
            }
            DexError::UnsupportedVersion(v) => {
                write!(f, "DEX unsupported version: {}", v)
            }
            DexError::TableTooLarge { table, count, max } => {
                write!(f, "DEX table '{}' too large: {} entries (max {})", table, count, max)
            }
            DexError::OffsetOutOfRange { offset, file_size } => {
                write!(f, "DEX offset 0x{:08X} out of range (file size 0x{:X})", offset, file_size)
            }
            DexError::InvalidStringIndex(idx) => {
                write!(f, "DEX invalid string index: {}", idx)
            }
            DexError::InvalidTypeIndex(idx) => {
                write!(f, "DEX invalid type index: {}", idx)
            }
            DexError::InvalidFieldIndex(idx) => {
                write!(f, "DEX invalid field index: {}", idx)
            }
            DexError::InvalidMethodIndex(idx) => {
                write!(f, "DEX invalid method index: {}", idx)
            }
            DexError::InvalidProtoIndex(idx) => {
                write!(f, "DEX invalid proto index: {}", idx)
            }
            DexError::NomError(s) => write!(f, "DEX parse error: {}", s),
            DexError::IoError(s) => write!(f, "DEX I/O error: {}", s),
        }
    }
}

impl std::error::Error for DexError {}

impl From<nom::Err<nom::error::Error<&[u8]>>> for DexError {
    fn from(err: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        DexError::NomError(format!("{:?}", err))
    }
}

impl From<std::io::Error> for DexError {
    fn from(err: std::io::Error) -> Self {
        DexError::IoError(err.to_string())
    }
}

// =============================================================================
// Value types for encoded values
// =============================================================================

/// Encoded value types used in annotations and static field initialisers.
#[derive(Debug, Clone, PartialEq)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array(Vec<EncodedValue>),
    Annotation(DexAnnotation),
    Null,
    Boolean(bool),
}

/// Annotation element (name-value pair).
#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationElement {
    pub name: String,
    pub value: EncodedValue,
}

/// Visibility of an annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationVisibility {
    Build,
    Runtime,
    System,
}

/// A single annotation.
#[derive(Debug, Clone, PartialEq)]
pub struct DexAnnotation {
    pub visibility: AnnotationVisibility,
    pub type_idx: u32,
    pub elements: Vec<AnnotationElement>,
}

// =============================================================================
// Core data types for DEX file structure
// =============================================================================

/// DEX file header.
///
/// 112 bytes in size, containing metadata about all sections
/// of the DEX file.
#[derive(Debug, Clone)]
pub struct DexHeader {
    /// DEX magic bytes (8 bytes: "dex\n035\0" or similar).
    pub magic: [u8; 8],
    /// Adler32 checksum of the remainder of the file.
    pub checksum: u32,
    /// SHA-1 signature of the remainder of the file.
    pub signature: [u8; 20],
    /// Total file size in bytes.
    pub file_size: u32,
    /// Size of this header (always 0x70).
    pub header_size: u32,
    /// Endianness tag (ENDIAN_CONSTANT).
    pub endian_tag: u32,
    /// Size of the link section, or 0 if absent.
    pub link_size: u32,
    /// Offset to the link section.
    pub link_off: u32,
    /// Offset to the map list.
    pub map_off: u32,
    /// Number of string_ids.
    pub string_ids_size: u32,
    /// Offset of the string_ids table.
    pub string_ids_off: u32,
    /// Number of type_ids.
    pub type_ids_size: u32,
    /// Offset of the type_ids table.
    pub type_ids_off: u32,
    /// Number of proto_ids.
    pub proto_ids_size: u32,
    /// Offset of the proto_ids table.
    pub proto_ids_off: u32,
    /// Number of field_ids.
    pub field_ids_size: u32,
    /// Offset of the field_ids table.
    pub field_ids_off: u32,
    /// Number of method_ids.
    pub method_ids_size: u32,
    /// Offset of the method_ids table.
    pub method_ids_off: u32,
    /// Number of class_defs.
    pub class_defs_size: u32,
    /// Offset of the class_defs table.
    pub class_defs_off: u32,
    /// Size of the data section.
    pub data_size: u32,
    /// Offset of the data section.
    pub data_off: u32,
}

/// A DEX type reference.
#[derive(Debug, Clone)]
pub struct DexType {
    /// Index into the string_ids table for the descriptor string.
    pub descriptor_idx: u32,
    /// The resolved descriptor string (e.g. "Ljava/lang/String;").
    pub descriptor: String,
}

/// A DEX prototype (method signature).
#[derive(Debug, Clone)]
pub struct DexProto {
    /// Index into string_ids for the shorty descriptor.
    pub shorty_idx: u32,
    /// The resolved shorty string (e.g. "VL" for (Ljava/lang/Object;)J).
    pub shorty: String,
    /// Index into type_ids for the return type.
    pub return_type_idx: u32,
    /// The resolved return type descriptor.
    pub return_type: String,
    /// Offset to a type_list for the parameter types, or 0 if none.
    pub parameters_off: u32,
    /// Resolved parameter type descriptors.
    pub parameters: Vec<String>,
}

/// A DEX field reference.
#[derive(Debug, Clone)]
pub struct DexField {
    /// Index into type_ids for the defining class.
    pub class_idx: u32,
    /// The resolved defining class descriptor.
    pub class: String,
    /// Index into type_ids for the field type.
    pub type_idx: u32,
    /// The resolved field type descriptor.
    pub field_type: String,
    /// Index into string_ids for the field name.
    pub name_idx: u32,
    /// The resolved field name.
    pub name: String,
}

/// A DEX method reference.
#[derive(Debug, Clone)]
pub struct DexMethod {
    /// Index into type_ids for the defining class.
    pub class_idx: u32,
    /// The resolved defining class descriptor.
    pub class: String,
    /// Index into type_ids for the proto (signature).
    pub proto_idx: u32,
    /// The resolved return type.
    pub return_type: String,
    /// The resolved parameter types.
    pub parameters: Vec<String>,
    /// Index into string_ids for the method name.
    pub name_idx: u32,
    /// The resolved method name.
    pub name: String,
    /// Method access flags.
    pub access_flags: u32,
    /// Bytecode, if this method is defined (not abstract/native).
    pub code: Option<DexCode>,
    /// Number of registers used by the code.
    pub registers: u16,
    /// Number of input registers (parameters).
    pub ins_size: u16,
}

/// Encoded field within a class_data_item.
#[derive(Debug, Clone)]
pub struct EncodedField {
    /// Delta-encoded index into field_ids.
    pub field_idx_diff: u32,
    /// The resolved field reference.
    pub field: Option<DexField>,
    /// Access flags for this field.
    pub access_flags: u32,
}

/// Encoded method within a class_data_item.
#[derive(Debug, Clone)]
pub struct EncodedMethod {
    /// Delta-encoded index into method_ids.
    pub method_idx_diff: u32,
    /// The resolved method reference.
    pub method: Option<DexMethod>,
    /// Access flags for this method.
    pub access_flags: u32,
    /// Offset to the code_item, or 0.
    pub code_off: u32,
}

/// A DEX class definition.
#[derive(Debug, Clone)]
pub struct DexClass {
    /// Index into type_ids for this class.
    pub class_idx: u32,
    /// The resolved class descriptor.
    pub name: String,
    /// Access flags.
    pub access_flags: u32,
    /// Superclass index into type_ids, or NO_INDEX.
    pub superclass_idx: u32,
    /// The resolved superclass descriptor, if any.
    pub superclass: Option<String>,
    /// Offset to the interfaces type_list, or 0.
    pub interfaces_off: u32,
    /// Resolved interface descriptors.
    pub interfaces: Vec<String>,
    /// Source file string index, or NO_INDEX.
    pub source_file_idx: u32,
    /// Resolved source file name, if any.
    pub source_file: Option<String>,
    /// Annotations directory offset, or 0.
    pub annotations_off: u32,
    /// Class data offset, or 0.
    pub class_data_off: u32,
    /// Static values initializer offset, or 0.
    pub static_values_off: u32,
    /// Direct methods (static, private, constructors).
    pub direct_methods: Vec<DexMethod>,
    /// Virtual methods (overridable).
    pub virtual_methods: Vec<DexMethod>,
    /// Instance fields.
    pub instance_fields: Vec<DexField>,
    /// Static fields.
    pub static_fields: Vec<DexField>,
}

/// Bytecode information for a method.
#[derive(Debug, Clone)]
pub struct DexCode {
    /// Number of registers used.
    pub registers_size: u16,
    /// Number of words of incoming arguments.
    pub ins_size: u16,
    /// Number of words of outgoing argument space.
    pub outs_size: u16,
    /// Number of try_item entries.
    pub tries_size: u16,
    /// Offset to debug_info, or 0 if absent.
    pub debug_info_off: u32,
    /// The actual bytecode instructions.
    pub insns: Vec<u8>,
    /// Try/catch blocks.
    pub tries: Vec<TryItem>,
    /// Catch handler lists.
    pub handlers: Vec<EncodedCatchHandler>,
}

/// A try/catch block entry.
#[derive(Debug, Clone)]
pub struct TryItem {
    /// Start address of the try block (code units).
    pub start_addr: u32,
    /// Number of code units covered.
    pub insn_count: u16,
    /// Offset to the encoded_catch_handler_list.
    pub handler_off: u16,
}

/// An encoded exception handler.
#[derive(Debug, Clone)]
pub struct EncodedCatchHandler {
    /// Number of catch-type pairs. -1 for catch-all.
    pub size: i32,
    /// Handlers for specific types.
    pub handlers: Vec<EncodedTypeAddrPair>,
    /// Catch-all handler address, if present.
    pub catch_all_addr: Option<u32>,
}

/// A (type, address) pair for exception handlers.
#[derive(Debug, Clone)]
pub struct EncodedTypeAddrPair {
    /// Index into type_ids for the exception type.
    pub type_idx: u32,
    /// Handler entry point address (code units).
    pub addr: u32,
}

/// A complete parsed DEX file.
#[derive(Debug, Clone)]
pub struct DexFile {
    /// The file header.
    pub header: DexHeader,
    /// All strings in the DEX file.
    pub strings: Vec<String>,
    /// All types.
    pub types: Vec<DexType>,
    /// All prototypes (method signatures).
    pub protos: Vec<DexProto>,
    /// All field references.
    pub fields: Vec<DexField>,
    /// All method references.
    pub methods: Vec<DexMethod>,
    /// All class definitions.
    pub classes: Vec<DexClass>,
}

// =============================================================================
// Low-level nom parsers
// =============================================================================

/// Parse the DEX magic bytes.
fn parse_magic(input: &[u8]) -> IResult<&[u8], [u8; 8]> {
    let (input, magic) = take(8usize)(input)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(magic);
    Ok((input, arr))
}

/// Parse a DEX header (0x70 bytes).
fn parse_header(input: &[u8]) -> IResult<&[u8], DexHeader> {
    let (input, (magic, checksum, signature, file_size, header_size, endian_tag, link_size,
                  link_off, map_off, string_ids_size, string_ids_off, type_ids_size,
                  type_ids_off, proto_ids_size, proto_ids_off, field_ids_size,
                  field_ids_off, method_ids_size, method_ids_off, class_defs_size,
                  class_defs_off)) = tuple((
        parse_magic,
        le_u32,
        take(20usize),
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
    ))(input)?;
    let (input, (data_size, data_off)) = tuple((
        le_u32,
        le_u32,
    ))(input)?;

    let mut sig = [0u8; 20];
    sig.copy_from_slice(signature);

    Ok((input, DexHeader {
        magic,
        checksum,
        signature: sig,
        file_size,
        header_size,
        endian_tag,
        link_size,
        link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    }))
}

// =============================================================================
// MUTF-8 / modified UTF-8 parsing
// =============================================================================

/// Parse a MUTF-8 (modified UTF-8) encoded string from a `string_data_item`.
///
/// MUTF-8 differs from standard UTF-8:
/// - Code point 0 (U+0000) is encoded as the two-byte sequence 0xC0 0x80.
/// - Supplementary characters (U+10000+) are encoded as a six-byte sequence
///   (a surrogate pair in modified CESU-8).
fn parse_mutf8(input: &[u8]) -> IResult<&[u8], String> {
    let (input, len) = read_uleb128(input)?;
    let len = len as usize;

    // Validate length against remaining input (approximate — MUTF-8 can be narrower
    // or wider than the decoded length; worst case 3 bytes per UTF-8 codepoint)
    if input.len() < len {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }

    let (input, data) = take(len)(input)?;
    let mut result = String::with_capacity(len);
    let mut pos = 0;

    while pos < data.len() {
        let b = data[pos];
        match b {
            0x00..=0x7F => {
                // One-byte encoding, but 0x00 maps to U+0000 (NUL is encoded as C0 80)
                if b == 0x00 {
                    result.push('\0');
                } else {
                    result.push(b as char);
                }
                pos += 1;
            }
            0xC0..=0xDF => {
                if pos + 1 >= data.len() {
                    break;
                }
                let b1 = data[pos + 1];
                if b == 0xC0 && b1 == 0x80 {
                    // MUTF-8 encoding of U+0000
                    result.push('\0');
                } else {
                    let cp = ((b as u32 & 0x1F) << 6) | (b1 as u32 & 0x3F);
                    result.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                }
                pos += 2;
            }
            0xED => {
                // Surrogate pair encoding for supplementary characters (CESU-8)
                if pos + 5 >= data.len() {
                    break;
                }
                // First surrogate (U+D800..U+DBFF)
                let b1 = data[pos + 1];
                let b2 = data[pos + 2];
                let hi = ((b as u32 & 0x0F) << 12)
                    | ((b1 as u32 & 0x3F) << 6)
                    | (b2 as u32 & 0x3F);

                // Second surrogate (U+DC00..U+DFFF), expected 0xED 0xBx 0x8x-0xBF
                let b3 = data[pos + 3];
                let b4 = data[pos + 4];
                let b5 = data[pos + 5];
                let lo = ((b3 as u32 & 0x0F) << 12)
                    | ((b4 as u32 & 0x3F) << 6)
                    | (b5 as u32 & 0x3F);

                let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                result.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                pos += 6;
            }
            0xE0..=0xEF => {
                if pos + 2 >= data.len() {
                    break;
                }
                let b1 = data[pos + 1];
                let b2 = data[pos + 2];
                let cp = ((b as u32 & 0x0F) << 12)
                    | ((b1 as u32 & 0x3F) << 6)
                    | (b2 as u32 & 0x3F);
                result.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                pos += 3;
            }
            _ => {
                // Invalid lead byte, skip
                result.push('\u{FFFD}');
                pos += 1;
            }
        }
    }

    // input is already past the consumed string bytes
    Ok((input, result))
}

/// Read a single LEB128 unsigned integer.
fn read_uleb128(input: &[u8]) -> IResult<&[u8], u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut pos = 0;

    while pos < input.len() {
        let byte = input[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((&input[pos..], result));
        }
        shift += 7;
        if shift >= 64 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            )));
        }
    }

    Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Eof,
    )))
}

/// Read a single LEB128 signed integer.
fn read_sleb128(input: &[u8]) -> IResult<&[u8], i64> {
    let mut result: i64 = 0;
    let mut shift = 0;
    let mut pos = 0;

    while pos < input.len() {
        let byte = input[pos];
        pos += 1;
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            // Sign-extend if the top bit of the last byte was set
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0 << shift;
            }
            return Ok((&input[pos..], result));
        }
    }

    Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Eof,
    )))
}

// =============================================================================
// Encoded value parsing
// =============================================================================

/// Parse an encoded value from the data section.
fn parse_encoded_value(input: &[u8]) -> IResult<&[u8], EncodedValue> {
    let (input, header) = le_u8(input)?;
    let value_type = header & 0x1F;
    let value_arg = (header >> 5) as usize;

    // Helper to read the value argument bytes
    fn read_value_arg(input: &[u8], arg: usize) -> IResult<&[u8], u64> {
        let (input, bytes) = take(arg + 1)(input)?;
        let mut val: u64 = 0;
        for &b in bytes.iter() {
            val = (val << 8) | (b as u64);
        }
        Ok((input, val))
    }

    match value_type {
        0x00 => {
            // VALUE_BYTE
            let (input, v) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Byte(v as i8)))
        }
        0x02 => {
            // VALUE_SHORT
            let (input, v) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Short(v as i16)))
        }
        0x03 => {
            // VALUE_CHAR
            let (input, v) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Char(v as u16)))
        }
        0x04 => {
            // VALUE_INT
            let (input, v) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Int(v as i32)))
        }
        0x06 => {
            // VALUE_LONG
            let (input, v) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Long(v as i64)))
        }
        0x10 => {
            // VALUE_FLOAT
            let (input, v) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Float(f32::from_bits(v as u32))))
        }
        0x11 => {
            // VALUE_DOUBLE
            let (input, v) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Double(f64::from_bits(v))))
        }
        0x17 => {
            // VALUE_STRING
            let (input, idx) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::String(idx as u32)))
        }
        0x18 => {
            // VALUE_TYPE
            let (input, idx) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Type(idx as u32)))
        }
        0x19 => {
            // VALUE_FIELD
            let (input, idx) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Field(idx as u32)))
        }
        0x1A => {
            // VALUE_METHOD
            let (input, idx) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Method(idx as u32)))
        }
        0x1B => {
            // VALUE_ENUM
            let (input, idx) = read_value_arg(input, value_arg)?;
            Ok((input, EncodedValue::Enum(idx as u32)))
        }
        0x1C => {
            // VALUE_ARRAY
            let (input, elem_count) = read_uleb128(input)?;
            let (input, elements) = nom::multi::count(parse_encoded_value, elem_count as usize)(input)?;
            Ok((input, EncodedValue::Array(elements)))
        }
        0x1D => {
            // VALUE_ANNOTATION
            let (input, annotation) = parse_encoded_annotation(input)?;
            Ok((input, EncodedValue::Annotation(annotation)))
        }
        0x1E => {
            // VALUE_NULL
            Ok((input, EncodedValue::Null))
        }
        0x1F => {
            // VALUE_BOOLEAN
            Ok((input, EncodedValue::Boolean(value_arg != 0)))
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

/// Parse an encoded annotation.
fn parse_encoded_annotation(input: &[u8]) -> IResult<&[u8], DexAnnotation> {
    let (input, type_idx) = read_uleb128(input)?;
    let (input, size) = read_uleb128(input)?;
    let mut elements = Vec::with_capacity(size as usize);

    let mut rest = input;
    for _ in 0..size {
        let (input, _name_idx) = read_uleb128(rest)?;
        let (input, value) = parse_encoded_value(input)?;
        elements.push(AnnotationElement {
            name: String::new(), // resolved later from string_ids
            value,
        });
        // Store name_idx separately — we'll resolve it later
        rest = input;
    }

    Ok((rest, DexAnnotation {
        visibility: AnnotationVisibility::Runtime,
        type_idx: type_idx as u32,
        elements,
    }))
}

// =============================================================================
// top-level parse_dex entry point
// =============================================================================

/// Parse a complete DEX file from raw bytes.
///
/// This is the main entry point. It parses the header, validates magic and
/// checksum, then parses all tables and class definitions, resolving string
/// references throughout.
///
/// # Errors
///
/// Returns a [`DexError`] if the input is not valid DEX data.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::dex::{parse_dex, DexFile};
///
/// let data = std::fs::read("classes.dex")?;
/// let dex = parse_dex(&data)?;
/// println!("Parsed {} classes", dex.classes.len());
/// ```
pub fn parse_dex(data: &[u8]) -> Result<DexFile, DexError> {
    // Parse header
    let (remaining, header) = parse_header(data)
        .map_err(|e| DexError::NomError(format!("Failed to parse DEX header: {:?}", e)))?;

    // Validate magic
    if header.magic[0..4] != DEX_MAGIC {
        return Err(DexError::InvalidMagic(header.magic.to_vec()));
    }

    // Validate file size
    if header.file_size as usize > data.len() {
        return Err(DexError::TruncatedInput {
            expected: header.file_size as usize,
            actual: data.len(),
        });
    }

    // Validate table sizes against safety limit
    let tables = [
        ("string_ids", header.string_ids_size),
        ("type_ids", header.type_ids_size),
        ("proto_ids", header.proto_ids_size),
        ("field_ids", header.field_ids_size),
        ("method_ids", header.method_ids_size),
        ("class_defs", header.class_defs_size),
    ];
    for (name, count) in &tables {
        if *count > MAX_TABLE_ENTRIES {
            return Err(DexError::TableTooLarge {
                table: name,
                count: *count,
                max: MAX_TABLE_ENTRIES,
            });
        }
    }

    let _ = remaining; // we index from `data` throughout

    // Parse strings
    let strings = parse_strings(data, &header, &[])?;

    // Parse types
    let types = parse_types(data, &header, &strings)?;

    // Parse protos
    let protos = parse_protos(data, &header, &strings, &types)?;

    // Parse fields
    let fields = parse_fields(data, &header, &strings, &types)?;

    // Parse methods
    let methods = parse_methods(data, &header, &strings, &types, &protos)?;

    // Parse classes
    let classes = parse_classes(data, &header, &strings, &types, &fields, &methods)?;

    Ok(DexFile {
        header,
        strings,
        types,
        protos,
        fields,
        methods,
        classes,
    })
}

/// Parse all string_data_items.
fn parse_strings(data: &[u8], header: &DexHeader, _strings: &[String]) -> Result<Vec<String>, DexError> {
    // The string_ids table just contains offsets into string_data items.
    // We parse each string_data_item and collect the strings.
    // But we have a bootstrapping problem: strings are needed for types, but we
    // need to parse them first. So this function actually parses strings from the
    // string_ids table and string_data items.

    if header.string_ids_off == 0 || header.string_ids_size == 0 {
        return Ok(Vec::new());
    }

    let table_start = header.string_ids_off as usize;
    let entry_size = 4; // each string_id is a uint32 offset
    let table_size = header.string_ids_size as usize * entry_size;

    if table_start + table_size > data.len() {
        return Err(DexError::TruncatedInput {
            expected: table_start + table_size,
            actual: data.len(),
        });
    }

    let mut result = Vec::with_capacity(header.string_ids_size as usize);

    for i in 0..header.string_ids_size as usize {
        let offset_bytes = &data[table_start + i * 4..table_start + i * 4 + 4];
        let offset = u32::from_le_bytes([offset_bytes[0], offset_bytes[1], offset_bytes[2], offset_bytes[3]]);

        if offset == 0 || offset as usize >= data.len() {
            result.push(String::new());
            continue;
        }

        let string_data = &data[offset as usize..];
        match parse_mutf8(string_data) {
            Ok((_, s)) => result.push(s),
            Err(_) => result.push(String::new()),
        }
    }

    Ok(result)
}

/// Parse the type_ids table.
fn parse_types(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
) -> Result<Vec<DexType>, DexError> {
    if header.type_ids_off == 0 || header.type_ids_size == 0 {
        return Ok(Vec::new());
    }

    let table_start = header.type_ids_off as usize;
    let entry_size = 4; // each type_id is a uint32 string index
    let table_size = header.type_ids_size as usize * entry_size;

    if table_start + table_size > data.len() {
        return Err(DexError::TruncatedInput {
            expected: table_start + table_size,
            actual: data.len(),
        });
    }

    let mut result = Vec::with_capacity(header.type_ids_size as usize);

    for i in 0..header.type_ids_size as usize {
        let offset_bytes = &data[table_start + i * 4..table_start + i * 4 + 4];
        let descriptor_idx = u32::from_le_bytes([offset_bytes[0], offset_bytes[1], offset_bytes[2], offset_bytes[3]]);
        let descriptor = strings.get(descriptor_idx as usize).cloned().unwrap_or_default();

        result.push(DexType {
            descriptor_idx,
            descriptor,
        });
    }

    Ok(result)
}

/// Parse the proto_ids table.
fn parse_protos(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[DexType],
) -> Result<Vec<DexProto>, DexError> {
    if header.proto_ids_off == 0 || header.proto_ids_size == 0 {
        return Ok(Vec::new());
    }

    let table_start = header.proto_ids_off as usize;
    let entry_size = 12; // shorty_idx: u32, return_type_idx: u32, parameters_off: u32
    let table_size = header.proto_ids_size as usize * entry_size;

    if table_start + table_size > data.len() {
        return Err(DexError::TruncatedInput {
            expected: table_start + table_size,
            actual: data.len(),
        });
    }

    let mut result = Vec::with_capacity(header.proto_ids_size as usize);

    for i in 0..header.proto_ids_size as usize {
        let entry = &data[table_start + i * 12..table_start + i * 12 + 12];
        let shorty_idx = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let return_type_idx = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let parameters_off = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);

        let shorty = strings.get(shorty_idx as usize).cloned().unwrap_or_default();
        let return_type = types.get(return_type_idx as usize)
            .map(|t| t.descriptor.clone())
            .unwrap_or_default();

        let parameters = if parameters_off > 0
            && (parameters_off as usize) < data.len()
        {
            let type_list = &data[parameters_off as usize..];
            // type_list: size (u32) followed by type_idx (u16) entries
            if type_list.len() >= 4 {
                let size = u32::from_le_bytes([type_list[0], type_list[1], type_list[2], type_list[3]]);
                let max_size = (type_list.len() - 4) / 2;
                let size = (size as usize).min(max_size);
                let mut params = Vec::with_capacity(size);
                for j in 0..size {
                    let base = 4 + j * 2;
                    let type_idx = u16::from_le_bytes([type_list[base], type_list[base + 1]]);
                    params.push(
                        types.get(type_idx as usize)
                            .map(|t| t.descriptor.clone())
                            .unwrap_or_default()
                    );
                }
                params
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        result.push(DexProto {
            shorty_idx,
            shorty,
            return_type_idx,
            return_type,
            parameters_off,
            parameters,
        });
    }

    Ok(result)
}

/// Parse the field_ids table.
fn parse_fields(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[DexType],
) -> Result<Vec<DexField>, DexError> {
    if header.field_ids_off == 0 || header.field_ids_size == 0 {
        return Ok(Vec::new());
    }

    let table_start = header.field_ids_off as usize;
    let entry_size = 8; // class_idx: u16, type_idx: u16, name_idx: u32
    let table_size = header.field_ids_size as usize * entry_size;

    if table_start + table_size > data.len() {
        return Err(DexError::TruncatedInput {
            expected: table_start + table_size,
            actual: data.len(),
        });
    }

    let mut result = Vec::with_capacity(header.field_ids_size as usize);

    for i in 0..header.field_ids_size as usize {
        let entry = &data[table_start + i * 8..table_start + i * 8 + 8];
        let class_idx = u16::from_le_bytes([entry[0], entry[1]]) as u32;
        let type_idx = u16::from_le_bytes([entry[2], entry[3]]) as u32;
        let name_idx = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);

        let class = types.get(class_idx as usize)
            .map(|t| t.descriptor.clone())
            .unwrap_or_default();
        let field_type = types.get(type_idx as usize)
            .map(|t| t.descriptor.clone())
            .unwrap_or_default();
        let name = strings.get(name_idx as usize).cloned().unwrap_or_default();

        result.push(DexField {
            class_idx,
            class,
            type_idx,
            field_type,
            name_idx,
            name,
        });
    }

    Ok(result)
}

/// Parse the method_ids table.
fn parse_methods(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[DexType],
    protos: &[DexProto],
) -> Result<Vec<DexMethod>, DexError> {
    if header.method_ids_off == 0 || header.method_ids_size == 0 {
        return Ok(Vec::new());
    }

    let table_start = header.method_ids_off as usize;
    let entry_size = 8; // class_idx: u16, proto_idx: u16, name_idx: u32
    let table_size = header.method_ids_size as usize * entry_size;

    if table_start + table_size > data.len() {
        return Err(DexError::TruncatedInput {
            expected: table_start + table_size,
            actual: data.len(),
        });
    }

    let mut result = Vec::with_capacity(header.method_ids_size as usize);

    for i in 0..header.method_ids_size as usize {
        let entry = &data[table_start + i * 8..table_start + i * 8 + 8];
        let class_idx = u16::from_le_bytes([entry[0], entry[1]]) as u32;
        let proto_idx = u16::from_le_bytes([entry[2], entry[3]]) as u32;
        let name_idx = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);

        let class = types.get(class_idx as usize)
            .map(|t| t.descriptor.clone())
            .unwrap_or_default();
        let name = strings.get(name_idx as usize).cloned().unwrap_or_default();

        let proto = protos.get(proto_idx as usize);
        let return_type = proto.map(|p| p.return_type.clone()).unwrap_or_default();
        let parameters = proto.map(|p| p.parameters.clone()).unwrap_or_default();

        result.push(DexMethod {
            class_idx,
            class,
            proto_idx,
            return_type,
            parameters,
            name_idx,
            name,
            access_flags: 0,
            code: None,
            registers: 0,
            ins_size: 0,
        });
    }

    Ok(result)
}

/// Parse all class definitions.
fn parse_classes(
    data: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[DexType],
    fields: &[DexField],
    methods: &[DexMethod],
) -> Result<Vec<DexClass>, DexError> {
    if header.class_defs_off == 0 || header.class_defs_size == 0 {
        return Ok(Vec::new());
    }

    let table_start = header.class_defs_off as usize;
    let entry_size = 32; // class_idx: u32, access_flags: u32, superclass_idx: u32, interfaces_off: u32, source_file_idx: u32, annotations_off: u32, class_data_off: u32, static_values_off: u32
    let table_size = header.class_defs_size as usize * entry_size;

    if table_start + table_size > data.len() {
        return Err(DexError::TruncatedInput {
            expected: table_start + table_size,
            actual: data.len(),
        });
    }

    let mut result = Vec::with_capacity(header.class_defs_size as usize);

    for i in 0..header.class_defs_size as usize {
        let entry = &data[table_start + i * 32..table_start + i * 32 + 32];
        let class_idx = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let access_flags = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let superclass_idx = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
        let interfaces_off = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
        let source_file_idx = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);
        let annotations_off = u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]]);
        let class_data_off = u32::from_le_bytes([entry[24], entry[25], entry[26], entry[27]]);
        let static_values_off = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);

        let name = types.get(class_idx as usize)
            .map(|t| t.descriptor.clone())
            .unwrap_or_default();

        let superclass = if superclass_idx != NO_INDEX {
            types.get(superclass_idx as usize)
                .map(|t| t.descriptor.clone())
        } else {
            None
        };

        let interfaces = parse_type_list_at(data, interfaces_off, types)
            .unwrap_or_default();

        let source_file = if source_file_idx != NO_INDEX {
            strings.get(source_file_idx as usize).cloned()
        } else {
            None
        };

        // Parse class_data_item
        let (instance_fields, static_fields, direct_methods_data, virtual_methods_data) =
            if class_data_off > 0 && (class_data_off as usize) < data.len() {
                parse_class_data(data, class_data_off, fields, methods, strings)
                    .unwrap_or_default()
            } else {
                Default::default()
            };

        result.push(DexClass {
            class_idx,
            name,
            access_flags,
            superclass_idx,
            superclass,
            interfaces_off,
            interfaces,
            source_file_idx,
            source_file,
            annotations_off,
            class_data_off,
            static_values_off,
            direct_methods: direct_methods_data,
            virtual_methods: virtual_methods_data,
            instance_fields,
            static_fields,
        });
    }

    Ok(result)
}

/// Parse a type_list at a given offset.
fn parse_type_list_at(
    data: &[u8],
    offset: u32,
    types: &[DexType],
) -> Result<Vec<String>, DexError> {
    if offset == 0 || offset as usize + 4 > data.len() {
        return Ok(Vec::new());
    }

    let list = &data[offset as usize..];
    if list.len() < 4 {
        return Ok(Vec::new());
    }

    let size = u32::from_le_bytes([list[0], list[1], list[2], list[3]]);
    let max_size = ((list.len() - 4) / 2) as u32;
    let size = size.min(max_size);

    let mut result = Vec::with_capacity(size as usize);
    for i in 0..size {
        let base = 4 + (i as usize) * 2;
        let type_idx = u16::from_le_bytes([list[base], list[base + 1]]);
        result.push(
            types.get(type_idx as usize)
                .map(|t| t.descriptor.clone())
                .unwrap_or_default()
        );
    }

    Ok(result)
}

/// Parse a class_data_item.
fn parse_class_data(
    data: &[u8],
    offset: u32,
    fields: &[DexField],
    methods: &[DexMethod],
    strings: &[String],
) -> Result<(Vec<DexField>, Vec<DexField>, Vec<DexMethod>, Vec<DexMethod>), DexError> {
    let input = &data[offset as usize..];

    // Read counts with uleb128
    let (input, static_fields_size) = read_uleb128(input)
        .map_err(|e| DexError::NomError(format!("Failed to read static_fields_size: {:?}", e)))?;
    let (input, instance_fields_size) = read_uleb128(input)
        .map_err(|e| DexError::NomError(format!("Failed to read instance_fields_size: {:?}", e)))?;
    let (input, direct_methods_size) = read_uleb128(input)
        .map_err(|e| DexError::NomError(format!("Failed to read direct_methods_size: {:?}", e)))?;
    let (mut input, virtual_methods_size) = read_uleb128(input)
        .map_err(|e| DexError::NomError(format!("Failed to read virtual_methods_size: {:?}", e)))?;

    let mut static_flds = Vec::with_capacity(static_fields_size as usize);
    let mut instance_flds = Vec::with_capacity(instance_fields_size as usize);
    let mut direct_mtds = Vec::with_capacity(direct_methods_size as usize);
    let mut virtual_mtds = Vec::with_capacity(virtual_methods_size as usize);

    // Parse encoded fields
    let mut last_field_idx = 0u32;
    let static_count = static_fields_size as usize + instance_fields_size as usize;
    let mut parsed_fields: Vec<(u32, u32)> = Vec::with_capacity(static_count);

    for s in [static_fields_size as usize, instance_fields_size as usize].iter() {
        for _ in 0..*s {
            let (inp, field_idx_diff) = read_uleb128(input)
                .map_err(|e| DexError::NomError(format!("Failed to read field_idx_diff: {:?}", e)))?;
            let (inp, access_flags) = read_uleb128(inp)
                .map_err(|e| DexError::NomError(format!("Failed to read access_flags: {:?}", e)))?;
            last_field_idx += field_idx_diff as u32;
            parsed_fields.push((last_field_idx, access_flags as u32));
            input = inp;
        }
    }

    // Parse encoded methods
    let mut last_method_idx = 0u32;
    let total_methods = direct_methods_size as usize + virtual_methods_size as usize;
    let mut parsed_methods: Vec<(u32, u32, u32)> = Vec::with_capacity(total_methods);

    for _ in 0..direct_methods_size as usize + virtual_methods_size as usize {
        let (inp, method_idx_diff) = read_uleb128(input)
            .map_err(|e| DexError::NomError(format!("Failed to read method_idx_diff: {:?}", e)))?;
        let (inp, access_flags) = read_uleb128(inp)
            .map_err(|e| DexError::NomError(format!("Failed to read access_flags: {:?}", e)))?;
        let (inp, code_off) = read_uleb128(inp)
            .map_err(|e| DexError::NomError(format!("Failed to read code_off: {:?}", e)))?;
        last_method_idx += method_idx_diff as u32;
        parsed_methods.push((last_method_idx, access_flags as u32, code_off as u32));
        input = inp;
    }

    // Resolve static fields
    for &(idx, _flags) in &parsed_fields[..static_fields_size as usize] {
        let mut field = fields.get(idx as usize).cloned().unwrap_or_else(|| DexField {
            class_idx: 0,
            class: String::new(),
            type_idx: 0,
            field_type: String::new(),
            name_idx: 0,
            name: String::new(),
        });
        field.name = strings.get(field.name_idx as usize).cloned().unwrap_or_default();
        static_flds.push(field);
    }

    // Resolve instance fields
    for &(idx, _flags) in &parsed_fields[static_fields_size as usize..] {
        let mut field = fields.get(idx as usize).cloned().unwrap_or_else(|| DexField {
            class_idx: 0,
            class: String::new(),
            type_idx: 0,
            field_type: String::new(),
            name_idx: 0,
            name: String::new(),
        });
        field.name = strings.get(field.name_idx as usize).cloned().unwrap_or_default();
        instance_flds.push(field);
    }

    // Resolve direct methods
    for &(idx, flags, code_off) in &parsed_methods[..direct_methods_size as usize] {
        let mut method = methods.get(idx as usize).cloned().unwrap_or_else(|| DexMethod {
            class_idx: 0,
            class: String::new(),
            proto_idx: 0,
            return_type: String::new(),
            parameters: Vec::new(),
            name_idx: 0,
            name: String::new(),
            access_flags: 0,
            code: None,
            registers: 0,
            ins_size: 0,
        });
        method.access_flags = flags;
        method.name = strings.get(method.name_idx as usize).cloned().unwrap_or_default();

        if code_off > 0 && (code_off as usize) < data.len() {
            method.code = parse_code_item(data, code_off).ok();
            if let Some(ref code) = method.code {
                method.registers = code.registers_size;
                method.ins_size = code.ins_size;
            }
        }
        direct_mtds.push(method);
    }

    // Resolve virtual methods
    for &(idx, flags, code_off) in &parsed_methods[direct_methods_size as usize..] {
        let mut method = methods.get(idx as usize).cloned().unwrap_or_else(|| DexMethod {
            class_idx: 0,
            class: String::new(),
            proto_idx: 0,
            return_type: String::new(),
            parameters: Vec::new(),
            name_idx: 0,
            name: String::new(),
            access_flags: 0,
            code: None,
            registers: 0,
            ins_size: 0,
        });
        method.access_flags = flags;
        method.name = strings.get(method.name_idx as usize).cloned().unwrap_or_default();

        if code_off > 0 && (code_off as usize) < data.len() {
            method.code = parse_code_item(data, code_off).ok();
            if let Some(ref code) = method.code {
                method.registers = code.registers_size;
                method.ins_size = code.ins_size;
            }
        }
        virtual_mtds.push(method);
    }

    Ok((instance_flds, static_flds, direct_mtds, virtual_mtds))
}

/// Parse a code_item at a given offset.
fn parse_code_item(data: &[u8], offset: u32) -> Result<DexCode, DexError> {
    let start = offset as usize;
    if start + 16 > data.len() {
        return Err(DexError::TruncatedInput {
            expected: start + 16,
            actual: data.len(),
        });
    }

    let src = &data[start..];
    let registers_size = u16::from_le_bytes([src[0], src[1]]);
    let ins_size = u16::from_le_bytes([src[2], src[3]]);
    let outs_size = u16::from_le_bytes([src[4], src[5]]);
    let tries_size = u16::from_le_bytes([src[6], src[7]]);
    let debug_info_off = u32::from_le_bytes([src[8], src[9], src[10], src[11]]);
    let insns_size = u32::from_le_bytes([src[12], src[13], src[14], src[15]]) as usize;

    let insns_start = start + 16;
    let insns_end = insns_start + insns_size * 2; // instructions are in 16-bit code units

    if insns_end > data.len() {
        return Err(DexError::TruncatedInput {
            expected: insns_end,
            actual: data.len(),
        });
    }

    let insns = data[insns_start..insns_end].to_vec();

    // Parse tries and handlers
    let mut tries = Vec::new();
    let mut handlers = Vec::new();

    if tries_size > 0 {
        // If tries_size is non-zero, tries are between instructions and handlers.
        // Need to align to 4 bytes after instructions.
        let mut try_offset = insns_end;
        // Align to 4 bytes if not already
        while try_offset % 4 != 0 {
            try_offset += 1;
        }

        for _ in 0..tries_size {
            if try_offset + 8 > data.len() {
                break;
            }
            let start_addr = u32::from_le_bytes([
                data[try_offset], data[try_offset + 1],
                data[try_offset + 2], data[try_offset + 3],
            ]);
            let insn_count = u16::from_le_bytes([
                data[try_offset + 4], data[try_offset + 5],
            ]);
            let handler_off = u16::from_le_bytes([
                data[try_offset + 6], data[try_offset + 7],
            ]);
            tries.push(TryItem {
                start_addr,
                insn_count,
                handler_off,
            });
            try_offset += 8;
        }

        // Parse encoded_catch_handler_list
        // The handler offset is relative to the start of the encoded_catch_handler_list
        // which begins right after the tries.
        if try_offset + 4 <= data.len() {
            let encoded_catch_handler_list_size = read_uleb128(&data[try_offset..])
                .map(|(_, v)| v)
                .unwrap_or(0);
            let mut handler_pos = try_offset;
            let (after, _size) = read_uleb128(&data[handler_pos..])
                .map_err(|e| DexError::NomError(format!("Failed to read handler list size: {:?}", e)))?;
            handler_pos = handler_pos + (handler_pos - after.len());

            for _ in 0..encoded_catch_handler_list_size {
                let handler_result = parse_encoded_catch_handler(data, handler_pos);
                if let Ok((rest, handler)) = handler_result {
                    handlers.push(handler);
                    // `data[handler_pos..]` - `rest` gives bytes consumed
                    let consumed = rest.as_ptr() as usize - data[handler_pos..].as_ptr() as usize;
                    handler_pos += consumed;
                } else {
                    break;
                }
            }
        }
    }

    Ok(DexCode {
        registers_size,
        ins_size,
        outs_size,
        tries_size,
        debug_info_off,
        insns,
        tries,
        handlers,
    })
}

/// Parse an encoded catch handler.
fn parse_encoded_catch_handler(data: &[u8], offset: usize) -> IResult<&[u8], EncodedCatchHandler> {
    let input = &data[offset..];
    let (input, size) = read_sleb128(input)?;
    let size_i32 = size as i32;

    let mut handlers = Vec::new();
    let mut catch_all_addr = None;
    let mut rest = input;

    let abs_size = if size_i32 <= 0 { -size_i32 } else { size_i32 };
    for _ in 0..abs_size {
        let (inp, type_idx) = read_uleb128(rest)?;
        let (inp, addr) = read_uleb128(inp)?;
        handlers.push(EncodedTypeAddrPair {
            type_idx: type_idx as u32,
            addr: addr as u32,
        });
        rest = inp;
    }

    if size_i32 <= 0 {
        let (inp, addr) = read_uleb128(rest)?;
        catch_all_addr = Some(addr as u32);
        rest = inp;
    }

    Ok((rest, EncodedCatchHandler {
        size: size_i32,
        handlers,
        catch_all_addr,
    }))
}

// =============================================================================
// Smali-like representation helpers
// =============================================================================

impl DexFile {
    /// Produce a smali-like disassembly of all classes in this DEX file.
    ///
    /// Returns a vector of (class_name, smali_source) pairs.
    pub fn to_smali(&self) -> Vec<(String, String)> {
        self.classes.iter().map(|class| {
            (class.name.clone(), self.class_to_smali(class))
        }).collect()
    }

    /// Convert a single class to a smali-like representation.
    fn class_to_smali(&self, class: &DexClass) -> String {
        let mut out = String::new();

        // Class header
        let access = access_flag_names(class.access_flags).join(" ");
        out.push_str(&format!(".class {} {};\n", access, class.name));

        if let Some(ref superclass) = class.superclass {
            out.push_str(&format!(".super {}\n", superclass));
        }

        for iface in &class.interfaces {
            out.push_str(&format!(".implements {}\n", iface));
        }

        if let Some(ref source) = class.source_file {
            out.push_str(&format!(".source \"{}\"\n", source));
        }

        out.push('\n');

        // Static fields
        for field in &class.static_fields {
            let access = access_flag_names(field.name_idx as u32).join(" ");
            out.push_str(&format!(
                "    .field {} {}:{}\n",
                access, field.name, field.field_type
            ));
        }

        // Instance fields
        for field in &class.instance_fields {
            let access = access_flag_names(field.name_idx as u32).join(" ");
            out.push_str(&format!(
                "    .field {} {}:{}\n",
                access, field.name, field.field_type
            ));
        }

        out.push('\n');

        // Direct methods
        for method in &class.direct_methods {
            out.push_str(&self.method_to_smali(method, "direct"));
            out.push('\n');
        }

        // Virtual methods
        for method in &class.virtual_methods {
            out.push_str(&self.method_to_smali(method, "virtual"));
            out.push('\n');
        }

        out
    }

    /// Convert a method to a smali-like representation.
    fn method_to_smali(&self, method: &DexMethod, _kind: &str) -> String {
        let mut out = String::new();
        let access = access_flag_names(method.access_flags).join(" ");
        let params = method.parameters.join("");
        out.push_str(&format!(
            "    .method {} {}({}){};\n",
            access, method.name, params, method.return_type
        ));

        if let Some(ref code) = method.code {
            out.push_str(&format!(
                "        .registers {}\n",
                code.registers_size
            ));
            out.push_str(&format!(
                "        .locals {}\n",
                code.registers_size.saturating_sub(method.ins_size)
            ));

            // Disassemble instructions (simplified — just hex dump for now)
            let insns = &code.insns;
            let mut pos = 0;
            while pos + 1 < insns.len() {
                let opcode = insns[pos] as u16 | ((insns[pos + 1] as u16) << 8);
                out.push_str(&format!("        {:04x}\n", opcode));
                pos += 2;
            }
        }

        out.push_str("    .end method\n");
        out
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal valid DEX file in memory.
    fn make_minimal_dex() -> Vec<u8> {
        // This is a carefully constructed minimal DEX file.
        // We need to ensure all offsets are consistent.
        // For simplicity we test with a real-world DEX or skip if not available.

        // Minimal DEX layout:
        // [header 0x70] [string_ids] [type_ids] [proto_ids] [field_ids] [method_ids] [class_defs] [data]

        let mut buf = Vec::new();

        // DEX header (0x70 = 112 bytes)
        let magic = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]; // dex\n035\0
        buf.extend_from_slice(&magic);                    // 0x00: magic (8)
        buf.extend_from_slice(&[0u8; 4]);                  // 0x08: checksum (placeholder)
        buf.extend_from_slice(&[0u8; 20]);                 // 0x0C: signature (placeholder)
        // file_size: we will patch this later
        let file_size_off = buf.len();
        buf.extend_from_slice(&0x70u32.to_le_bytes());     // 0x20: file_size (placeholder -> patch)
        buf.extend_from_slice(&0x70u32.to_le_bytes());     // 0x24: header_size = 0x70
        buf.extend_from_slice(&0x12345678u32.to_le_bytes()); // 0x28: endian_tag
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x2C: link_size
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x30: link_off
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x34: map_off (0 = no map)
        buf.extend_from_slice(&1u32.to_le_bytes());        // 0x38: string_ids_size = 1
        let string_ids_off = buf.len() + 4; // starts after header
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x3C: string_ids_off (patch)
        buf.extend_from_slice(&1u32.to_le_bytes());        // 0x40: type_ids_size = 1
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x44: type_ids_off (patch)
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x48: proto_ids_size = 0
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x4C: proto_ids_off
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x50: field_ids_size = 0
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x54: field_ids_off
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x58: method_ids_size = 0
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x5C: method_ids_off
        buf.extend_from_slice(&1u32.to_le_bytes());        // 0x60: class_defs_size = 1
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x64: class_defs_off (patch)
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x68: data_size (patch)
        buf.extend_from_slice(&0u32.to_le_bytes());        // 0x6C: data_off (patch)

        assert_eq!(buf.len(), 0x70); // Header done

        // String IDs table: one entry, offset to "Ljava/lang/Object;"
        let string_ids_off_val = buf.len() as u32;
        buf[0x3C..0x40].copy_from_slice(&string_ids_off_val.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // placeholder, patched below

        // Type IDs table: one entry, string index 0
        let type_ids_off_val = buf.len() as u32;
        buf[0x44..0x48].copy_from_slice(&type_ids_off_val.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // descriptor_idx = 0

        // Class defs table: one entry
        let class_defs_off_val = buf.len() as u32;
        buf[0x64..0x68].copy_from_slice(&class_defs_off_val.to_le_bytes());
        // class_idx=0, access_flags=ACC_PUBLIC, superclass_idx=NO_INDEX, interfaces_off=0,
        // source_file_idx=NO_INDEX, annotations_off=0, class_data_off=0, static_values_off=0
        buf.extend_from_slice(&0u32.to_le_bytes());    // class_idx = 0
        buf.extend_from_slice(&0x0001u32.to_le_bytes()); // access_flags = ACC_PUBLIC
        buf.extend_from_slice(&NO_INDEX.to_le_bytes());  // superclass_idx = NO_INDEX
        buf.extend_from_slice(&0u32.to_le_bytes());    // interfaces_off
        buf.extend_from_slice(&NO_INDEX.to_le_bytes());  // source_file_idx = NO_INDEX
        buf.extend_from_slice(&0u32.to_le_bytes());    // annotations_off
        buf.extend_from_slice(&0u32.to_le_bytes());    // class_data_off
        buf.extend_from_slice(&0u32.to_le_bytes());    // static_values_off

        // Data section: string_data_item for "Ljava/lang/Object;"
        let data_off_val = buf.len() as u32;
        buf[0x6C..0x70].copy_from_slice(&data_off_val.to_le_bytes());
        // Patch string_ids[0] to point to the string data in the data section
        buf[string_ids_off_val as usize..string_ids_off_val as usize + 4]
            .copy_from_slice(&data_off_val.to_le_bytes());
        // MUTF-8: L j a v a / l a n g / O b j e c t ;
        // length uleb128: 18
        buf.push(18); // uleb128 length of string
        buf.extend_from_slice(b"Ljava/lang/Object;");
        let data_size_val = (buf.len() as u32) - data_off_val;
        buf[0x68..0x6C].copy_from_slice(&data_size_val.to_le_bytes());

        // Patch file_size
        let file_size = buf.len() as u32;
        buf[file_size_off..file_size_off + 4].copy_from_slice(&file_size.to_le_bytes());

        buf
    }

    #[test]
    fn test_parse_minimal_dex() {
        let data = make_minimal_dex();
        let result = parse_dex(&data);
        assert!(result.is_ok(), "Failed to parse minimal DEX: {:?}", result.err());

        let dex = result.unwrap();
        assert_eq!(dex.strings.len(), 1);
        assert_eq!(dex.strings[0], "Ljava/lang/Object;");
        assert_eq!(dex.types.len(), 1);
        assert_eq!(dex.types[0].descriptor, "Ljava/lang/Object;");
        assert_eq!(dex.classes.len(), 1);
        assert_eq!(dex.classes[0].name, "Ljava/lang/Object;");
        assert_eq!(dex.classes[0].access_flags, 0x0001); // ACC_PUBLIC
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0u8; 256];
        let result = parse_dex(&data);
        assert!(result.is_err());
        match result {
            Err(DexError::InvalidMagic(_)) | Err(DexError::NomError(_)) => {}
            _ => panic!("Expected InvalidMagic or NomError"),
        }
    }

    #[test]
    fn test_access_flag_names() {
        let names = access_flag_names(ACC_PUBLIC | ACC_STATIC | ACC_FINAL);
        assert!(names.contains(&"public"));
        assert!(names.contains(&"static"));
        assert!(names.contains(&"final"));
    }

    #[test]
    fn test_too_small() {
        let data = vec![0x64, 0x65, 0x78, 0x0a]; // "dex\n" but not enough data
        let result = parse_dex(&data);
        assert!(result.is_err());
    }
}
