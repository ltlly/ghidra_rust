//! DEX (Dalvik Executable) format parser.
//!
//! Complete nom-based parser for Android `.dex` bytecode files, including:
//! - Header with magic, checksum, SHA-1 signature
//! - String table (MUTF-8 with varint length prefix)
//! - Type, proto, field, method ID tables
//! - Class definitions with class data (fields, methods, code)
//! - Try/catch blocks and debug info
//! - Annotations and encoded values
//! - Map list for section validation
//!
//! References:
//! - Dalvik Executable Format: <https://source.android.com/docs/core/runtime/dex-format>
//! - AOSP: `dalvik/libdex/DexFile.h`

use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{le_u32, le_u8};
use nom::IResult;
use std::fmt;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Magic & Version Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// DEX magic prefix: "dex\n"
pub const DEX_MAGIC: [u8; 4] = [0x64, 0x65, 0x78, 0x0a]; // "dex\n"
/// Size of the DEX magic field (8 bytes).
pub const DEX_MAGIC_SIZE: usize = 8;
/// Size of the DEX signature field (SHA-1, 20 bytes).
pub const DEX_SIGNATURE_SIZE: usize = 20;
/// Expected DEX header size (0x70 = 112 bytes).
pub const DEX_HEADER_SIZE: usize = 0x70;
/// Maximum allowed entries in any table to prevent DoS.
const MAX_TABLE_ENTRIES: u32 = 65536;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Endianness Tag
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Little-endian endian tag used by all standard DEX files.
pub const ENDIAN_CONSTANT: u32 = 0x12345678;
/// Reversed endian tag (big-endian, rare).
pub const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Access Flags
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
    if flags & ACC_PUBLIC != 0 { names.push("public"); }
    if flags & ACC_PRIVATE != 0 { names.push("private"); }
    if flags & ACC_PROTECTED != 0 { names.push("protected"); }
    if flags & ACC_STATIC != 0 { names.push("static"); }
    if flags & ACC_FINAL != 0 { names.push("final"); }
    if flags & ACC_SYNCHRONIZED != 0 { names.push("synchronized"); }
    if flags & ACC_VOLATILE != 0 { names.push("volatile"); }
    if flags & ACC_BRIDGE != 0 { names.push("bridge"); }
    if flags & ACC_TRANSIENT != 0 { names.push("transient"); }
    if flags & ACC_VARARGS != 0 { names.push("varargs"); }
    if flags & ACC_NATIVE != 0 { names.push("native"); }
    if flags & ACC_INTERFACE != 0 { names.push("interface"); }
    if flags & ACC_ABSTRACT != 0 { names.push("abstract"); }
    if flags & ACC_STRICT != 0 { names.push("strict"); }
    if flags & ACC_SYNTHETIC != 0 { names.push("synthetic"); }
    if flags & ACC_ANNOTATION != 0 { names.push("annotation"); }
    if flags & ACC_ENUM != 0 { names.push("enum"); }
    if flags & ACC_CONSTRUCTOR != 0 { names.push("constructor"); }
    if flags & ACC_DECLARED_SYNCHRONIZED != 0 { names.push("declared_synchronized"); }
    names
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Encoded Value Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const VALUE_BYTE: u8 = 0x00;
pub const VALUE_SHORT: u8 = 0x02;
pub const VALUE_CHAR: u8 = 0x03;
pub const VALUE_INT: u8 = 0x04;
pub const VALUE_LONG: u8 = 0x06;
pub const VALUE_FLOAT: u8 = 0x10;
pub const VALUE_DOUBLE: u8 = 0x11;
pub const VALUE_METHOD_TYPE: u8 = 0x15;
pub const VALUE_METHOD_HANDLE: u8 = 0x16;
pub const VALUE_STRING: u8 = 0x17;
pub const VALUE_TYPE: u8 = 0x18;
pub const VALUE_FIELD: u8 = 0x19;
pub const VALUE_METHOD: u8 = 0x1a;
pub const VALUE_ENUM: u8 = 0x1b;
pub const VALUE_ARRAY: u8 = 0x1c;
pub const VALUE_ANNOTATION: u8 = 0x1d;
pub const VALUE_NULL: u8 = 0x1e;
pub const VALUE_BOOLEAN: u8 = 0x1f;

/// Return a human-readable name for an encoded value type.
pub fn value_type_name(vt: u8) -> &'static str {
    match vt {
        VALUE_BYTE => "byte",
        VALUE_SHORT => "short",
        VALUE_CHAR => "char",
        VALUE_INT => "int",
        VALUE_LONG => "long",
        VALUE_FLOAT => "float",
        VALUE_DOUBLE => "double",
        VALUE_METHOD_TYPE => "method_type",
        VALUE_METHOD_HANDLE => "method_handle",
        VALUE_STRING => "string",
        VALUE_TYPE => "type",
        VALUE_FIELD => "field",
        VALUE_METHOD => "method",
        VALUE_ENUM => "enum",
        VALUE_ARRAY => "array",
        VALUE_ANNOTATION => "annotation",
        VALUE_NULL => "null",
        VALUE_BOOLEAN => "boolean",
        _ => "unknown",
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Visibility Values (for annotations)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const VISIBILITY_BUILD: u8 = 0x00;
pub const VISIBILITY_RUNTIME: u8 = 0x01;
pub const VISIBILITY_SYSTEM: u8 = 0x02;

pub fn visibility_name(v: u8) -> &'static str {
    match v {
        VISIBILITY_BUILD => "build",
        VISIBILITY_RUNTIME => "runtime",
        VISIBILITY_SYSTEM => "system",
        _ => "unknown",
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Debug Info Opcodes
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const DBG_END_SEQUENCE: u8 = 0x00;
pub const DBG_ADVANCE_PC: u8 = 0x01;
pub const DBG_ADVANCE_LINE: u8 = 0x02;
pub const DBG_START_LOCAL: u8 = 0x03;
pub const DBG_START_LOCAL_EXTENDED: u8 = 0x04;
pub const DBG_END_LOCAL: u8 = 0x05;
pub const DBG_RESTART_LOCAL: u8 = 0x06;
pub const DBG_SET_PROLOGUE_END: u8 = 0x07;
pub const DBG_SET_EPILOGUE_BEGIN: u8 = 0x08;
pub const DBG_SET_FILE: u8 = 0x09;
pub const DBG_FIRST_SPECIAL: u8 = 0x0a;

pub fn dbg_opcode_name(op: u8) -> &'static str {
    match op {
        DBG_END_SEQUENCE => "DBG_END_SEQUENCE",
        DBG_ADVANCE_PC => "DBG_ADVANCE_PC",
        DBG_ADVANCE_LINE => "DBG_ADVANCE_LINE",
        DBG_START_LOCAL => "DBG_START_LOCAL",
        DBG_START_LOCAL_EXTENDED => "DBG_START_LOCAL_EXTENDED",
        DBG_END_LOCAL => "DBG_END_LOCAL",
        DBG_RESTART_LOCAL => "DBG_RESTART_LOCAL",
        DBG_SET_PROLOGUE_END => "DBG_SET_PROLOGUE_END",
        DBG_SET_EPILOGUE_BEGIN => "DBG_SET_EPILOGUE_BEGIN",
        DBG_SET_FILE => "DBG_SET_FILE",
        _ => {
            if op >= DBG_FIRST_SPECIAL { "DBG_SPECIAL" }
            else { "DBG_UNKNOWN" }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Map Item Type Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const TYPE_HEADER_ITEM: u16 = 0x0000;
pub const TYPE_STRING_ID_ITEM: u16 = 0x0001;
pub const TYPE_TYPE_ID_ITEM: u16 = 0x0002;
pub const TYPE_PROTO_ID_ITEM: u16 = 0x0003;
pub const TYPE_FIELD_ID_ITEM: u16 = 0x0004;
pub const TYPE_METHOD_ID_ITEM: u16 = 0x0005;
pub const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
pub const TYPE_CALL_SITE_ID_ITEM: u16 = 0x0007;
pub const TYPE_METHOD_HANDLE_ITEM: u16 = 0x0008;
pub const TYPE_MAP_LIST: u16 = 0x1000;
pub const TYPE_TYPE_LIST: u16 = 0x1001;
pub const TYPE_ANNOTATION_SET_REF_LIST: u16 = 0x1002;
pub const TYPE_ANNOTATION_SET_ITEM: u16 = 0x1003;
pub const TYPE_CLASS_DATA_ITEM: u16 = 0x2000;
pub const TYPE_CODE_ITEM: u16 = 0x2001;
pub const TYPE_STRING_DATA_ITEM: u16 = 0x2002;
pub const TYPE_DEBUG_INFO_ITEM: u16 = 0x2003;
pub const TYPE_ANNOTATION_ITEM: u16 = 0x2004;
pub const TYPE_ENCODED_ARRAY_ITEM: u16 = 0x2005;
pub const TYPE_ANNOTATIONS_DIRECTORY_ITEM: u16 = 0x2006;
pub const TYPE_HIDDENAPI_CLASS_DATA_ITEM: u16 = 0xF000;

pub fn map_type_name(t: u16) -> &'static str {
    match t {
        TYPE_HEADER_ITEM => "HEADER_ITEM",
        TYPE_STRING_ID_ITEM => "STRING_ID_ITEM",
        TYPE_TYPE_ID_ITEM => "TYPE_ID_ITEM",
        TYPE_PROTO_ID_ITEM => "PROTO_ID_ITEM",
        TYPE_FIELD_ID_ITEM => "FIELD_ID_ITEM",
        TYPE_METHOD_ID_ITEM => "METHOD_ID_ITEM",
        TYPE_CLASS_DEF_ITEM => "CLASS_DEF_ITEM",
        TYPE_CALL_SITE_ID_ITEM => "CALL_SITE_ID_ITEM",
        TYPE_METHOD_HANDLE_ITEM => "METHOD_HANDLE_ITEM",
        TYPE_MAP_LIST => "MAP_LIST",
        TYPE_TYPE_LIST => "TYPE_LIST",
        TYPE_ANNOTATION_SET_REF_LIST => "ANNOTATION_SET_REF_LIST",
        TYPE_ANNOTATION_SET_ITEM => "ANNOTATION_SET_ITEM",
        TYPE_CLASS_DATA_ITEM => "CLASS_DATA_ITEM",
        TYPE_CODE_ITEM => "CODE_ITEM",
        TYPE_STRING_DATA_ITEM => "STRING_DATA_ITEM",
        TYPE_DEBUG_INFO_ITEM => "DEBUG_INFO_ITEM",
        TYPE_ANNOTATION_ITEM => "ANNOTATION_ITEM",
        TYPE_ENCODED_ARRAY_ITEM => "ENCODED_ARRAY_ITEM",
        TYPE_ANNOTATIONS_DIRECTORY_ITEM => "ANNOTATIONS_DIRECTORY_ITEM",
        TYPE_HIDDENAPI_CLASS_DATA_ITEM => "HIDDENAPI_CLASS_DATA_ITEM",
        _ => "UNKNOWN",
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Error Type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Errors that can occur during DEX parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexError {
    /// Invalid or missing DEX magic bytes.
    InvalidMagic,
    /// The file does not match the expected endianness.
    InvalidEndianTag,
    /// Data is truncated/too short.
    TruncatedData,
    /// Too many entries in a table (probable corruption or DoS attack).
    TooManyEntries,
    /// Invalid string data (bad MUTF-8 or varint length).
    InvalidString,
    /// Invalid encoded value type.
    InvalidValueType,
    /// Invalid ULEB128 or SLEB128 encoding.
    InvalidLeb128,
    /// A nom parse error occurred.
    NomError(String),
}

impl fmt::Display for DexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DexError::InvalidMagic => write!(f, "Invalid DEX magic bytes"),
            DexError::InvalidEndianTag => write!(f, "Invalid DEX endian tag"),
            DexError::TruncatedData => write!(f, "Truncated DEX data"),
            DexError::TooManyEntries => write!(f, "Too many entries in DEX table"),
            DexError::InvalidString => write!(f, "Invalid MUTF-8 string in DEX"),
            DexError::InvalidValueType => write!(f, "Invalid encoded value type"),
            DexError::InvalidLeb128 => write!(f, "Invalid LEB128 encoding"),
            DexError::NomError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for DexError {}

impl From<nom::Err<nom::error::Error<&[u8]>>> for DexError {
    fn from(e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        DexError::NomError(format!("{:?}", e))
    }
}

/// Type alias for DEX parse results.
pub type DexResult<T> = Result<T, DexError>;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// LEB128 Nom Combinators
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Nom parser for unsigned LEB128 values.
pub fn nom_uleb128(input: &[u8]) -> IResult<&[u8], u64> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in input.iter().enumerate() {
        if i >= 10 {
            return Err(nom::Err::Error(Error::new(input, ErrorKind::TooLarge)));
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((&input[i + 1..], result));
        }
        shift += 7;
    }
    Err(nom::Err::Error(Error::new(input, ErrorKind::TooLarge)))
}

/// Nom parser for signed LEB128 values.
pub fn nom_sleb128(input: &[u8]) -> IResult<&[u8], i64> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut last_byte: u8 = 0;
    for (i, &byte) in input.iter().enumerate() {
        if i >= 10 {
            return Err(nom::Err::Error(Error::new(input, ErrorKind::TooLarge)));
        }
        last_byte = byte;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            // Sign-extend if negative
            if shift < 64 && (byte & 0x40) != 0 {
                result |= -(1i64 << shift);
            }
            return Ok((&input[i + 1..], result));
        }
    }
    // Sign-extend truncated value
    if shift < 64 && (last_byte & 0x40) != 0 {
        result |= -(1i64 << shift);
    }
    Err(nom::Err::Error(Error::new(input, ErrorKind::TooLarge)))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// LEB128 Decode Helpers (non-nom, standalone)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Decode an unsigned LEB128 value from a byte slice.
/// Returns the decoded value and the number of bytes consumed.
pub fn decode_uleb128(data: &[u8]) -> DexResult<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(DexError::InvalidLeb128);
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(DexError::InvalidLeb128)
}

/// Decode a signed LEB128 value from a byte slice.
pub fn decode_sleb128(data: &[u8]) -> DexResult<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut byte: u8 = 0;
    let mut i = 0;
    for &b in data.iter() {
        if i >= 10 {
            return Err(DexError::InvalidLeb128);
        }
        byte = b;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    // Sign-extend if the high bit of the last byte is set
    if shift < 64 && (byte & 0x40) != 0 {
        result |= -(1i64 << shift);
    }
    Ok((result, i))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// MUTF-8 Decoding
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Decode a MUTF-8 (Modified UTF-8) string with a ULEB128-prefixed length.
/// Handles null bytes encoded as two-byte sequences (0xC0 0x80).
pub fn decode_mutf8(data: &[u8]) -> DexResult<(String, usize)> {
    let (ulen, len_bytes) = decode_uleb128(data)?;
    let len = ulen as usize;
    let mut offset = len_bytes;
    // Read len bytes of MUTF-8 data
    if offset + len > data.len() {
        return Err(DexError::TruncatedData);
    }
    let mut result = Vec::with_capacity(len);
    let raw = &data[offset..offset + len];
    let mut i = 0;
    while i < raw.len() {
        let byte = raw[i];
        if byte == 0xC0 && i + 1 < raw.len() && raw[i + 1] == 0x80 {
            // MUTF-8 encoded null character
            result.push(0);
            i += 2;
        } else if byte < 0x80 {
            result.push(byte);
            i += 1;
        } else if byte < 0xE0 {
            if i + 1 >= raw.len() {
                return Err(DexError::InvalidString);
            }
            result.push(byte);
            result.push(raw[i + 1]);
            i += 2;
        } else {
            if i + 2 >= raw.len() {
                return Err(DexError::InvalidString);
            }
            result.push(byte);
            result.push(raw[i + 1]);
            result.push(raw[i + 2]);
            i += 3;
        }
    }
    offset += len;
    let s = String::from_utf8(result).map_err(|_| DexError::InvalidString)?;
    Ok((s, offset))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Data Structures
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// The parsed DEX file with all contents.
#[derive(Debug, Clone)]
pub struct DexFile {
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub type_ids: Vec<u32>,
    pub proto_ids: Vec<ProtoId>,
    pub field_ids: Vec<FieldId>,
    pub method_ids: Vec<MethodId>,
    pub class_defs: Vec<ClassDef>,
    pub map_list: Option<MapList>,
}

impl DexFile {
    /// Look up a string by its index in the string table.
    pub fn string(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(|s| s.as_str())
    }

    /// Look up a type descriptor by its index.
    pub fn type_descriptor(&self, idx: u32) -> Option<&str> {
        let string_idx = self.type_ids.get(idx as usize)?;
        self.string(*string_idx)
    }

    /// Resolve a field name from a FieldId index.
    pub fn field_name(&self, idx: u32) -> Option<&str> {
        let field = self.field_ids.get(idx as usize)?;
        self.string(field.name_idx)
    }

    /// Resolve a method name from a MethodId index.
    pub fn method_name(&self, idx: u32) -> Option<&str> {
        let method = self.method_ids.get(idx as usize)?;
        self.string(method.name_idx)
    }

    /// Return all class names found in the DEX file.
    pub fn class_names(&self) -> Vec<Option<&str>> {
        self.class_defs.iter().map(|cd| self.type_descriptor(cd.class_idx)).collect()
    }
}

/// DEX file header (always 0x70 = 112 bytes).
#[derive(Debug, Clone)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

/// Proto ID: references the shorty descriptor, return type, and parameter list.
#[derive(Debug, Clone)]
pub struct ProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
    pub parameters: Vec<u16>,
}

/// Field ID: identifies a field by class, type, and name.
#[derive(Debug, Clone)]
pub struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

/// Method ID: identifies a method by class, proto, and name.
#[derive(Debug, Clone)]
pub struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

/// Class definition: high-level description of a class.
#[derive(Debug, Clone)]
pub struct ClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub interfaces: Vec<u16>,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
    pub class_data: Option<ClassData>,
    pub annotations: Vec<AnnotationItem>,
    pub static_values: Option<EncodedArray>,
}

/// Class data: the actual field and method definitions within a class.
#[derive(Debug, Clone)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

/// Encoded field: a field within class data, with access flags.
#[derive(Debug, Clone)]
pub struct EncodedField {
    pub field_idx_diff: u64,
    pub access_flags: u64,
}

/// Encoded method: a method within class data, with access flags and code.
#[derive(Debug, Clone)]
pub struct EncodedMethod {
    pub method_idx_diff: u64,
    pub access_flags: u64,
    pub code_off: u64,
    pub code: Option<CodeItem>,
}

/// Code item: the bytecode body of a method.
#[derive(Debug, Clone)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub instructions: Vec<u16>,
    pub tries: Vec<TryItem>,
    pub handlers: Vec<EncodedCatchHandler>,
    pub debug_info: Option<DebugInfo>,
}

/// Try/catch block record.
#[derive(Debug, Clone)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

/// Encoded catch handler.
#[derive(Debug, Clone)]
pub struct EncodedCatchHandler {
    pub size: i64,
    pub handlers: Vec<EncodedTypeAddrPair>,
    pub catch_all_addr: Option<u64>,
}

/// Type-address pair in a catch handler.
#[derive(Debug, Clone)]
pub struct EncodedTypeAddrPair {
    pub type_idx: u64,
    pub addr: u64,
}

/// Debug info for a method.
#[derive(Debug, Clone)]
pub struct DebugInfo {
    pub line_start: u64,
    pub parameter_names: Vec<Option<String>>,
    pub debug_entries: Vec<DebugEntry>,
}

/// A debug info entry (opcode and optional data).
#[derive(Debug, Clone)]
pub struct DebugEntry {
    pub opcode: u8,
    pub data: Option<i64>,
    pub name: Option<String>,
    pub type_idx: Option<u64>,
    pub sig: Option<String>,
}

/// Encoded value (used in annotations, static values, etc.).
#[derive(Debug, Clone)]
pub enum EncodedValue {
    Byte(u8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    MethodType(u32),
    MethodHandle(u32),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array(EncodedArray),
    Annotation(DexAnnotation),
    Null,
    Boolean(bool),
}

/// An array of encoded values.
#[derive(Debug, Clone)]
pub struct EncodedArray {
    pub values: Vec<EncodedValue>,
}

/// An annotation (used in class, field, method annotations).
#[derive(Debug, Clone)]
pub struct DexAnnotation {
    pub type_idx: u64,
    pub elements: Vec<AnnotationElement>,
}

/// An annotation element (name-value pair).
#[derive(Debug, Clone)]
pub struct AnnotationElement {
    pub name_idx: u64,
    pub value: EncodedValue,
}

/// An annotation item with its visibility.
#[derive(Debug, Clone)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: DexAnnotation,
}

/// Map list entry: describes a section in the DEX file.
#[derive(Debug, Clone)]
pub struct MapItem {
    pub type_: u16,
    pub unused: u16,
    pub size: u32,
    pub offset: u32,
}

/// Map list: the root section list for validation.
#[derive(Debug, Clone)]
pub struct MapList {
    pub items: Vec<MapItem>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Header
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Parse the DEX header using nom combinators.
fn parse_dex_header(input: &[u8]) -> IResult<&[u8], DexHeader> {
    let (input, magic) = take(8usize)(input)?;
    let (input, checksum) = le_u32(input)?;
    let (input, signature) = take(20usize)(input)?;
    let (input, file_size) = le_u32(input)?;
    let (input, header_size) = le_u32(input)?;
    let (input, endian_tag) = le_u32(input)?;
    let (input, link_size) = le_u32(input)?;
    let (input, link_off) = le_u32(input)?;
    let (input, map_off) = le_u32(input)?;
    let (input, string_ids_size) = le_u32(input)?;
    let (input, string_ids_off) = le_u32(input)?;
    let (input, type_ids_size) = le_u32(input)?;
    let (input, type_ids_off) = le_u32(input)?;
    let (input, proto_ids_size) = le_u32(input)?;
    let (input, proto_ids_off) = le_u32(input)?;
    let (input, field_ids_size) = le_u32(input)?;
    let (input, field_ids_off) = le_u32(input)?;
    let (input, method_ids_size) = le_u32(input)?;
    let (input, method_ids_off) = le_u32(input)?;
    let (input, class_defs_size) = le_u32(input)?;
    let (input, class_defs_off) = le_u32(input)?;
    let (input, data_size) = le_u32(input)?;
    let (input, data_off) = le_u32(input)?;

    let mut magic_arr = [0u8; 8];
    magic_arr.copy_from_slice(magic);
    let mut sig = [0u8; 20];
    sig.copy_from_slice(signature);

    Ok((input, DexHeader {
        magic: magic_arr, checksum, signature: sig,
        file_size, header_size, endian_tag,
        link_size, link_off, map_off,
        string_ids_size, string_ids_off,
        type_ids_size, type_ids_off,
        proto_ids_size, proto_ids_off,
        field_ids_size, field_ids_off,
        method_ids_size, method_ids_off,
        class_defs_size, class_defs_off,
        data_size, data_off,
    }))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: String Table
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_strings(data: &[u8], header: &DexHeader) -> DexResult<Vec<String>> {
    if header.string_ids_size == 0 || header.string_ids_size > MAX_TABLE_ENTRIES {
        return Ok(Vec::new());
    }
    let count = header.string_ids_size as usize;
    let mut strings = Vec::with_capacity(count);
    for i in 0..count {
        let off_offset = header.string_ids_off as usize + i * 4;
        if off_offset + 4 > data.len() {
            return Err(DexError::TruncatedData);
        }
        let str_off =
            u32::from_le_bytes([data[off_offset], data[off_offset + 1], data[off_offset + 2], data[off_offset + 3]])
                as usize;
        if str_off == 0 || str_off >= data.len() {
            strings.push(String::new());
            continue;
        }
        match decode_mutf8(&data[str_off..]) {
            Ok((s, _)) => strings.push(s),
            Err(_) => strings.push(String::new()),
        }
    }
    Ok(strings)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Type Table
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_type_ids(data: &[u8], header: &DexHeader) -> DexResult<Vec<u32>> {
    if header.type_ids_size == 0 || header.type_ids_size > MAX_TABLE_ENTRIES {
        return Ok(Vec::new());
    }
    let count = header.type_ids_size as usize;
    let mut types = Vec::with_capacity(count);
    for i in 0..count {
        let off = header.type_ids_off as usize + i * 4;
        if off + 4 > data.len() {
            return Err(DexError::TruncatedData);
        }
        types.push(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]));
    }
    Ok(types)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Proto Table
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_proto_ids(data: &[u8], header: &DexHeader) -> DexResult<Vec<ProtoId>> {
    if header.proto_ids_size == 0 || header.proto_ids_size > MAX_TABLE_ENTRIES {
        return Ok(Vec::new());
    }
    let count = header.proto_ids_size as usize;
    let mut protos = Vec::with_capacity(count);
    for i in 0..count {
        let base = header.proto_ids_off as usize + i * 12;
        if base + 12 > data.len() {
            return Err(DexError::TruncatedData);
        }
        let shorty_idx = u32::from_le_bytes([data[base], data[base + 1], data[base + 2], data[base + 3]]);
        let return_type_idx = u32::from_le_bytes([data[base + 4], data[base + 5], data[base + 6], data[base + 7]]);
        let parameters_off = u32::from_le_bytes([data[base + 8], data[base + 9], data[base + 10], data[base + 11]]);
        let parameters = if parameters_off != 0 {
            parse_type_list(data, parameters_off as usize)?
        } else {
            Vec::new()
        };
        protos.push(ProtoId { shorty_idx, return_type_idx, parameters_off, parameters });
    }
    Ok(protos)
}

/// Parse a type_list structure from the data section.
fn parse_type_list(data: &[u8], offset: usize) -> DexResult<Vec<u16>> {
    if offset + 4 > data.len() {
        return Err(DexError::TruncatedData);
    }
    let size = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
    if size > 65536 {
        return Err(DexError::TooManyEntries);
    }
    let mut list = Vec::with_capacity(size);
    for i in 0..size {
        let off = offset + 4 + i * 2;
        if off + 2 > data.len() {
            break;
        }
        list.push(u16::from_le_bytes([data[off], data[off + 1]]));
    }
    Ok(list)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Field Table
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_field_ids(data: &[u8], header: &DexHeader) -> DexResult<Vec<FieldId>> {
    if header.field_ids_size == 0 || header.field_ids_size > MAX_TABLE_ENTRIES {
        return Ok(Vec::new());
    }
    let count = header.field_ids_size as usize;
    let mut fields = Vec::with_capacity(count);
    for i in 0..count {
        let base = header.field_ids_off as usize + i * 8;
        if base + 8 > data.len() {
            return Err(DexError::TruncatedData);
        }
        let class_idx = u16::from_le_bytes([data[base], data[base + 1]]);
        let type_idx = u16::from_le_bytes([data[base + 2], data[base + 3]]);
        let name_idx = u32::from_le_bytes([data[base + 4], data[base + 5], data[base + 6], data[base + 7]]);
        fields.push(FieldId { class_idx, type_idx, name_idx });
    }
    Ok(fields)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Method Table
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_method_ids(data: &[u8], header: &DexHeader) -> DexResult<Vec<MethodId>> {
    if header.method_ids_size == 0 || header.method_ids_size > MAX_TABLE_ENTRIES {
        return Ok(Vec::new());
    }
    let count = header.method_ids_size as usize;
    let mut methods = Vec::with_capacity(count);
    for i in 0..count {
        let base = header.method_ids_off as usize + i * 8;
        if base + 8 > data.len() {
            return Err(DexError::TruncatedData);
        }
        let class_idx = u16::from_le_bytes([data[base], data[base + 1]]);
        let proto_idx = u16::from_le_bytes([data[base + 2], data[base + 3]]);
        let name_idx = u32::from_le_bytes([data[base + 4], data[base + 5], data[base + 6], data[base + 7]]);
        methods.push(MethodId { class_idx, proto_idx, name_idx });
    }
    Ok(methods)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Class Definitions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_class_defs(data: &[u8], header: &DexHeader) -> DexResult<Vec<ClassDef>> {
    if header.class_defs_size == 0 || header.class_defs_size > MAX_TABLE_ENTRIES {
        return Ok(Vec::new());
    }
    let count = header.class_defs_size as usize;
    let mut defs = Vec::with_capacity(count);
    for i in 0..count {
        let base = header.class_defs_off as usize + i * 32;
        if base + 32 > data.len() {
            return Err(DexError::TruncatedData);
        }
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };
        let class_idx = read_u32(base);
        let access_flags = read_u32(base + 4);
        let superclass_idx = read_u32(base + 8);
        let interfaces_off = read_u32(base + 12);
        let source_file_idx = read_u32(base + 16);
        let annotations_off = read_u32(base + 20);
        let class_data_off = read_u32(base + 24);
        let static_values_off = read_u32(base + 28);

        let interfaces = if interfaces_off != 0 {
            parse_type_list(data, interfaces_off as usize).unwrap_or_default()
        } else {
            Vec::new()
        };

        let class_data = if class_data_off != 0 {
            parse_class_data(data, class_data_off as usize).ok()
        } else {
            None
        };

        let annotations = if annotations_off != 0 {
            parse_annotations_directory(data, annotations_off as usize).unwrap_or_default()
        } else {
            Vec::new()
        };

        let static_values = if static_values_off != 0 {
            parse_encoded_array(data, static_values_off as usize).ok()
        } else {
            None
        };

        defs.push(ClassDef {
            class_idx, access_flags, superclass_idx, interfaces_off, interfaces,
            source_file_idx, annotations_off, class_data_off, static_values_off,
            class_data, annotations, static_values,
        });
    }
    Ok(defs)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Class Data
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_class_data(data: &[u8], offset: usize) -> DexResult<ClassData> {
    if offset >= data.len() {
        return Err(DexError::TruncatedData);
    }
    let rest = &data[offset..];
    let (rest, static_fields_size) = nom_uleb128(rest)
        .map_err(|_| DexError::InvalidLeb128)?;
    let (rest, instance_fields_size) = nom_uleb128(rest)
        .map_err(|_| DexError::InvalidLeb128)?;
    let (rest, direct_methods_size) = nom_uleb128(rest)
        .map_err(|_| DexError::InvalidLeb128)?;
    let (rest, virtual_methods_size) = nom_uleb128(rest)
        .map_err(|_| DexError::InvalidLeb128)?;

    let (rest, static_fields) =
        parse_encoded_fields(rest, static_fields_size as usize).map_err(|_| DexError::InvalidLeb128)?;
    let (rest, instance_fields) =
        parse_encoded_fields(rest, instance_fields_size as usize).map_err(|_| DexError::InvalidLeb128)?;
    let (rest, direct_methods) =
        parse_encoded_methods(rest, direct_methods_size as usize).map_err(|_| DexError::InvalidLeb128)?;
    let (_rest, virtual_methods) =
        parse_encoded_methods(rest, virtual_methods_size as usize).map_err(|_| DexError::InvalidLeb128)?;

    Ok(ClassData { static_fields, instance_fields, direct_methods, virtual_methods })
}

fn parse_encoded_fields(input: &[u8], count: usize) -> IResult<&[u8], Vec<EncodedField>> {
    let mut rest = input;
    let mut fields = Vec::with_capacity(count);
    let mut prev_idx: u64 = 0;
    for _ in 0..count {
        let (r, idx_diff) = nom_uleb128(rest)?;
        let (r, access_flags) = nom_uleb128(r)?;
        prev_idx += idx_diff;
        fields.push(EncodedField { field_idx_diff: prev_idx, access_flags });
        rest = r;
    }
    Ok((rest, fields))
}

fn parse_encoded_methods(input: &[u8], count: usize) -> IResult<&[u8], Vec<EncodedMethod>> {
    let mut rest = input;
    let mut methods = Vec::with_capacity(count);
    let mut prev_idx: u64 = 0;
    for _ in 0..count {
        let (r, idx_diff) = nom_uleb128(rest)?;
        let (r, access_flags) = nom_uleb128(r)?;
        let (r, code_off) = nom_uleb128(r)?;
        prev_idx += idx_diff;
        methods.push(EncodedMethod {
            method_idx_diff: prev_idx,
            access_flags,
            code_off,
            code: None,
        });
        rest = r;
    }
    Ok((rest, methods))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Code Item
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_code_item(data: &[u8], offset: usize) -> DexResult<CodeItem> {
    if offset == 0 || offset + 16 > data.len() {
        return Err(DexError::TruncatedData);
    }
    let read_u16 = |off: usize| -> u16 {
        u16::from_le_bytes([data[off], data[off + 1]])
    };
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    };

    let registers_size = read_u16(offset);
    let ins_size = read_u16(offset + 2);
    let outs_size = read_u16(offset + 4);
    let tries_size = read_u16(offset + 6);
    let debug_info_off = read_u32(offset + 8);
    let insns_size = read_u32(offset + 12);

    let mut pos = offset + 16;
    let insns_end = pos + (insns_size as usize) * 2;
    if insns_end > data.len() {
        return Err(DexError::TruncatedData);
    }
    let mut instructions = Vec::with_capacity(insns_size as usize);
    for i in 0..insns_size as usize {
        instructions.push(read_u16(pos + i * 2));
    }
    pos = insns_end;

    let mut tries = Vec::new();
    let mut handlers = Vec::new();
    if tries_size > 0 {
        // Align pos to 4 bytes
        while pos % 4 != 0 {
            pos += 1;
        }
        // Parse tries
        for _ in 0..tries_size {
            if pos + 8 > data.len() {
                break;
            }
            let start_addr = read_u32(pos);
            let insn_count = read_u16(pos + 4);
            let handler_off = read_u16(pos + 6);
            tries.push(TryItem { start_addr, insn_count, handler_off });
            pos += 8;
        }
        // Parse handlers
        if pos < data.len() {
            if let Ok((_, h)) = parse_encoded_catch_handler_list(&data[pos..]) {
                handlers = h;
            }
        }
    }

    let debug_info = if debug_info_off != 0 {
        parse_debug_info(data, debug_info_off as usize).ok()
    } else {
        None
    };

    Ok(CodeItem {
        registers_size, ins_size, outs_size, tries_size,
        debug_info_off, insns_size, instructions, tries, handlers, debug_info,
    })
}

fn parse_encoded_catch_handler_list(input: &[u8]) -> IResult<&[u8], Vec<EncodedCatchHandler>> {
    let (input, size) = nom_uleb128(input)?;
    let count = size as usize;
    let mut rest = input;
    let mut handlers = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let (r, signed_size) = nom_sleb128(rest)?;
        let abs_size = signed_size.unsigned_abs();
        let has_catch_all = signed_size <= 0;
        let mut pairs = Vec::with_capacity((abs_size as usize).min(256));
        rest = r;
        for _ in 0..abs_size {
            let (r2, type_idx) = nom_uleb128(rest)?;
            let (r2, addr) = nom_uleb128(r2)?;
            pairs.push(EncodedTypeAddrPair { type_idx, addr });
            rest = r2;
        }
        let catch_all_addr = if has_catch_all {
            let (r3, addr) = nom_uleb128(rest)?;
            rest = r3;
            Some(addr)
        } else {
            None
        };
        handlers.push(EncodedCatchHandler {
            size: signed_size,
            handlers: pairs,
            catch_all_addr,
        });
    }
    Ok((rest, handlers))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Debug Info
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_debug_info(data: &[u8], offset: usize) -> DexResult<DebugInfo> {
    if offset >= data.len() {
        return Err(DexError::TruncatedData);
    }
    let rest = &data[offset..];

    let (rest, line_start) =
        nom_uleb128(rest).map_err(|_| DexError::InvalidLeb128)?;
    let (rest, parameter_count) =
        nom_uleb128(rest).map_err(|_| DexError::InvalidLeb128)?;

    let mut parameter_names = Vec::new();
    let mut r = rest;
    for _ in 0..parameter_count {
        let (r2, name_idx) =
            nom_uleb128(r).map_err(|_| DexError::InvalidLeb128)?;
        let name = if name_idx == u64::MAX || (name_idx as u32) == 0xFFFFFFFF {
            None
        } else {
            Some(format!("<idx:{}>", name_idx))
        };
        parameter_names.push(name);
        r = r2;
    }

    let mut debug_entries = Vec::new();
    loop {
        if r.is_empty() {
            break;
        }
        let (r2, opcode_byte) = le_u8(r).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| DexError::InvalidLeb128)?;
        let opcode = opcode_byte;
        r = r2;

        if opcode == DBG_END_SEQUENCE {
            debug_entries.push(DebugEntry { opcode, data: None, name: None, type_idx: None, sig: None });
            break;
        }

        let entry = match opcode {
            DBG_ADVANCE_PC => {
                let (r3, val) = nom_uleb128(r).map_err(|_| DexError::InvalidLeb128)?;
                r = r3;
                DebugEntry { opcode, data: Some(val as i64), name: None, type_idx: None, sig: None }
            }
            DBG_ADVANCE_LINE => {
                let (r3, val) = nom_sleb128(r).map_err(|_| DexError::InvalidLeb128)?;
                r = r3;
                DebugEntry { opcode, data: Some(val), name: None, type_idx: None, sig: None }
            }
            DBG_START_LOCAL => {
                let (r3, reg) = nom_uleb128(r).map_err(|_| DexError::InvalidLeb128)?;
                let (r3, name_idx) = nom_uleb128(r3).map_err(|_| DexError::InvalidLeb128)?;
                let (r3, type_idx) = nom_uleb128(r3).map_err(|_| DexError::InvalidLeb128)?;
                r = r3;
                DebugEntry {
                    opcode, data: Some(reg as i64),
                    name: Some(format!("<name:{}>", name_idx)),
                    type_idx: Some(type_idx), sig: None,
                }
            }
            DBG_START_LOCAL_EXTENDED => {
                let (r3, reg) = nom_uleb128(r).map_err(|_| DexError::InvalidLeb128)?;
                let (r3, name_idx) = nom_uleb128(r3).map_err(|_| DexError::InvalidLeb128)?;
                let (r3, type_idx) = nom_uleb128(r3).map_err(|_| DexError::InvalidLeb128)?;
                let (r3, sig_idx) = nom_uleb128(r3).map_err(|_| DexError::InvalidLeb128)?;
                r = r3;
                DebugEntry {
                    opcode, data: Some(reg as i64),
                    name: Some(format!("<name:{}>", name_idx)),
                    type_idx: Some(type_idx),
                    sig: Some(format!("<sig:{}>", sig_idx)),
                }
            }
            DBG_END_LOCAL | DBG_RESTART_LOCAL => {
                let (r3, reg) = nom_uleb128(r).map_err(|_| DexError::InvalidLeb128)?;
                r = r3;
                DebugEntry { opcode, data: Some(reg as i64), name: None, type_idx: None, sig: None }
            }
            DBG_SET_PROLOGUE_END | DBG_SET_EPILOGUE_BEGIN => {
                DebugEntry { opcode, data: None, name: None, type_idx: None, sig: None }
            }
            DBG_SET_FILE => {
                let (r3, file_idx) = nom_uleb128(r).map_err(|_| DexError::InvalidLeb128)?;
                r = r3;
                DebugEntry { opcode, data: Some(file_idx as i64), name: None, type_idx: None, sig: None }
            }
            _ => {
                // Special opcode: adjust line and address
                let adjusted = opcode.saturating_sub(DBG_FIRST_SPECIAL);
                DebugEntry { opcode, data: Some(adjusted as i64), name: None, type_idx: None, sig: None }
            }
        };
        debug_entries.push(entry);
    }

    Ok(DebugInfo { line_start, parameter_names, debug_entries })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Encoded Values & Arrays
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_encoded_value(input: &[u8]) -> IResult<&[u8], EncodedValue> {
    let (rest, header) = le_u8(input)?;
    let value_type = header & 0x1f;
    let value_arg = (header >> 5) as usize;

    // Read the argument bytes
    let (rest, arg_bytes) = take(value_arg)(rest)?;
    let mut arg_val: u64 = 0;
    for (i, &b) in arg_bytes.iter().enumerate() {
        arg_val |= (b as u64) << (i * 8);
    }

    match value_type {
        VALUE_BYTE => Ok((rest, EncodedValue::Byte(arg_val as u8))),
        VALUE_SHORT => {
            let val = sign_extend_short(arg_val, value_arg);
            Ok((rest, EncodedValue::Short(val)))
        }
        VALUE_CHAR => Ok((rest, EncodedValue::Char(arg_val as u16))),
        VALUE_INT => {
            let val = sign_extend_int(arg_val as u32, value_arg) as i32;
            Ok((rest, EncodedValue::Int(val)))
        }
        VALUE_LONG => {
            let val = sign_extend_long(arg_val, value_arg);
            Ok((rest, EncodedValue::Long(val)))
        }
        VALUE_FLOAT => {
            let val = if value_arg == 0 { 0.0f32 }
            else { f32::from_bits((arg_val as u32) << (32 - value_arg * 8)) };
            Ok((rest, EncodedValue::Float(val)))
        }
        VALUE_DOUBLE => {
            let val = if value_arg == 0 { 0.0f64 }
            else { f64::from_bits(arg_val << (64 - value_arg * 8)) };
            Ok((rest, EncodedValue::Double(val)))
        }
        VALUE_METHOD_TYPE => Ok((rest, EncodedValue::MethodType(arg_val as u32))),
        VALUE_METHOD_HANDLE => Ok((rest, EncodedValue::MethodHandle(arg_val as u32))),
        VALUE_STRING => Ok((rest, EncodedValue::String(arg_val as u32))),
        VALUE_TYPE => Ok((rest, EncodedValue::Type(arg_val as u32))),
        VALUE_FIELD => Ok((rest, EncodedValue::Field(arg_val as u32))),
        VALUE_METHOD => Ok((rest, EncodedValue::Method(arg_val as u32))),
        VALUE_ENUM => Ok((rest, EncodedValue::Enum(arg_val as u32))),
        VALUE_ARRAY => {
            let (rest2, arr) = parse_encoded_array_nom(rest)?;
            Ok((rest2, EncodedValue::Array(arr)))
        }
        VALUE_ANNOTATION => {
            let (rest2, ann) = parse_annotation(rest)?;
            Ok((rest2, EncodedValue::Annotation(ann)))
        }
        VALUE_NULL => Ok((rest, EncodedValue::Null)),
        VALUE_BOOLEAN => Ok((rest, EncodedValue::Boolean(arg_val != 0))),
        _ => Err(nom::Err::Error(Error::new(input, ErrorKind::Tag))),
    }
}

fn sign_extend_short(val: u64, arg_size: usize) -> i16 {
    if arg_size == 0 { return 0; }
    let bits = 8 * arg_size;
    if bits >= 16 { return val as i16; }
    let shifted = (val as i16) << (16 - bits);
    shifted >> (16 - bits)
}

fn sign_extend_int(val: u32, arg_size: usize) -> i32 {
    match arg_size {
        0 => 0,
        1 => ((val as i32) << 24) >> 24,
        2 => ((val as i32) << 16) >> 16,
        3 => ((val as i32) << 8) >> 8,
        _ => val as i32,
    }
}

fn sign_extend_long(val: u64, arg_size: usize) -> i64 {
    if arg_size == 0 { return 0; }
    let bits = (8 * arg_size) as u32;
    if bits >= 64 { return val as i64; }
    let shifted = (val as i64) << (64 - bits);
    shifted >> (64 - bits)
}

fn parse_encoded_array(data: &[u8], offset: usize) -> DexResult<EncodedArray> {
    if offset >= data.len() {
        return Err(DexError::TruncatedData);
    }
    let rest = &data[offset..];
    let (_rest, array) = parse_encoded_array_nom(rest).map_err(|_| DexError::InvalidValueType)?;
    Ok(array)
}

fn parse_encoded_array_nom(input: &[u8]) -> IResult<&[u8], EncodedArray> {
    let (input, size) = nom_uleb128(input)?;
    let mut rest = input;
    let mut values = Vec::with_capacity((size as usize).min(4096));
    for _ in 0..size {
        let (r, val) = parse_encoded_value(rest)?;
        values.push(val);
        rest = r;
    }
    Ok((rest, EncodedArray { values }))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Annotations
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_annotation(input: &[u8]) -> IResult<&[u8], DexAnnotation> {
    let (input, type_idx) = nom_uleb128(input)?;
    let (input, size) = nom_uleb128(input)?;
    let mut rest = input;
    let mut elements = Vec::with_capacity((size as usize).min(1024));
    for _ in 0..size {
        let (r, name_idx) = nom_uleb128(rest)?;
        let (r, value) = parse_encoded_value(r)?;
        elements.push(AnnotationElement { name_idx, value });
        rest = r;
    }
    Ok((rest, DexAnnotation { type_idx, elements }))
}

/// Parse an annotations directory at the given offset.
fn parse_annotations_directory(data: &[u8], offset: usize) -> DexResult<Vec<AnnotationItem>> {
    if offset + 16 > data.len() {
        return Ok(Vec::new());
    }
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    };

    let mut items = Vec::new();
    let class_ann_off = read_u32(offset);
    let fields_size = read_u32(offset + 4);
    let methods_size = read_u32(offset + 8);
    let params_size = read_u32(offset + 12);

    // Class annotations
    if class_ann_off != 0 {
        if let Ok(anns) = parse_annotation_set_items(data, class_ann_off as usize) {
            items.extend(anns);
        }
    }

    // Field annotations
    let mut pos = offset + 16;
    for _ in 0..fields_size {
        if pos + 8 > data.len() { break; }
        let _field_idx = read_u32(pos);
        let field_ann_off = read_u32(pos + 4);
        pos += 8;
        if field_ann_off != 0 {
            if let Ok(anns) = parse_annotation_set_items(data, field_ann_off as usize) {
                items.extend(anns);
            }
        }
    }

    // Method annotations
    for _ in 0..methods_size {
        if pos + 8 > data.len() { break; }
        let _method_idx = read_u32(pos);
        let method_ann_off = read_u32(pos + 4);
        pos += 8;
        if method_ann_off != 0 {
            if let Ok(anns) = parse_annotation_set_items(data, method_ann_off as usize) {
                items.extend(anns);
            }
        }
    }

    // Parameter annotations
    for _ in 0..params_size {
        if pos + 8 > data.len() { break; }
        let _method_idx = read_u32(pos);
        let param_ann_off = read_u32(pos + 4);
        pos += 8;
        if param_ann_off != 0 {
            if let Ok(anns) = parse_annotation_set_ref_items(data, param_ann_off as usize) {
                items.extend(anns);
            }
        }
    }

    Ok(items)
}

fn parse_annotation_set_items(data: &[u8], offset: usize) -> DexResult<Vec<AnnotationItem>> {
    if offset + 4 > data.len() {
        return Ok(Vec::new());
    }
    let size = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
    if size > 65536 { return Ok(Vec::new()); }
    let mut items = Vec::with_capacity(size);
    for i in 0..size {
        let off = offset + 4 + i * 4;
        if off + 4 > data.len() { break; }
        let annotation_off = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if annotation_off != 0 {
            if let Ok(ai) = parse_annotation_item(data, annotation_off as usize) {
                items.push(ai);
            }
        }
    }
    Ok(items)
}

fn parse_annotation_set_ref_items(data: &[u8], offset: usize) -> DexResult<Vec<AnnotationItem>> {
    if offset + 4 > data.len() {
        return Ok(Vec::new());
    }
    let size = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
    if size > 65536 { return Ok(Vec::new()); }
    let mut items = Vec::new();
    for i in 0..size {
        let off = offset + 4 + i * 4;
        if off + 4 > data.len() { break; }
        let set_ref_off = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if set_ref_off != 0 {
            let sub_size = if set_ref_off as usize + 4 <= data.len() {
                u32::from_le_bytes([
                    data[set_ref_off as usize],
                    data[set_ref_off as usize + 1],
                    data[set_ref_off as usize + 2],
                    data[set_ref_off as usize + 3],
                ]) as usize
            } else {
                0
            };
            for j in 0..sub_size {
                let sub_off_pos = set_ref_off as usize + 4 + j * 4;
                if sub_off_pos + 4 > data.len() { break; }
                let ann_off = u32::from_le_bytes([
                    data[sub_off_pos], data[sub_off_pos + 1],
                    data[sub_off_pos + 2], data[sub_off_pos + 3],
                ]);
                if ann_off != 0 {
                    if let Ok(ai) = parse_annotation_item(data, ann_off as usize) {
                        items.push(ai);
                    }
                }
            }
        }
    }
    Ok(items)
}

fn parse_annotation_item(data: &[u8], offset: usize) -> DexResult<AnnotationItem> {
    if offset + 1 > data.len() {
        return Err(DexError::TruncatedData);
    }
    let visibility = data[offset];
    let rest = &data[offset + 1..];
    let (_, annotation) = parse_annotation(rest).map_err(|_| DexError::InvalidValueType)?;
    Ok(AnnotationItem { visibility, annotation })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Nom Parsers: Map List
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn parse_map_list(data: &[u8], offset: usize) -> DexResult<MapList> {
    if offset + 4 > data.len() {
        return Ok(MapList { items: Vec::new() });
    }
    let size = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
    if size > 65536 {
        return Ok(MapList { items: Vec::new() });
    }
    let mut items = Vec::with_capacity(size);
    for i in 0..size {
        let base = offset + 4 + i * 12;
        if base + 12 > data.len() { break; }
        let type_ = u16::from_le_bytes([data[base], data[base + 1]]);
        let unused = u16::from_le_bytes([data[base + 2], data[base + 3]]);
        let item_size = u32::from_le_bytes([data[base + 4], data[base + 5], data[base + 6], data[base + 7]]);
        let item_offset = u32::from_le_bytes([data[base + 8], data[base + 9], data[base + 10], data[base + 11]]);
        items.push(MapItem { type_, unused, size: item_size, offset: item_offset });
    }
    Ok(MapList { items })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Main Parse Entry Point
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Parse a complete DEX file from a byte slice.
///
/// # Arguments
/// * `data` - The raw bytes of a DEX file.
///
/// # Returns
/// A `DexResult<DexFile>` with the fully parsed DEX structure.
pub fn parse_dex(data: &[u8]) -> DexResult<DexFile> {
    if data.len() < DEX_HEADER_SIZE {
        return Err(DexError::TruncatedData);
    }

    // Verify magic
    if data.len() < DEX_MAGIC_SIZE || data[0..4] != DEX_MAGIC {
        return Err(DexError::InvalidMagic);
    }

    // Parse header using nom
    let (_, header) = parse_dex_header(data).map_err(|_| DexError::InvalidMagic)?;

    // Verify endian tag
    if header.endian_tag != ENDIAN_CONSTANT && header.endian_tag != REVERSE_ENDIAN_CONSTANT {
        return Err(DexError::InvalidEndianTag);
    }

    // Validate table sizes
    if header.string_ids_size > MAX_TABLE_ENTRIES
        || header.type_ids_size > MAX_TABLE_ENTRIES
        || header.proto_ids_size > MAX_TABLE_ENTRIES
        || header.field_ids_size > MAX_TABLE_ENTRIES
        || header.method_ids_size > MAX_TABLE_ENTRIES
        || header.class_defs_size > MAX_TABLE_ENTRIES
    {
        return Err(DexError::TooManyEntries);
    }

    // Parse each table
    let strings = parse_strings(data, &header)?;
    let type_ids = parse_type_ids(data, &header)?;
    let proto_ids = parse_proto_ids(data, &header)?;
    let field_ids = parse_field_ids(data, &header)?;
    let method_ids = parse_method_ids(data, &header)?;
    let class_defs = parse_class_defs(data, &header)?;

    // Parse map list if present
    let map_list = if header.map_off != 0 {
        Some(parse_map_list(data, header.map_off as usize).unwrap_or_else(|_| MapList { items: Vec::new() }))
    } else {
        None
    };

    // Resolve code offsets in class data methods
    let mut resolved_defs = class_defs;
    for def in &mut resolved_defs {
        if let Some(ref mut cd) = def.class_data {
            for method in cd.direct_methods.iter_mut().chain(cd.virtual_methods.iter_mut()) {
                if method.code_off != 0 {
                    if let Ok(code) = parse_code_item(data, method.code_off as usize) {
                        method.code = Some(code);
                    }
                }
            }
        }
    }

    Ok(DexFile {
        header, strings, type_ids, proto_ids, field_ids, method_ids,
        class_defs: resolved_defs, map_list,
    })
}

/// Check whether the given data looks like a DEX file.
pub fn is_dex(data: &[u8]) -> bool {
    data.len() >= DEX_MAGIC_SIZE && data[0..4] == DEX_MAGIC
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// BinaryLoader Implementation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// DEX binary loader — loads Android Dalvik Executable files for analysis.
pub struct DexLoader;

impl crate::BinaryLoader for DexLoader {
    fn name(&self) -> &str {
        "DEX"
    }

    fn can_load(&self, data: &[u8]) -> bool {
        is_dex(data)
    }

    fn load(
        &self,
        data: &[u8],
        options: &crate::LoadOptions,
    ) -> anyhow::Result<crate::base::analyzer::Program> {
        use crate::base::analyzer::{Address, MemoryBlock, Program};

        let dex = parse_dex(data)?;
        let lang = crate::base::analyzer::Language {
            processor: "Dalvik".into(),
            variant: "LE".into(),
            size: 32,
        };

        let base = options.base_address;
        let mut program = Program::new("dex_file", lang);
        program.image_base = base;

        // Create a single memory block for the DEX file.
        let block = MemoryBlock {
            name: "DEX".into(),
            start: Address::new(base),
            size: dex.header.file_size as u64,
            is_read: true,
            is_write: false,
            is_execute: false,
            is_initialized: true,
        };
        program.memory_blocks.push(block);

        Ok(program)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid DEX header in a byte buffer.
    fn make_minimal_dex() -> Vec<u8> {
        let mut buf = vec![0u8; DEX_HEADER_SIZE];
        buf[0..8].copy_from_slice(&[0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]); // "dex\n035\0"
        buf[32..36].copy_from_slice(&(DEX_HEADER_SIZE as u32).to_le_bytes()); // file_size
        buf[36..40].copy_from_slice(&(DEX_HEADER_SIZE as u32).to_le_bytes()); // header_size
        buf[40..44].copy_from_slice(&ENDIAN_CONSTANT.to_le_bytes()); // endian_tag
        buf
    }

    #[test]
    fn test_parse_valid_dex_header() {
        let data = make_minimal_dex();
        let result = parse_dex(&data);
        assert!(result.is_ok());
        let dex = result.unwrap();
        assert_eq!(dex.header.endian_tag, ENDIAN_CONSTANT);
        assert_eq!(dex.header.file_size, DEX_HEADER_SIZE as u32);
        assert!(dex.strings.is_empty());
        assert!(dex.type_ids.is_empty());
        assert!(dex.proto_ids.is_empty());
        assert!(dex.field_ids.is_empty());
        assert!(dex.method_ids.is_empty());
        assert!(dex.class_defs.is_empty());
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = make_minimal_dex();
        data[0] = 0x00;
        assert!(matches!(parse_dex(&data), Err(DexError::InvalidMagic)));
    }

    #[test]
    fn test_truncated_data() {
        let data = vec![0; 4];
        assert!(matches!(parse_dex(&data), Err(DexError::TruncatedData)));
    }

    #[test]
    fn test_decode_uleb128() {
        assert_eq!(decode_uleb128(&[0x01]).unwrap(), (1, 1));
        assert_eq!(decode_uleb128(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(decode_uleb128(&[0x00]).unwrap(), (0, 1));
    }

    #[test]
    fn test_decode_sleb128() {
        assert_eq!(decode_sleb128(&[0x01]).unwrap(), (1, 1));
        assert_eq!(decode_sleb128(&[0x7f]).unwrap(), (-1, 1));
    }

    #[test]
    fn test_nom_uleb128() {
        assert_eq!(nom_uleb128(&[0x01]).unwrap(), (&b""[..], 1u64));
        assert_eq!(nom_uleb128(&[0x80, 0x01]).unwrap(), (&b""[..], 128u64));
    }

    #[test]
    fn test_nom_sleb128() {
        assert_eq!(nom_sleb128(&[0x01]).unwrap(), (&b""[..], 1i64));
        assert_eq!(nom_sleb128(&[0x7f]).unwrap(), (&b""[..], -1i64));
    }

    #[test]
    fn test_access_flag_names() {
        let names = access_flag_names(ACC_PUBLIC | ACC_STATIC | ACC_FINAL);
        assert!(names.contains(&"public"));
        assert!(names.contains(&"static"));
        assert!(names.contains(&"final"));
    }

    #[test]
    fn test_value_type_names() {
        assert_eq!(value_type_name(VALUE_BYTE), "byte");
        assert_eq!(value_type_name(VALUE_NULL), "null");
        assert_eq!(value_type_name(VALUE_BOOLEAN), "boolean");
        assert_eq!(value_type_name(0xFF), "unknown");
    }

    #[test]
    fn test_visibility_names() {
        assert_eq!(visibility_name(VISIBILITY_BUILD), "build");
        assert_eq!(visibility_name(VISIBILITY_RUNTIME), "runtime");
        assert_eq!(visibility_name(VISIBILITY_SYSTEM), "system");
    }

    #[test]
    fn test_map_type_names() {
        assert_eq!(map_type_name(TYPE_HEADER_ITEM), "HEADER_ITEM");
        assert_eq!(map_type_name(TYPE_MAP_LIST), "MAP_LIST");
        assert_eq!(map_type_name(0xFFFF), "UNKNOWN");
    }

    #[test]
    fn test_is_dex() {
        let data = make_minimal_dex();
        assert!(is_dex(&data));
        assert!(!is_dex(b"not_dex"));
        assert!(!is_dex(&[]));
    }

    #[test]
    fn test_decode_mutf8_simple() {
        // ULEB128(3) + "abc"
        let data = [0x03, 0x61, 0x62, 0x63];
        let (s, n) = decode_mutf8(&data).unwrap();
        assert_eq!(s, "abc");
        assert_eq!(n, 4);
    }

    #[test]
    fn test_decode_mutf8_null() {
        // ULEB128(2) + MUTF8 null (C0 80)
        let data = [0x02, 0xC0, 0x80];
        let (s, _) = decode_mutf8(&data).unwrap();
        assert_eq!(s, "\0");
    }
}
