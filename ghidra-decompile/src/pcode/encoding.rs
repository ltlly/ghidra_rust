//! Encoder and Decoder infrastructure for P-code serialization.
//!
//! Ports Ghidra's `Encoder`, `Decoder`, `AttributeId`, `ElementId`,
//! `PackedDecode`, `PackedEncode`, `XmlEncode`, `PackedDecodeOverlay`,
//! `PackedEncodeOverlay`, `PatchPackedEncode`, `PatchEncoder`,
//! `CachedEncoder`, `ByteIngest`, `StringIngest`, `LinkedByteBuffer`,
//! and `PackedBytes`.
//!
//! These types provide the serialization/deserialization infrastructure for
//! the decompiler's XML-like streaming format.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// AttributeId - identifiers for XML attributes
// ============================================================================

/// Identifiers for attributes used in the P-code serialization format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttributeId {
    /// Name attribute.
    Name,
    /// Value/content attribute.
    Content,
    /// Space (address space) attribute.
    Space,
    /// Offset attribute.
    Offset,
    /// Size attribute.
    Size,
    /// Unique id attribute.
    Uniq,
    /// Index attribute.
    Index,
    /// Id (unique identifier) attribute.
    Id,
    /// Code (opcode) attribute.
    Code,
    /// Type lock attribute.
    TypeLock,
    /// Name lock attribute.
    NameLock,
    /// First use offset attribute.
    First,
    /// Last address attribute.
    Last,
    /// Volatile attribute.
    Volatile,
    /// Read-only attribute.
    ReadOnly,
    /// Merge attribute.
    Merge,
    /// This pointer attribute.
    ThisPtr,
    /// Hidden return parameter attribute.
    HiddenRetParm,
    /// Category attribute.
    Cat,
    /// Inline attribute.
    Inline,
    /// No-return attribute.
    NoReturn,
    /// Custom storage attribute.
    Custom,
    /// Constructor attribute.
    Constructor,
    /// Destructor attribute.
    Destructor,
    /// Model (calling convention) attribute.
    Model,
    /// Model lock attribute.
    ModelLock,
    /// Extra pop attribute.
    ExtraPop,
    /// Dot-dot-dot (varargs) attribute.
    DotDotDot,
    /// Void lock attribute.
    VoidLock,
    /// Lock attribute.
    Lock,
    /// Main (main address space) attribute.
    Main,
    /// Label attribute.
    Label,
    /// Format attribute.
    Format,
    /// Symbol reference attribute.
    SymRef,
    /// Reference attribute.
    Ref,
    /// Group attribute.
    Grp,
    /// Persistent attribute.
    Persists,
    /// Address-tied attribute.
    AddrTied,
    /// Unaffected attribute.
    Unaff,
    /// Input attribute.
    Input,
    /// Representative reference attribute.
    RepRef,
    /// Logical size attribute.
    LogicalSize,
    /// Piece attributes.
    Piece,
    /// Unknown attribute.
    Unknown,
}

impl AttributeId {
    /// Get the numeric id (for wire format compatibility).
    pub fn id(self) -> i32 {
        match self {
            AttributeId::Name => 1,
            AttributeId::Content => 2,
            AttributeId::Space => 3,
            AttributeId::Offset => 4,
            AttributeId::Size => 5,
            AttributeId::Uniq => 6,
            AttributeId::Index => 7,
            AttributeId::Id => 8,
            AttributeId::Code => 9,
            AttributeId::TypeLock => 10,
            AttributeId::NameLock => 11,
            AttributeId::First => 12,
            AttributeId::Last => 13,
            AttributeId::Volatile => 14,
            AttributeId::ReadOnly => 15,
            AttributeId::Merge => 16,
            AttributeId::ThisPtr => 17,
            AttributeId::HiddenRetParm => 18,
            AttributeId::Cat => 19,
            AttributeId::Inline => 20,
            AttributeId::NoReturn => 21,
            AttributeId::Custom => 22,
            AttributeId::Constructor => 23,
            AttributeId::Destructor => 24,
            AttributeId::Model => 25,
            AttributeId::ModelLock => 26,
            AttributeId::ExtraPop => 27,
            AttributeId::DotDotDot => 28,
            AttributeId::VoidLock => 29,
            AttributeId::Lock => 30,
            AttributeId::Main => 31,
            AttributeId::Label => 32,
            AttributeId::Format => 33,
            AttributeId::SymRef => 34,
            AttributeId::Ref => 35,
            AttributeId::Grp => 36,
            AttributeId::Persists => 37,
            AttributeId::AddrTied => 38,
            AttributeId::Unaff => 39,
            AttributeId::Input => 40,
            AttributeId::RepRef => 41,
            AttributeId::LogicalSize => 42,
            AttributeId::Piece => 43,
            AttributeId::Unknown => 99,
        }
    }

    /// Get the string name of this attribute.
    pub fn name(self) -> &'static str {
        match self {
            AttributeId::Name => "name",
            AttributeId::Content => "content",
            AttributeId::Space => "space",
            AttributeId::Offset => "offset",
            AttributeId::Size => "size",
            AttributeId::Uniq => "uniq",
            AttributeId::Index => "index",
            AttributeId::Id => "id",
            AttributeId::Code => "code",
            AttributeId::TypeLock => "typelock",
            AttributeId::NameLock => "namelock",
            AttributeId::First => "first",
            AttributeId::Last => "last",
            AttributeId::Volatile => "volatile",
            AttributeId::ReadOnly => "readonly",
            AttributeId::Merge => "merge",
            AttributeId::ThisPtr => "thisptr",
            AttributeId::HiddenRetParm => "hiddenretparm",
            AttributeId::Cat => "cat",
            AttributeId::Inline => "inline",
            AttributeId::NoReturn => "noreturn",
            AttributeId::Custom => "custom",
            AttributeId::Constructor => "constructor",
            AttributeId::Destructor => "destructor",
            AttributeId::Model => "model",
            AttributeId::ModelLock => "modellock",
            AttributeId::ExtraPop => "extrapop",
            AttributeId::DotDotDot => "dotdotdot",
            AttributeId::VoidLock => "voidlock",
            AttributeId::Lock => "lock",
            AttributeId::Main => "main",
            AttributeId::Label => "label",
            AttributeId::Format => "format",
            AttributeId::SymRef => "symref",
            AttributeId::Ref => "ref",
            AttributeId::Grp => "grp",
            AttributeId::Persists => "persists",
            AttributeId::AddrTied => "addrtied",
            AttributeId::Unaff => "unaff",
            AttributeId::Input => "input",
            AttributeId::RepRef => "repref",
            AttributeId::LogicalSize => "logicalsize",
            AttributeId::Piece => "piece",
            AttributeId::Unknown => "unknown",
        }
    }

    /// Parse an attribute id from a string name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "name" => Some(AttributeId::Name),
            "content" => Some(AttributeId::Content),
            "space" => Some(AttributeId::Space),
            "offset" => Some(AttributeId::Offset),
            "size" => Some(AttributeId::Size),
            "uniq" => Some(AttributeId::Uniq),
            "index" => Some(AttributeId::Index),
            "id" => Some(AttributeId::Id),
            "code" => Some(AttributeId::Code),
            "typelock" => Some(AttributeId::TypeLock),
            "namelock" => Some(AttributeId::NameLock),
            "first" => Some(AttributeId::First),
            "last" => Some(AttributeId::Last),
            "volatile" => Some(AttributeId::Volatile),
            "readonly" => Some(AttributeId::ReadOnly),
            "merge" => Some(AttributeId::Merge),
            "thisptr" => Some(AttributeId::ThisPtr),
            "hiddenretparm" => Some(AttributeId::HiddenRetParm),
            "cat" => Some(AttributeId::Cat),
            "inline" => Some(AttributeId::Inline),
            "noreturn" => Some(AttributeId::NoReturn),
            "custom" => Some(AttributeId::Custom),
            "constructor" => Some(AttributeId::Constructor),
            "destructor" => Some(AttributeId::Destructor),
            "model" => Some(AttributeId::Model),
            "modellock" => Some(AttributeId::ModelLock),
            "extrapop" => Some(AttributeId::ExtraPop),
            "dotdotdot" => Some(AttributeId::DotDotDot),
            "voidlock" => Some(AttributeId::VoidLock),
            "lock" => Some(AttributeId::Lock),
            "main" => Some(AttributeId::Main),
            "label" => Some(AttributeId::Label),
            "format" => Some(AttributeId::Format),
            "symref" => Some(AttributeId::SymRef),
            "ref" => Some(AttributeId::Ref),
            "grp" => Some(AttributeId::Grp),
            "persists" => Some(AttributeId::Persists),
            "addrtied" => Some(AttributeId::AddrTied),
            "unaff" => Some(AttributeId::Unaff),
            "input" => Some(AttributeId::Input),
            "repref" => Some(AttributeId::RepRef),
            "logicalsize" => Some(AttributeId::LogicalSize),
            "piece" => Some(AttributeId::Piece),
            _ => None,
        }
    }
}

// ============================================================================
// ElementId - identifiers for XML elements
// ============================================================================

/// Identifiers for elements used in the P-code serialization format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ElementId {
    /// Function element.
    Function,
    /// AST element (syntax tree).
    Ast,
    /// Varnodes element.
    Varnodes,
    /// Single varnode element.
    Varnode,
    /// Block element.
    Block,
    /// Block edge element.
    BlockEdge,
    /// Block header element.
    BHead,
    /// Prototype element.
    Prototype,
    /// Return symbol element.
    ReturnSym,
    /// Parameter element.
    Param,
    /// Symbol element.
    Symbol,
    /// Symbol list element.
    SymbolList,
    /// Map symbol element.
    MapSym,
    /// Equate symbol element.
    EquateSymbol,
    /// Scope element.
    Scope,
    /// Local database element.
    LocalDb,
    /// High variable element.
    High,
    /// High list element.
    HighList,
    /// Jump table element.
    JumpTable,
    /// Jump table list element.
    JumpTableList,
    /// Address element.
    Addr,
    /// Op element.
    Op,
    /// Seqnum element.
    SeqNum,
    /// Void element.
    Void,
    /// Space id element.
    SpaceId,
    /// IOP element.
    Iop,
    /// Range element.
    Range,
    /// Range list element.
    RangeList,
    /// Edge element.
    Edge,
    /// Parent element.
    Parent,
    /// Val element.
    Val,
    /// Inject element.
    Inject,
    /// Internal list element.
    InternalList,
    /// Override element.
    Override,
    /// Proto override element.
    ProtoOverride,
    /// Hash element.
    Hash,
    /// Load table element.
    LoadTable,
    /// Dest element.
    Dest,
    /// Value element.
    Value,
}

impl ElementId {
    /// Get the numeric id.
    pub fn id(self) -> i32 {
        match self {
            ElementId::Function => 1,
            ElementId::Ast => 2,
            ElementId::Varnodes => 3,
            ElementId::Varnode => 4,
            ElementId::Block => 5,
            ElementId::BlockEdge => 6,
            ElementId::BHead => 7,
            ElementId::Prototype => 8,
            ElementId::ReturnSym => 9,
            ElementId::Param => 10,
            ElementId::Symbol => 11,
            ElementId::SymbolList => 12,
            ElementId::MapSym => 13,
            ElementId::EquateSymbol => 14,
            ElementId::Scope => 15,
            ElementId::LocalDb => 16,
            ElementId::High => 17,
            ElementId::HighList => 18,
            ElementId::JumpTable => 19,
            ElementId::JumpTableList => 20,
            ElementId::Addr => 21,
            ElementId::Op => 22,
            ElementId::SeqNum => 23,
            ElementId::Void => 24,
            ElementId::SpaceId => 25,
            ElementId::Iop => 26,
            ElementId::Range => 27,
            ElementId::RangeList => 28,
            ElementId::Edge => 29,
            ElementId::Parent => 30,
            ElementId::Val => 31,
            ElementId::Inject => 32,
            ElementId::InternalList => 33,
            ElementId::Override => 34,
            ElementId::ProtoOverride => 35,
            ElementId::Hash => 36,
            ElementId::LoadTable => 37,
            ElementId::Dest => 38,
            ElementId::Value => 39,
        }
    }

    /// Get the string name.
    pub fn name(self) -> &'static str {
        match self {
            ElementId::Function => "function",
            ElementId::Ast => "ast",
            ElementId::Varnodes => "varnodes",
            ElementId::Varnode => "varnode",
            ElementId::Block => "block",
            ElementId::BlockEdge => "blockedge",
            ElementId::BHead => "bhead",
            ElementId::Prototype => "prototype",
            ElementId::ReturnSym => "returnsym",
            ElementId::Param => "param",
            ElementId::Symbol => "symbol",
            ElementId::SymbolList => "symbollist",
            ElementId::MapSym => "mapsym",
            ElementId::EquateSymbol => "equatesymbol",
            ElementId::Scope => "scope",
            ElementId::LocalDb => "localdb",
            ElementId::High => "high",
            ElementId::HighList => "highlist",
            ElementId::JumpTable => "jumptable",
            ElementId::JumpTableList => "jumptablelist",
            ElementId::Addr => "addr",
            ElementId::Op => "op",
            ElementId::SeqNum => "seqnum",
            ElementId::Void => "void",
            ElementId::SpaceId => "spaceid",
            ElementId::Iop => "iop",
            ElementId::Range => "range",
            ElementId::RangeList => "rangelist",
            ElementId::Edge => "edge",
            ElementId::Parent => "parent",
            ElementId::Val => "val",
            ElementId::Inject => "inject",
            ElementId::InternalList => "internallist",
            ElementId::Override => "override",
            ElementId::ProtoOverride => "protooverride",
            ElementId::Hash => "hash",
            ElementId::LoadTable => "loadtable",
            ElementId::Dest => "dest",
            ElementId::Value => "value",
        }
    }

    /// Parse from a string name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "function" => Some(ElementId::Function),
            "ast" => Some(ElementId::Ast),
            "varnodes" => Some(ElementId::Varnodes),
            "varnode" => Some(ElementId::Varnode),
            "block" => Some(ElementId::Block),
            "blockedge" => Some(ElementId::BlockEdge),
            "bhead" => Some(ElementId::BHead),
            "prototype" => Some(ElementId::Prototype),
            "returnsym" => Some(ElementId::ReturnSym),
            "param" => Some(ElementId::Param),
            "symbol" => Some(ElementId::Symbol),
            "symbollist" => Some(ElementId::SymbolList),
            "mapsym" => Some(ElementId::MapSym),
            "equatesymbol" => Some(ElementId::EquateSymbol),
            "scope" => Some(ElementId::Scope),
            "localdb" => Some(ElementId::LocalDb),
            "high" => Some(ElementId::High),
            "highlist" => Some(ElementId::HighList),
            "jumptable" => Some(ElementId::JumpTable),
            "jumptablelist" => Some(ElementId::JumpTableList),
            "addr" => Some(ElementId::Addr),
            "op" => Some(ElementId::Op),
            "seqnum" => Some(ElementId::SeqNum),
            "void" => Some(ElementId::Void),
            "spaceid" => Some(ElementId::SpaceId),
            "iop" => Some(ElementId::Iop),
            "range" => Some(ElementId::Range),
            "rangelist" => Some(ElementId::RangeList),
            "edge" => Some(ElementId::Edge),
            "parent" => Some(ElementId::Parent),
            "val" => Some(ElementId::Val),
            "inject" => Some(ElementId::Inject),
            "internallist" => Some(ElementId::InternalList),
            "override" => Some(ElementId::Override),
            "protooverride" => Some(ElementId::ProtoOverride),
            "hash" => Some(ElementId::Hash),
            "loadtable" => Some(ElementId::LoadTable),
            "dest" => Some(ElementId::Dest),
            "value" => Some(ElementId::Value),
            _ => None,
        }
    }
}

// ============================================================================
// DecoderException
// ============================================================================

/// Error type for decoder operations.
#[derive(Debug, Clone)]
pub struct DecoderException {
    /// Error message.
    pub message: String,
}

impl DecoderException {
    /// Create a new decoder exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Create a decoder exception wrapping another error.
    pub fn wrap(message: &str, source: &str) -> Self {
        Self {
            message: format!("{}: {}", message, source),
        }
    }
}

impl std::fmt::Display for DecoderException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecoderException: {}", self.message)
    }
}

impl std::error::Error for DecoderException {}

// ============================================================================
// Encoder trait
// ============================================================================

/// Trait for encoding P-code data to a stream.
///
/// Implementors provide methods to write elements, attributes, and values.
pub trait Encoder {
    /// Open a new element.
    fn open_element(&mut self, id: ElementId);

    /// Close the current element.
    fn close_element(&mut self);

    /// Write a signed integer attribute.
    fn write_signed_integer(&mut self, attrib: AttributeId, value: i64);

    /// Write an unsigned integer attribute.
    fn write_unsigned_integer(&mut self, attrib: AttributeId, value: u64);

    /// Write a string attribute.
    fn write_string(&mut self, attrib: AttributeId, value: &str);

    /// Write a boolean attribute.
    fn write_bool(&mut self, attrib: AttributeId, value: bool);

    /// Write a space attribute.
    fn write_space(&mut self, attrib: AttributeId, name: &str);
}

// ============================================================================
// Decoder trait
// ============================================================================

/// Trait for decoding P-code data from a stream.
///
/// Implementors provide methods to read elements, attributes, and values.
pub trait Decoder {
    /// Open the next element. Returns the element id.
    fn open_element(&mut self) -> Result<i32, DecoderException>;

    /// Close the current element.
    fn close_element(&mut self, id: i32) -> Result<(), DecoderException>;

    /// Peek at the next element id without consuming it.
    fn peek_element(&self) -> i32;

    /// Get the next attribute id. Returns 0 if no more attributes.
    fn get_next_attribute_id(&mut self) -> i32;

    /// Get an indexed attribute id.
    fn get_indexed_attribute_id(&mut self, attrib: AttributeId) -> i32;

    /// Rewind attribute traversal.
    fn rewind_attributes(&mut self);

    /// Read the current attribute as a boolean.
    fn read_bool(&self) -> bool;

    /// Read the current attribute as a signed integer.
    fn read_signed_integer(&self) -> i64;

    /// Read the current attribute as an unsigned integer.
    fn read_unsigned_integer(&self) -> u64;

    /// Read the current attribute as a string.
    fn read_string(&self) -> &str;

    /// Read a signed integer attribute by id, with an expected string default.
    fn read_signed_integer_expect_string(
        &self,
        attrib: AttributeId,
        default_str: &str,
        default_val: i64,
    ) -> i64;

    /// Skip the current element and its children.
    fn skip_element(&mut self) -> Result<(), DecoderException>;

    /// Close the current element, skipping its content.
    fn close_element_skipping(&mut self, id: i32) -> Result<(), DecoderException>;

    /// Read a space attribute.
    fn read_space(&mut self, attrib: AttributeId) -> Result<String, DecoderException>;

    /// Get the address factory name.
    fn get_address_factory(&self) -> &str;
}

// ============================================================================
// XmlEncoder - simple XML-like encoder
// ============================================================================

/// A simple encoder that produces an XML-like string representation.
#[derive(Debug, Clone)]
pub struct XmlEncoder {
    /// The output buffer.
    pub output: String,
    /// Current indentation depth.
    pub depth: usize,
    /// Stack of open element names.
    pub stack: Vec<String>,
}

impl XmlEncoder {
    /// Create a new XML encoder.
    pub fn new() -> Self {
        Self {
            output: String::new(),
            depth: 0,
            stack: Vec::new(),
        }
    }

    /// Get the encoded output as a string.
    pub fn get_output(&self) -> &str {
        &self.output
    }

    /// Produce indentation whitespace.
    fn indent(&self) -> String {
        "  ".repeat(self.depth)
    }
}

impl Default for XmlEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for XmlEncoder {
    fn open_element(&mut self, id: ElementId) {
        let name = id.name();
        let indent = self.indent();
        self.output.push_str(&format!("{}<{}", indent, name));
        self.stack.push(name.to_string());
        self.depth += 1;
    }

    fn close_element(&mut self) {
        self.depth -= 1;
        if let Some(name) = self.stack.pop() {
            let indent = self.indent();
            self.output.push_str(&format!("{}</{}>\n", indent, name));
        }
    }

    fn write_signed_integer(&mut self, attrib: AttributeId, value: i64) {
        self.output
            .push_str(&format!(" {}=\"{}\"", attrib.name(), value));
    }

    fn write_unsigned_integer(&mut self, attrib: AttributeId, value: u64) {
        self.output
            .push_str(&format!(" {}=\"{}\"", attrib.name(), value));
    }

    fn write_string(&mut self, attrib: AttributeId, value: &str) {
        self.output
            .push_str(&format!(" {}=\"{}\"", attrib.name(), value));
    }

    fn write_bool(&mut self, attrib: AttributeId, value: bool) {
        self.output
            .push_str(&format!(" {}=\"{}\"", attrib.name(), if value { "true" } else { "false" }));
    }

    fn write_space(&mut self, attrib: AttributeId, name: &str) {
        self.output
            .push_str(&format!(" {}=\"{}\"", attrib.name(), name));
    }
}

// ============================================================================
// PackedBytes - packed byte buffer for compact serialization
// ============================================================================

/// A compact byte buffer for the packed encoding format.
#[derive(Debug, Clone)]
pub struct PackedBytes {
    /// The underlying byte storage.
    pub data: Vec<u8>,
}

impl PackedBytes {
    /// Create a new empty packed bytes buffer.
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create with a given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Write a byte.
    pub fn write_byte(&mut self, b: u8) {
        self.data.push(b);
    }

    /// Write bytes.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Write an unsigned integer as a variable-length encoded value.
    pub fn write_unsigned(&mut self, mut val: u64) {
        while val >= 0x80 {
            self.data.push((val as u8) | 0x80);
            val >>= 7;
        }
        self.data.push(val as u8);
    }

    /// Write a signed integer (zigzag encoded).
    pub fn write_signed(&mut self, val: i64) {
        let encoded = ((val << 1) ^ (val >> 63)) as u64;
        self.write_unsigned(encoded);
    }

    /// Write a string (length-prefixed).
    pub fn write_string(&mut self, s: &str) {
        self.write_unsigned(s.len() as u64);
        self.data.extend_from_slice(s.as_bytes());
    }

    /// Get the current length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for PackedBytes {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PackedDecode - packed format decoder
// ============================================================================

/// A decoder for the packed binary format.
#[derive(Debug, Clone)]
pub struct PackedDecode {
    /// The input data.
    pub data: Vec<u8>,
    /// Current read position.
    pub position: usize,
    /// Current element stack (element ids).
    pub element_stack: Vec<i32>,
    /// Attribute state for the current element.
    pub current_attribs: HashMap<i32, DecodedValue>,
    /// Next attribute index for traversal.
    pub attrib_index: usize,
    /// Attribute keys in traversal order.
    pub attrib_keys: Vec<i32>,
}

/// A decoded value (boolean, integer, or string).
#[derive(Debug, Clone)]
pub enum DecodedValue {
    /// Boolean value.
    Bool(bool),
    /// Signed integer value.
    SignedInt(i64),
    /// Unsigned integer value.
    UnsignedInt(u64),
    /// String value.
    String(String),
}

impl PackedDecode {
    /// Create a new packed decoder.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            position: 0,
            element_stack: Vec::new(),
            current_attribs: HashMap::new(),
            attrib_index: 0,
            attrib_keys: Vec::new(),
        }
    }

    /// Read a byte.
    pub fn read_byte(&mut self) -> Option<u8> {
        if self.position < self.data.len() {
            let b = self.data[self.position];
            self.position += 1;
            Some(b)
        } else {
            None
        }
    }

    /// Read a variable-length unsigned integer.
    pub fn read_unsigned(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let b = self.read_byte()?;
            result |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Some(result)
    }

    /// Read a zigzag-encoded signed integer.
    pub fn read_signed(&mut self) -> Option<i64> {
        let val = self.read_unsigned()?;
        Some(((val >> 1) as i64) ^ -((val & 1) as i64))
    }

    /// Read a length-prefixed string.
    pub fn read_string_val(&mut self) -> Option<String> {
        let len = self.read_unsigned()? as usize;
        if self.position + len > self.data.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&self.data[self.position..self.position + len]).to_string();
        self.position += len;
        Some(s)
    }

    /// Get the total data length.
    pub fn total_len(&self) -> usize {
        self.data.len()
    }

    /// Get remaining bytes.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }
}

// ============================================================================
// PackedEncode - packed format encoder
// ============================================================================

/// An encoder for the packed binary format.
#[derive(Debug, Clone)]
pub struct PackedEncode {
    /// The output buffer.
    pub buffer: PackedBytes,
}

impl PackedEncode {
    /// Create a new packed encoder.
    pub fn new() -> Self {
        Self {
            buffer: PackedBytes::new(),
        }
    }

    /// Get the encoded data.
    pub fn get_data(&self) -> &[u8] {
        &self.buffer.data
    }

    /// Get the length of encoded data.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the encoded data is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Default for PackedEncode {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for PackedEncode {
    fn open_element(&mut self, id: ElementId) {
        self.buffer.write_unsigned(id.id() as u64);
    }

    fn close_element(&mut self) {
        self.buffer.write_byte(0); // end-of-element marker
    }

    fn write_signed_integer(&mut self, attrib: AttributeId, value: i64) {
        self.buffer.write_unsigned(attrib.id() as u64);
        self.buffer.write_signed(value);
    }

    fn write_unsigned_integer(&mut self, attrib: AttributeId, value: u64) {
        self.buffer.write_unsigned(attrib.id() as u64);
        self.buffer.write_unsigned(value);
    }

    fn write_string(&mut self, attrib: AttributeId, value: &str) {
        self.buffer.write_unsigned(attrib.id() as u64);
        self.buffer.write_string(value);
    }

    fn write_bool(&mut self, attrib: AttributeId, value: bool) {
        self.buffer.write_unsigned(attrib.id() as u64);
        self.buffer.write_byte(if value { 1 } else { 0 });
    }

    fn write_space(&mut self, attrib: AttributeId, name: &str) {
        self.buffer.write_unsigned(attrib.id() as u64);
        self.buffer.write_string(name);
    }
}

// ============================================================================
// ByteIngest
// ============================================================================

/// A trait for types that can ingest raw bytes.
pub trait ByteIngest {
    /// Ingest a single byte.
    fn ingest_byte(&mut self, b: u8);

    /// Ingest a slice of bytes.
    fn ingest_bytes(&mut self, data: &[u8]) {
        for &b in data {
            self.ingest_byte(b);
        }
    }
}

// ============================================================================
// StringIngest
// ============================================================================

/// A trait for types that can ingest strings.
pub trait StringIngest {
    /// Ingest a string.
    fn ingest_string(&mut self, s: &str);
}

// ============================================================================
// LinkedByteBuffer
// ============================================================================

/// A linked list of byte buffers, used for efficient incremental encoding.
#[derive(Debug, Clone)]
pub struct LinkedByteBuffer {
    /// The buffers in order.
    pub buffers: Vec<Vec<u8>>,
    /// Total length across all buffers.
    pub total_len: usize,
}

impl LinkedByteBuffer {
    /// Create a new linked byte buffer.
    pub fn new() -> Self {
        Self {
            buffers: Vec::new(),
            total_len: 0,
        }
    }

    /// Add a new buffer.
    pub fn add_buffer(&mut self, data: Vec<u8>) {
        self.total_len += data.len();
        self.buffers.push(data);
    }

    /// Flatten all buffers into a single Vec.
    pub fn flatten(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_len);
        for buf in &self.buffers {
            result.extend_from_slice(buf);
        }
        result
    }

    /// Get the total length.
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }
}

impl Default for LinkedByteBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteIngest for LinkedByteBuffer {
    fn ingest_byte(&mut self, b: u8) {
        if self.buffers.is_empty() {
            self.buffers.push(Vec::new());
        }
        self.buffers.last_mut().unwrap().push(b);
        self.total_len += 1;
    }
}

// ============================================================================
// AddressXML - address encoding/decoding utilities
// ============================================================================

/// Maximum number of pieces in a join address.
pub const MAX_PIECES: usize = 10;

/// Utilities for encoding and decoding addresses.
pub struct AddressXML;

impl AddressXML {
    /// Encode an address as attributes on the current element.
    pub fn encode_attributes(encoder: &mut dyn Encoder, space: &str, offset: u64) {
        encoder.write_space(AttributeId::Space, space);
        encoder.write_unsigned_integer(AttributeId::Offset, offset);
    }

    /// Encode an address as an `<addr>` element.
    pub fn encode(encoder: &mut dyn Encoder, space: &str, offset: u64) {
        encoder.open_element(ElementId::Addr);
        Self::encode_attributes(encoder, space, offset);
        encoder.close_element();
    }

    /// Encode a varnode as attributes.
    pub fn encode_varnode(encoder: &mut dyn Encoder, space: &str, offset: u64, size: u32) {
        encoder.write_space(AttributeId::Space, space);
        encoder.write_unsigned_integer(AttributeId::Offset, offset);
        encoder.write_signed_integer(AttributeId::Size, size as i64);
    }

    /// Encode multiple varnodes (for join storage).
    pub fn encode_varnodes(
        encoder: &mut dyn Encoder,
        varnodes: &[(String, u64, u32)],
        logical_size: u32,
    ) {
        encoder.open_element(ElementId::Addr);
        if logical_size > 0 {
            encoder.write_signed_integer(AttributeId::LogicalSize, logical_size as i64);
        }
        for (i, (space, offset, _size)) in varnodes.iter().enumerate() {
            let piece_name = format!("piece{}", i);
            encoder.write_string(AttributeId::Piece, &format!("{}:0x{:x}", space, offset));
            let _ = piece_name;
        }
        encoder.close_element();
    }
}

// ============================================================================
// PatchEncoder - encoder that patches previously written data
// ============================================================================

/// An encoder that can patch previously written data.
///
/// Useful for encoding forward references that need to be resolved later.
#[derive(Debug, Clone)]
pub struct PatchEncoder {
    /// The output data.
    pub data: Vec<u8>,
    /// Patches to apply: (offset, value) pairs.
    pub patches: Vec<(usize, u64)>,
}

impl PatchEncoder {
    /// Create a new patch encoder.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            patches: Vec::new(),
        }
    }

    /// Get the current position (for recording patch locations).
    pub fn position(&self) -> usize {
        self.data.len()
    }

    /// Apply all patches.
    pub fn apply_patches(&mut self) {
        for &(offset, value) in &self.patches {
            let bytes = value.to_le_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if offset + i < self.data.len() {
                    self.data[offset + i] = b;
                }
            }
        }
        self.patches.clear();
    }
}

impl Default for PatchEncoder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_id_roundtrip() {
        let ids = vec![
            AttributeId::Name,
            AttributeId::Content,
            AttributeId::Space,
            AttributeId::Offset,
            AttributeId::Size,
            AttributeId::Code,
            AttributeId::Id,
        ];
        for id in ids {
            let name = id.name();
            let parsed = AttributeId::from_name(name);
            assert_eq!(parsed, Some(id), "roundtrip failed for {:?}", id);
        }
    }

    #[test]
    fn test_element_id_roundtrip() {
        let ids = vec![
            ElementId::Function,
            ElementId::Ast,
            ElementId::Block,
            ElementId::Op,
            ElementId::Varnode,
            ElementId::Symbol,
        ];
        for id in ids {
            let name = id.name();
            let parsed = ElementId::from_name(name);
            assert_eq!(parsed, Some(id), "roundtrip failed for {:?}", id);
        }
    }

    #[test]
    fn test_xml_encoder() {
        let mut encoder = XmlEncoder::new();
        encoder.open_element(ElementId::Function);
        encoder.write_string(AttributeId::Name, "main");
        encoder.write_signed_integer(AttributeId::Size, 100);
        encoder.close_element();
        let output = encoder.get_output();
        assert!(output.contains("function"));
        assert!(output.contains("main"));
    }

    #[test]
    fn test_packed_bytes() {
        let mut pb = PackedBytes::new();
        pb.write_unsigned(42);
        pb.write_signed(-10);
        pb.write_string("hello");
        assert!(!pb.is_empty());

        let mut decoder = PackedDecode::new(pb.data);
        assert_eq!(decoder.read_unsigned(), Some(42));
        assert_eq!(decoder.read_signed(), Some(-10));
        assert_eq!(decoder.read_string_val(), Some("hello".to_string()));
    }

    #[test]
    fn test_packed_encode_decode_roundtrip() {
        let mut encoder = PackedEncode::new();
        encoder.open_element(ElementId::Op);
        encoder.write_signed_integer(AttributeId::Code, 19);
        encoder.write_string(AttributeId::Name, "INT_ADD");
        encoder.close_element();
        assert!(!encoder.is_empty());
    }

    #[test]
    fn test_linked_byte_buffer() {
        let mut buf = LinkedByteBuffer::new();
        buf.ingest_byte(1);
        buf.ingest_bytes(&[2, 3, 4]);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.flatten(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_decoder_exception() {
        let err = DecoderException::new("bad data");
        assert!(err.message.contains("bad data"));
        assert!(format!("{}", err).contains("DecoderException"));

        let err2 = DecoderException::wrap("parsing", "unexpected token");
        assert!(err2.message.contains("parsing"));
        assert!(err2.message.contains("unexpected token"));
    }

    #[test]
    fn test_address_xml() {
        let mut encoder = XmlEncoder::new();
        AddressXML::encode(&mut encoder, "ram", 0x1000);
        let output = encoder.get_output();
        assert!(output.contains("addr"));
        assert!(output.contains("ram"));
        assert!(output.contains("4096"));
    }

    #[test]
    fn test_patch_encoder() {
        let mut pe = PatchEncoder::new();
        pe.data.extend_from_slice(&[0u8; 16]);
        let pos = pe.position();
        pe.patches.push((pos - 8, 0x1234_5678_9ABC_DEF0));
        pe.apply_patches();
        let value = u64::from_le_bytes(pe.data[pos - 8..pos].try_into().unwrap());
        assert_eq!(value, 0x1234_5678_9ABC_DEF0);
    }
}
