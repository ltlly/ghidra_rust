//! Swift language support: name demangler, type metadata, and calling convention.
//!
//! Handles mangled Swift symbols produced by the Swift compiler.
//! Supports Swift 4+ mangling (`$s`/`$S` prefixes) as well as
//! legacy Swift 2.x/3.x mangling (`_T0`, `_Tt`, `__T` prefixes).
//!
//! # Mangling Format Overview
//!
//! The modern Swift mangling (Swift 4+) uses a postfix tree encoding.
//! A mangled name begins with `$s` (or `$S`) followed by the module name
//! and a sequence of node operators and their operands.
//!
//! # Example
//!
//! ```ignore
//! $s10MyModule14MyViewControllerC5titleSSvp
//! -> MyModule.MyViewController.title : String { get }
//! ```

pub mod options;
pub mod swift_analyzer;
pub mod swift_demangler;
pub mod swift_language_service;

use std::fmt;
use std::fmt::Write as FmtWrite;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during demangling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DemangleError {
    /// Not a Swift mangled name (wrong prefix).
    NotMangled,
    /// Unexpected end of input while parsing.
    UnexpectedEnd,
    /// Unknown mangling operator encountered.
    UnknownOperator(String),
    /// Invalid encoding of a number or identifier.
    InvalidEncoding(String),
    /// Generic demangling failure.
    DemangleFailed(String),
}

impl fmt::Display for DemangleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMangled => write!(f, "not a Swift mangled name"),
            Self::UnexpectedEnd => write!(f, "unexpected end of input"),
            Self::UnknownOperator(op) => write!(f, "unknown operator: {op}"),
            Self::InvalidEncoding(msg) => write!(f, "invalid encoding: {msg}"),
            Self::DemangleFailed(msg) => write!(f, "demangle failed: {msg}"),
        }
    }
}

impl std::error::Error for DemangleError {}

// ---------------------------------------------------------------------------
// Node type -- represents the parsed demangling tree
// ---------------------------------------------------------------------------

/// All recognised node kinds in the Swift mangling grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    // ---- Memory allocation ----
    /// Stack allocation for a value (AllocStack).
    AllocStack,
    /// Anonymous context descriptor.
    AnonymousContext,

    // ---- Declarations ----
    Structure {
        name: String,
        module: String,
        generic_args: Option<Box<Node>>,
    },
    Class {
        name: String,
        module: String,
        generic_args: Option<Box<Node>>,
    },
    Enum {
        name: String,
        module: String,
        generic_args: Option<Box<Node>>,
    },
    Protocol {
        name: String,
        module: String,
    },
    Extension {
        extended: Box<Node>,
        module: String,
    },
    TypeAlias {
        name: String,
        module: String,
        underlying: Option<Box<Node>>,
    },
    Actor {
        name: String,
        module: String,
    },
    DistributedActor {
        name: String,
        module: String,
    },
    /// Catch-all for other nominal types (e.g. opaque types).
    OtherNominalType {
        name: String,
        module: String,
    },

    // ---- Functions ----
    Function {
        name: String,
        context: Option<Box<Node>>,
        params: Option<Box<Node>>,
        returns: Option<Box<Node>>,
    },
    Constructor {
        context: Option<Box<Node>>,
        params: Option<Box<Node>>,
    },
    Deallocator {
        context: Option<Box<Node>>,
    },
    Destructor {
        context: Option<Box<Node>>,
    },
    /// A method looked up via the Objective-C or Swift method lookup function.
    MethodLookupFunction {
        class_name: String,
        method_name: String,
    },

    // ---- Variables / Properties ----
    Variable {
        name: String,
        context: Option<Box<Node>>,
        ty: Option<Box<Node>>,
    },
    Subscript {
        context: Option<Box<Node>>,
    },
    /// A stored property accessor (ProductTypeProperty).
    ProductTypeProperty,

    // ---- Property accessors ----
    GlobalGetter {
        context: Option<Box<Node>>,
    },
    Setter {
        context: Option<Box<Node>>,
    },
    /// Property observer: `willSet`.
    WillSet,
    /// Property observer: `didSet`.
    DidSet,
    /// `materializeForSet` accessor.
    MaterializeForSet,
    /// `modify` accessor.
    Modifying,
    /// Unsafe addressor (read-only).
    UnsafeAddressor,
    /// Unsafe mutable addressor (read-write).
    UnsafeMutableAddressor,

    // ---- Closures ----
    Closure {
        index: u32,
        context: Option<Box<Node>>,
    },
    ImplicitClosure {
        index: u32,
        context: Option<Box<Node>>,
    },
    AutoClosure(Box<Node>),

    // ---- Special function attributes ----
    Static {
        inner: Box<Node>,
    },
    LazyProperty {
        inner: Box<Node>,
    },
    /// KeyPath getter.
    KeyPathGetter {
        pattern: Option<Box<Node>>,
    },
    /// KeyPath setter.
    KeyPathSetter {
        pattern: Option<Box<Node>>,
    },
    /// Full key path accessor.
    KeyPath {
        getter: Option<Box<Node>>,
        setter: Option<Box<Node>>,
        equals: Option<Box<Node>>,
        hash: Option<Box<Node>>,
    },

    // ---- Operators ----
    InfixOperator {
        name: String,
    },
    PrefixOperator {
        name: String,
    },
    PostfixOperator {
        name: String,
    },

    // ---- Type annotations ----
    ThrowsAnnotation,
    ErrorType,
    Throwing(Box<Node>),
    AsyncAnnotation(Box<Node>),
    Sendable(Box<Node>),

    // ---- Ownership / memory management ----
    Owned(Box<Node>),
    Shared(Box<Node>),
    InOut(Box<Node>),
    Isolated(Box<Node>),
    NoEscape(Box<Node>),
    Differentially(Box<Node>),
    Weak,

    // ---- Function type forms ----
    CurriedFunctionType {
        params: Box<Node>,
        result: Box<Node>,
    },
    UncurriedFunctionType {
        params: Box<Node>,
        result: Box<Node>,
    },

    // ---- Types / Type structure ----
    Type(Box<Node>),
    TypeList {
        children: Vec<Node>,
    },
    Tuple {
        elements: Vec<Node>,
    },
    TupleElement {
        name: Option<String>,
        ty: Box<Node>,
    },
    ArgumentTuple {
        elements: Vec<Node>,
    },
    ReturnType {
        inner: Box<Node>,
    },
    BuiltinTypeName(String),

    // ---- Sugared types ----
    SugaredOptional(Box<Node>),
    SugaredArray(Box<Node>),
    SugaredDictionary {
        key: Box<Node>,
        value: Box<Node>,
    },
    SugaredParen(Box<Node>),

    // ---- Label lists ----
    LabelList {
        labels: Vec<String>,
    },

    // ---- Decl context ----
    DeclContext {
        inner: Box<Node>,
    },

    // ---- Generics ----
    DependentGenericConformance {
        ty: Box<Node>,
        protocol: Box<Node>,
    },
    DependentGenericType {
        ty: Box<Node>,
    },
    DependentMemberType {
        base: Box<Node>,
        member: String,
    },
    DependentGenericParamCount(u32),
    DependentGenericParamType {
        depth: u32,
        index: u32,
    },
    BoundGeneric {
        base: Box<Node>,
        args: Vec<Node>,
    },
    DependentAssociatedConformance {
        ty: Box<Node>,
        protocol: Box<Node>,
    },
    DefaultAssociatedConformance(Box<Node>),

    // ---- Metatypes ----
    Metatype(Box<Node>),
    ExistentialMetatype(Box<Node>),

    // ---- DynamicSelf ----
    DynamicallySelf,

    // ---- Protocol-related ----
    ProtocolList {
        protocols: Vec<Node>,
    },
    ProtocolConformance {
        ty: Box<Node>,
        protocol: Box<Node>,
    },
    ProtocolSelfConformance(Box<Node>),
    ProtocolWitnessTable {
        conforming_type: Box<Node>,
        protocol: Box<Node>,
    },
    GenericProtocolWitnessTable {
        conforming_type: Box<Node>,
        protocol: Box<Node>,
    },
    GenericTypeMetadata(Box<Node>),
    FullTypeMetadata(Box<Node>),
    TypeMetadata(Box<Node>),
    ReflectionMetadata(Box<Node>),
    NominalTypeDescriptor(Box<Node>),
    ProtocolDescriptor(Box<Node>),
    ProtocolConformanceDescriptor {
        ty: Box<Node>,
        protocol: Box<Node>,
    },
    AssociatedType {
        name: String,
        protocol: Box<Node>,
    },
    AssociatedConformance {
        ty: Box<Node>,
        protocol: Box<Node>,
    },
    WitnessMethod {
        protocol: Box<Node>,
        method: Box<Node>,
    },
    ValueWitness {
        ty: Box<Node>,
    },

    // ---- SIL (Swift Intermediate Language) ----
    SilFunction {
        name: String,
        context: Option<Box<Node>>,
    },
    SilThunk {
        inner: Option<Box<Node>>,
    },
    SilGlobalVariable,
    SilBox {
        ty: Box<Node>,
    },

    // ---- ObjC interop ----
    ObjCBlock(Box<Node>),
    ObjCAttribute,

    // ---- VTable / field metadata ----
    VTable {
        class: Box<Node>,
        entries: Vec<VTableEntry>,
    },
    FieldOffset {
        name: String,
        ty: Box<Node>,
        offset: u32,
    },

    // ---- Local / Private decl ----
    LocalDeclName {
        number: u32,
    },
    PrivateDeclName {
        file: String,
        identifier: String,
    },
    RelatedEntityDeclName {
        base: String,
        related: String,
    },

    // ---- Primitives ----
    Module(String),
    Identifier(String),
    Index(u32),
    UnknownIndex,
    Suffix(String),

    // ---- Initializer ----
    Initializer {
        context: Option<Box<Node>>,
    },

    // ---- Directness (final, open, etc.) ----
    Directness {
        kind: String,
        inner: Box<Node>,
    },

    // ---- Indirect result ----
    IndirectResult,

    /// A leaf we could not demangle further.
    Unknown(String),
}

/// An entry in a VTable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VTableEntry {
    /// The kind of entry (method, override, etc.).
    pub kind: String,
    /// The name of the method.
    pub name: Option<String>,
    /// The implementation address or mangled name.
    pub implementation: Option<String>,
}

// ---------------------------------------------------------------------------
// Swift calling convention
// ---------------------------------------------------------------------------

/// The Swift calling convention.
///
/// Swift uses a specific calling convention that differs from the
/// platform default. Understanding the calling convention is essential
/// for correct decompilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwiftCallingConvention {
    /// Standard Swift calling convention.
    /// - Self is passed as the last parameter
    /// - Error result is returned via implicit out-parameter
    Swift,
    /// Swift async calling convention.
    /// - Uses a continuation parameter
    SwiftAsync,
    /// Swift closure calling convention (thick function values).
    SwiftClosure,
    /// C-compatible function (marked `@convention(c)`).
    C,
    /// Block-compatible function (marked `@convention(block)`).
    Block,
    /// Thin function (no context, marked `@convention(thin)`).
    Thin,
}

impl SwiftCallingConvention {
    /// Determine the calling convention from a node tree context.
    pub fn from_node(node: &Node) -> Self {
        match node {
            Node::ObjCBlock(_) => SwiftCallingConvention::Block,
            Node::AsyncAnnotation(_) => SwiftCallingConvention::SwiftAsync,
            Node::AutoClosure(_) => SwiftCallingConvention::SwiftClosure,
            _ => SwiftCallingConvention::Swift,
        }
    }

    /// Return the human-readable name of this calling convention.
    pub fn name(&self) -> &'static str {
        match self {
            SwiftCallingConvention::Swift => "swiftcall",
            SwiftCallingConvention::SwiftAsync => "swiftasynccall",
            SwiftCallingConvention::SwiftClosure => "swiftclosurecall",
            SwiftCallingConvention::C => "c",
            SwiftCallingConvention::Block => "block",
            SwiftCallingConvention::Thin => "thin",
        }
    }

    /// Return the number of implicit parameters this convention uses.
    pub fn implicit_param_count(&self) -> usize {
        match self {
            SwiftCallingConvention::Swift => 1,        // self
            SwiftCallingConvention::SwiftAsync => 2,   // self + continuation
            SwiftCallingConvention::SwiftClosure => 1, // context
            SwiftCallingConvention::C => 0,
            SwiftCallingConvention::Block => 1, // block literal
            SwiftCallingConvention::Thin => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Swift type metadata structure
// ---------------------------------------------------------------------------

/// Represents parsed Swift type metadata as emitted by the Swift runtime.
///
/// The Swift runtime embeds type metadata in the binary's data sections.
/// This metadata is used for dynamic casting, generics, reflection, and
/// protocol conformance checks.
#[derive(Debug, Clone)]
pub struct SwiftTypeMetadata {
    /// The kind of metadata record.
    pub kind: MetadataKind,
    /// The address (VA) where this metadata record is located.
    pub address: u64,
    /// Size in bytes of the metadata record.
    pub size: usize,
    /// The mangled type name (can be demangled).
    pub mangled_name: Option<String>,
    /// If the name was successfully demangled, the result.
    pub demangled_name: Option<String>,
    /// The nominal type descriptor pointer.
    pub nominal_type_descriptor: Option<u64>,
    /// Number of generic parameters.
    pub generic_param_count: u32,
    /// The value witness table pointer.
    pub value_witness_table: Option<u64>,
    /// Protocol conformance descriptors.
    pub protocol_conformances: Vec<u64>,
    /// Parent type metadata (for nested types).
    pub parent: Option<u64>,
}

/// Kinds of Swift type metadata records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataKind {
    /// A class metadata record.
    Class,
    /// A struct metadata record.
    Struct,
    /// An enum metadata record.
    Enum,
    /// An optional type metadata record.
    Optional,
    /// An opaque/opaque existential type.
    Opaque,
    /// A tuple type.
    Tuple,
    /// A function type.
    Function,
    /// An existential type (protocol composition).
    Existential,
    /// A metatype.
    Metatype,
    /// A heap-local (box) type.
    HeapLocal,
    /// An error type.
    ErrorType,
    /// Foreign type (C / ObjC interop).
    Foreign,
    /// Unknown / unparsable.
    Unknown(u32),
}

impl SwiftTypeMetadata {
    /// Create an empty type metadata record at the given address.
    pub fn new(address: u64, kind: MetadataKind) -> Self {
        SwiftTypeMetadata {
            kind,
            address,
            size: 0,
            mangled_name: None,
            demangled_name: None,
            nominal_type_descriptor: None,
            generic_param_count: 0,
            value_witness_table: None,
            protocol_conformances: Vec::new(),
            parent: None,
        }
    }

    /// Attempt to demangle the associated name.
    pub fn demangle_name(&mut self) {
        if let Some(ref mangled) = self.mangled_name {
            self.demangled_name = Some(demangle_or_original(mangled));
        }
    }

    /// Return a human-readable summary of this metadata record.
    pub fn summary(&self) -> String {
        let kind_str = match &self.kind {
            MetadataKind::Class => "class",
            MetadataKind::Struct => "struct",
            MetadataKind::Enum => "enum",
            MetadataKind::Optional => "optional",
            MetadataKind::Opaque => "opaque",
            MetadataKind::Tuple => "tuple",
            MetadataKind::Function => "function",
            MetadataKind::Existential => "existential",
            MetadataKind::Metatype => "metatype",
            MetadataKind::HeapLocal => "box",
            MetadataKind::ErrorType => "error",
            MetadataKind::Foreign => "foreign",
            MetadataKind::Unknown(n) => return format!("unknown_metadata_kind({n})"),
        };
        let name = self
            .demangled_name
            .as_deref()
            .or(self.mangled_name.as_deref())
            .unwrap_or("<unnamed>");
        format!("{kind_str} {name} @ {:#x}", self.address)
    }
}

/// A parsed Swift type metadata section from a binary.
#[derive(Debug, Clone, Default)]
pub struct SwiftMetadataSection {
    /// All type metadata records found.
    pub type_metadata: Vec<SwiftTypeMetadata>,
    /// All protocol conformance records.
    pub protocol_conformances: Vec<ProtocolConformanceRecord>,
    /// All protocol descriptor records.
    pub protocol_descriptors: Vec<ProtocolDescriptorRecord>,
    /// Reflection string table entries.
    pub reflection_strings: Vec<(u64, String)>,
    /// Field metadata records.
    pub field_metadata: Vec<FieldMetadataRecord>,
}

/// A protocol conformance descriptor record.
#[derive(Debug, Clone)]
pub struct ProtocolConformanceRecord {
    /// Address of the conformance descriptor.
    pub address: u64,
    /// The protocol being conformed to (descriptor pointer).
    pub protocol_descriptor: u64,
    /// The conforming type (nominal type descriptor pointer).
    pub nominal_type_descriptor: Option<u64>,
    /// The witness table pointer.
    pub witness_table: Option<u64>,
    /// Flags.
    pub flags: u32,
}

/// A protocol descriptor record.
#[derive(Debug, Clone)]
pub struct ProtocolDescriptorRecord {
    /// Address of the protocol descriptor.
    pub address: u64,
    /// Mangled name of the protocol.
    pub mangled_name: Option<String>,
    /// Number of requirements.
    pub num_requirements: u32,
    /// Associated protocol names.
    pub associated_protocols: Vec<String>,
}

/// A field metadata record (for struct/class layout).
#[derive(Debug, Clone)]
pub struct FieldMetadataRecord {
    /// Address of the field descriptor.
    pub address: u64,
    /// Mangled type name this field belongs to.
    pub mangled_type_name: Option<String>,
    /// Number of fields.
    pub num_fields: u32,
    /// Field offsets and types.
    pub fields: Vec<FieldRecord>,
}

// Note: FieldRecord is defined below in the Binary Format Structures section.

// ---------------------------------------------------------------------------
// Parser state
// ---------------------------------------------------------------------------

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &str {
        &self.input[self.pos..]
    }

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    /// Read a natural number using Swift's compressed integer encoding.
    ///
    /// Encoding: a sequence of decimal digits optionally terminated by
    /// an underscore. Digits are: 0-9 only.
    fn read_natural(&mut self) -> Result<u32, DemangleError> {
        let mut value: u32 = 0;
        let mut found = false;
        while let Some(c) = self.peek() {
            if c == '_' {
                self.pos += 1;
                return if found { Ok(value) } else { Ok(0) };
            }
            let digit = match c {
                '0'..='9' => c as u32 - b'0' as u32,
                _ => {
                    if found {
                        return Ok(value);
                    }
                    return Err(DemangleError::InvalidEncoding(format!(
                        "expected decimal digit, got '{c}'"
                    )));
                }
            };
            self.pos += c.len_utf8();
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit))
                .ok_or_else(|| DemangleError::InvalidEncoding("natural number overflow".into()))?;
            found = true;
        }
        if found {
            Ok(value)
        } else {
            Err(DemangleError::UnexpectedEnd)
        }
    }

    /// Read an identifier: a natural number giving the byte-length followed
    /// by that many UTF-8 bytes. Length prefix is 0-9 only (Swift format).
    fn read_identifier(&mut self) -> Result<String, DemangleError> {
        if let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                let len = self.read_natural()? as usize;
                if self.pos + len > self.input.len() {
                    return Err(DemangleError::UnexpectedEnd);
                }
                let s = self.input[self.pos..self.pos + len].to_string();
                self.pos += len;
                return Ok(s);
            }
        }
        Err(DemangleError::InvalidEncoding(
            "expected identifier length prefix".into(),
        ))
    }

    /// Read a module identifier (may omit the 'u' prefix in some contexts).
    fn read_module(&mut self) -> Result<String, DemangleError> {
        if self.peek() == Some('u') {
            self.advance();
            self.read_identifier()
        } else if let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.read_identifier()
            } else {
                Ok(String::new())
            }
        } else {
            Ok(String::new())
        }
    }

    /// Peek at the next operator character(s) to determine what node to parse.
    fn peek_operator(&self) -> Option<String> {
        let rem = self.remaining();
        if rem.is_empty() {
            return None;
        }
        // Multi-character operators sorted by length (longest first)
        let multi_ops: &[&str] = &[
            "ySd", "ySa", "ySp", "ySo", "Sb", "Sd", "Sf", "Si", "Su", "SV", "Ss", "Sp", "Sa", "So",
            "St", "SB", "yy", "yc", "yS", "yF", "yG", "yK", "yX", "yY", "ya", "yd", "ye", "yh",
            "HD", "Hn", "Ho", "Hr", "Hw", "He", "Ac", "Da", "Gd", "Ge", "Mc", "Mg", "Mp", "Mm",
            "Mr", "Mf", "Ma", "MAC", "MD", "WP", "WG", "yB", "WV", "Wf", "WM", "Wv", "Ww", "Wm",
            "Ll", "Xw", "iR", "NE", "fc", "fd", "fe", "fi", "fm", "fg", "fs", "fM", "fu", "fU",
            "fk", "op", "oP", "SS", "Hd", "Ps", "PC", "XD", "FT", "An", "Aa",
        ];
        for op in multi_ops {
            if rem.starts_with(op) {
                return Some(op.to_string());
            }
        }
        rem.chars().next().map(|c| c.to_string())
    }
}

// ---------------------------------------------------------------------------
// Node parsing
// ---------------------------------------------------------------------------

impl Parser<'_> {
    /// Parse a named type (class/struct/enum/protocol etc.) with module prefix.
    fn parse_named_type<F>(&mut self, constructor: F) -> Result<Node, DemangleError>
    where
        F: FnOnce(String, String) -> Node,
    {
        let saved = self.pos;
        let first = self.read_module()?;
        match self.read_identifier() {
            Ok(name) => Ok(constructor(name, first)),
            Err(_) => {
                // first was actually the name, not the module
                self.pos = saved;
                let name = self.read_identifier()?;
                Ok(constructor(name, String::new()))
            }
        }
    }

    /// Parse a single node from the current position.
    fn parse_node(&mut self) -> Result<Node, DemangleError> {
        if self.at_end() {
            return Err(DemangleError::UnexpectedEnd);
        }

        let op = self.peek_operator().unwrap_or_default();

        // Advance past the operator
        for _ in 0..op.len() {
            self.advance();
        }

        match op.as_str() {
            // ---- Module ----
            "u" => {
                let name = self.read_identifier()?;
                Ok(Node::Module(name))
            }

            // ---- Named types ----
            "V" => self.parse_named_type(|name, module| Node::Structure {
                name,
                module,
                generic_args: None,
            }),
            "C" => self.parse_named_type(|name, module| Node::Class {
                name,
                module,
                generic_args: None,
            }),
            "O" => self.parse_named_type(|name, module| Node::Enum {
                name,
                module,
                generic_args: None,
            }),
            "P" => self.parse_named_type(|name, module| Node::Protocol { name, module }),
            "a" => self.parse_named_type(|name, module| Node::TypeAlias {
                name,
                module,
                underlying: None,
            }),
            "Ac" => self.parse_named_type(|name, module| Node::Actor { name, module }),
            "Da" => self.parse_named_type(|name, module| Node::DistributedActor { name, module }),

            // ---- Function ----
            "f" => self.parse_function(),
            "F" => self.parse_sil_function(),

            // ---- Variable / subscript ----
            "v" => self.parse_variable(),
            "i" => self.parse_subscript(),
            "S" => {
                let inner = self.parse_node()?;
                Ok(Node::Static {
                    inner: Box::new(inner),
                })
            }

            // ---- Closures ----
            "c" => {
                let index = self.read_natural()?;
                Ok(Node::ImplicitClosure {
                    index,
                    context: None,
                })
            }
            "q" => {
                let index = self.read_natural()?;
                Ok(Node::Closure {
                    index,
                    context: None,
                })
            }

            // ---- Auto closure ----
            "y" => {
                if !self.at_end() {
                    match self.peek() {
                        Some('c') | Some('S') | Some('F') | Some('G') | Some('K') => {
                            let inner = self.parse_node()?;
                            Ok(Node::AutoClosure(Box::new(inner)))
                        }
                        _ => Ok(Node::AutoClosure(Box::new(Node::Unknown("?".into())))),
                    }
                } else {
                    Ok(Node::AutoClosure(Box::new(Node::Unknown("?".into()))))
                }
            }

            // ---- Extension ----
            "E" => {
                let module = self.read_module()?;
                let extended = self.parse_node()?;
                Ok(Node::Extension {
                    extended: Box::new(extended),
                    module,
                })
            }

            // ---- Type list ----
            "D" => self.parse_typelist(),

            // ---- Tuple ----
            "T" => self.parse_tuple(),

            // ---- Label list ----
            "l" => self.parse_labellist(),

            // ---- Return type ----
            "R" => {
                let inner = self.parse_node()?;
                Ok(Node::ReturnType {
                    inner: Box::new(inner),
                })
            }

            // ---- Builtin types ----
            "Sb" => Ok(Node::BuiltinTypeName("Bool".into())),
            "Sd" => Ok(Node::BuiltinTypeName("Float64".into())),
            "Sf" => Ok(Node::BuiltinTypeName("Float32".into())),
            "Si" => Ok(Node::BuiltinTypeName("Int".into())),
            "Su" => Ok(Node::BuiltinTypeName("UInt".into())),
            "SV" => Ok(Node::BuiltinTypeName("UnsafeRawPointer".into())),
            "Ss" => Ok(Node::BuiltinTypeName("String".into())),
            "Sp" => Ok(Node::BuiltinTypeName("UnsafePointer".into())),
            "Sa" => Ok(Node::BuiltinTypeName("Array".into())),
            "So" => Ok(Node::BuiltinTypeName("Object".into())),
            "St" => Ok(Node::BuiltinTypeName("Tuple".into())),
            "SB" => Ok(Node::BuiltinTypeName("BinaryFloatingPoint".into())),

            // ---- Sugared types ----
            "ySd" => {
                let key = self.parse_node().unwrap_or(Node::Unknown("?".into()));
                let value = self.parse_node()?;
                Ok(Node::SugaredDictionary {
                    key: Box::new(key),
                    value: Box::new(value),
                })
            }
            "ySa" => {
                let inner = self.parse_node()?;
                Ok(Node::SugaredArray(Box::new(inner)))
            }
            "ySp" => {
                let inner = self.parse_node()?;
                Ok(Node::SugaredParen(Box::new(inner)))
            }
            "ySo" => {
                let inner = self.parse_node()?;
                Ok(Node::SugaredOptional(Box::new(inner)))
            }

            // ---- Curried function ----
            "yc" => {
                let params = self.parse_node()?;
                let result = self.parse_node()?;
                Ok(Node::CurriedFunctionType {
                    params: Box::new(params),
                    result: Box::new(result),
                })
            }

            // ---- Uncurried function ----
            "yS" => {
                let params = self.parse_node()?;
                let result = self.parse_node()?;
                Ok(Node::UncurriedFunctionType {
                    params: Box::new(params),
                    result: Box::new(result),
                })
            }

            // ---- Throwing function ----
            "yK" => {
                let inner = self.parse_node()?;
                Ok(Node::Throwing(Box::new(inner)))
            }

            // ---- ObjC attribute ----
            "yX" => Ok(Node::ObjCAttribute),

            // ---- Async ----
            "yY" => {
                let inner = self.parse_node()?;
                Ok(Node::AsyncAnnotation(Box::new(inner)))
            }

            // ---- ObjC block ----
            "yB" => {
                let inner = self.parse_node()?;
                Ok(Node::ObjCBlock(Box::new(inner)))
            }

            // ---- Metatype ----
            "M" => {
                let inner = self.parse_node()?;
                Ok(Node::Metatype(Box::new(inner)))
            }

            // ---- Existential metatype ----
            "X" => {
                let inner = self.parse_node()?;
                Ok(Node::ExistentialMetatype(Box::new(inner)))
            }

            // ---- Throws / Error ----
            "K" => Ok(Node::ThrowsAnnotation),
            "m" => Ok(Node::ErrorType),

            // ---- Ownership modifiers ----
            "n" => {
                let inner = self.parse_node()?;
                Ok(Node::Owned(Box::new(inner)))
            }
            "z" => {
                let inner = self.parse_node()?;
                Ok(Node::InOut(Box::new(inner)))
            }
            "h" => {
                let inner = self.parse_node()?;
                Ok(Node::Shared(Box::new(inner)))
            }
            "e" => {
                let inner = self.parse_node()?;
                Ok(Node::Isolated(Box::new(inner)))
            }
            "w" => {
                let inner = self.parse_node()?;
                Ok(Node::Differentially(Box::new(inner)))
            }

            // ---- Protocol-related ----
            "WP" => {
                let conforming = self.parse_node()?;
                let protocol = self.parse_node()?;
                Ok(Node::ProtocolWitnessTable {
                    conforming_type: Box::new(conforming),
                    protocol: Box::new(protocol),
                })
            }
            "WG" => {
                let conforming = self.parse_node()?;
                let protocol = self.parse_node()?;
                Ok(Node::GenericProtocolWitnessTable {
                    conforming_type: Box::new(conforming),
                    protocol: Box::new(protocol),
                })
            }

            // ---- SIL ----
            "G" => Ok(Node::SilGlobalVariable),

            // ---- Local / private decl names ----
            "L" => {
                let num = self.read_natural()?;
                Ok(Node::LocalDeclName { number: num })
            }

            // ---- Dependent generic ----
            "Gd" => {
                let ty = self.parse_node()?;
                let protocol = self.parse_node()?;
                Ok(Node::DependentGenericConformance {
                    ty: Box::new(ty),
                    protocol: Box::new(protocol),
                })
            }
            "Ge" => {
                let ty = self.parse_node()?;
                Ok(Node::DependentGenericType { ty: Box::new(ty) })
            }

            // ---- Number / Index / Identifier ----
            "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" => {
                self.pos -= op.len();
                // Check if this is a length-prefixed identifier (Swift mangling)
                // vs a bare number. If the next token after the digits is more
                // alphanumeric content, it's an identifier.
                let saved = self.pos;
                // Read digits to check if this is an identifier prefix
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() { self.advance(); } else { break; }
                }
                let is_identifier = !self.at_end() && self.peek().map_or(false, |c| c.is_ascii_alphabetic());
                self.pos = saved;
                if is_identifier {
                    // It's an identifier: the digits are the length prefix
                    let name = self.read_identifier()?;
                    // After reading the identifier, check for a type operator
                    // or treat it as a function name
                    let context = match self.peek() {
                        Some('V') => {
                            self.advance();
                            let module = self.read_module().unwrap_or_default();
                            Some(Box::new(Node::Structure { name: name.clone(), module, generic_args: None }))
                        }
                        Some('C') => {
                            self.advance();
                            let module = self.read_module().unwrap_or_default();
                            Some(Box::new(Node::Class { name: name.clone(), module, generic_args: None }))
                        }
                        Some('O') => {
                            self.advance();
                            let module = self.read_module().unwrap_or_default();
                            Some(Box::new(Node::Enum { name: name.clone(), module, generic_args: None }))
                        }
                        _ => None,
                    };
                    if context.is_some() {
                        // The identifier was a type name; the function name comes next
                        let fn_name = self.read_identifier().unwrap_or_default();
                        Ok(Node::Function { name: fn_name, context, params: None, returns: None })
                    } else {
                        Ok(Node::Function { name, context: None, params: None, returns: None })
                    }
                } else {
                    // Just a number
                    self.pos = saved;
                    let idx = self.read_natural()?;
                    Ok(Node::Index(idx))
                }
            }

            // ---- AllocStack / AnonymousContext ----
            "Aa" => Ok(Node::AllocStack),
            "An" => Ok(Node::AnonymousContext),

            // ---- Constructor / Deallocator / Destructor ----
            "fc" => self.parse_constructor(),
            "fd" => self.parse_deallocator(),
            "fe" => self.parse_destructor(),
            "fi" => self.parse_initializer(),
            "fm" => self.parse_method_lookup(),
            "fg" => self.parse_global_getter(),
            "fs" => self.parse_setter(),
            "fM" => self.parse_modifying(),
            "fu" => Ok(Node::UnsafeAddressor),
            "fU" => Ok(Node::UnsafeMutableAddressor),

            // ---- KeyPath ----
            "fk" => self.parse_keypath(),

            // ---- BoundGeneric ----
            "b" => self.parse_bound_generic(),

            // ---- Operators ----
            "o" => self.parse_operator(),
            "op" => self.parse_postfix_operator(),
            "oP" => self.parse_prefix_operator(),

            // ---- Product type property ----
            "p" => Ok(Node::ProductTypeProperty),

            // ---- Suffix ----
            "SS" => {
                let suffix = self.read_identifier().unwrap_or_default();
                Ok(Node::Suffix(suffix))
            }

            // ---- Directness ----
            "Hd" => {
                let inner = self.parse_node()?;
                Ok(Node::Directness {
                    kind: "direct".into(),
                    inner: Box::new(inner),
                })
            }

            // ---- VTable ----
            "WV" => {
                let class_node = self.parse_node()?;
                Ok(Node::VTable {
                    class: Box::new(class_node),
                    entries: Vec::new(),
                })
            }

            // ---- Field offset ----
            "Wf" => {
                let name = self.read_identifier()?;
                let ty = self.parse_node()?;
                Ok(Node::FieldOffset {
                    name,
                    ty: Box::new(ty),
                    offset: 0,
                })
            }

            // ---- DidSet / WillSet ----
            "Wv" => Ok(Node::DidSet),
            "Ww" => Ok(Node::WillSet),
            "Wm" => Ok(Node::MaterializeForSet),

            // ---- Witness method ----
            "WM" => {
                let protocol = self.parse_node()?;
                let method = self.parse_node()?;
                Ok(Node::WitnessMethod {
                    protocol: Box::new(protocol),
                    method: Box::new(method),
                })
            }

            // ---- Lazy property ----
            "Ll" => {
                let inner = self.parse_node()?;
                Ok(Node::LazyProperty {
                    inner: Box::new(inner),
                })
            }

            // ---- Weak ----
            "Xw" => Ok(Node::Weak),

            // ---- IndirectResult ----
            "iR" => Ok(Node::IndirectResult),

            // ---- SIL Thunk ----
            "FT" => Ok(Node::SilThunk { inner: None }),

            // ---- DynamicSelf ----
            "XD" => Ok(Node::DynamicallySelf),

            // ---- NoEscape ----
            "NE" => {
                let inner = self.parse_node()?;
                Ok(Node::NoEscape(Box::new(inner)))
            }

            // ---- Metadata records ----
            "Mp" => {
                let inner = self.parse_node()?;
                Ok(Node::ProtocolDescriptor(Box::new(inner)))
            }
            "Mn" => {
                let inner = self.parse_node()?;
                Ok(Node::NominalTypeDescriptor(Box::new(inner)))
            }
            "Mc" => {
                let ty = self.parse_node()?;
                let protocol = self.parse_node()?;
                Ok(Node::ProtocolConformance {
                    ty: Box::new(ty),
                    protocol: Box::new(protocol),
                })
            }
            "Mg" => {
                let inner = self.parse_node()?;
                Ok(Node::GenericTypeMetadata(Box::new(inner)))
            }
            "Mm" => {
                let inner = self.parse_node()?;
                Ok(Node::TypeMetadata(Box::new(inner)))
            }
            "Mf" => {
                let inner = self.parse_node()?;
                Ok(Node::FullTypeMetadata(Box::new(inner)))
            }
            "Mr" => {
                let inner = self.parse_node()?;
                Ok(Node::ReflectionMetadata(Box::new(inner)))
            }
            "Ma" => {
                let name = self.read_identifier()?;
                let protocol = self.parse_node()?;
                Ok(Node::AssociatedType {
                    name,
                    protocol: Box::new(protocol),
                })
            }
            "MAC" => {
                let ty = self.parse_node()?;
                let protocol = self.parse_node()?;
                Ok(Node::AssociatedConformance {
                    ty: Box::new(ty),
                    protocol: Box::new(protocol),
                })
            }
            "MD" => {
                let inner = self.parse_node()?;
                Ok(Node::DefaultAssociatedConformance(Box::new(inner)))
            }
            "me" => {
                let ty = self.parse_node()?;
                let protocol = self.parse_node()?;
                Ok(Node::DependentAssociatedConformance {
                    ty: Box::new(ty),
                    protocol: Box::new(protocol),
                })
            }
            "Ps" => {
                let inner = self.parse_node()?;
                Ok(Node::ProtocolSelfConformance(Box::new(inner)))
            }
            "PC" => {
                let ty = self.parse_node()?;
                let protocol = self.parse_node()?;
                Ok(Node::ProtocolConformanceDescriptor {
                    ty: Box::new(ty),
                    protocol: Box::new(protocol),
                })
            }

            // ---- Catch-all: treat as unknown ----
            _ => Ok(Node::Unknown(op.clone())),
        }
    }

    fn parse_function(&mut self) -> Result<Node, DemangleError> {
        let saved = self.pos;

        let context = match self.peek() {
            Some('V' | 'C' | 'O' | 'P' | 'E' | 'a' | 'A') => Some(self.parse_node()?),
            Some('u') => {
                // Look ahead: read module, then check if followed by a type
                let m = self.read_module()?;
                match self.peek() {
                    Some('V' | 'C' | 'O' | 'P' | 'E' | 'a') => {
                        self.pos = saved;
                        Some(self.parse_node()?)
                    }
                    _ => {
                        self.pos = saved + 1 + m.len();
                        None
                    }
                }
            }
            _ => None,
        };

        let name = if self.at_end() {
            return Err(DemangleError::UnexpectedEnd);
        } else if let Some(c) = self.peek() {
            if c.is_ascii_digit() || c.is_ascii_uppercase() {
                self.read_identifier()?
            } else {
                self.read_identifier()?
            }
        } else {
            return Err(DemangleError::UnexpectedEnd);
        };

        let params = match self.peek() {
            Some(c) if c != 'R' && c != 'y' && c != 'K' && !self.at_end() => self.parse_node().ok(),
            _ => None,
        };

        let returns = match self.peek() {
            Some('R') => {
                self.advance();
                self.parse_node().ok()
            }
            _ => None,
        };

        Ok(Node::Function {
            name,
            context: context.map(Box::new),
            params: params.map(Box::new),
            returns: returns.map(Box::new),
        })
    }

    fn parse_variable(&mut self) -> Result<Node, DemangleError> {
        let saved = self.pos;
        let context = match self.peek() {
            Some('V' | 'C' | 'O' | 'P' | 'E' | 'a') => Some(self.parse_node()?),
            Some('u') => {
                let m = self.read_module()?;
                match self.peek() {
                    Some('V' | 'C' | 'O' | 'P' | 'E' | 'a') => {
                        self.pos = saved;
                        Some(self.parse_node()?)
                    }
                    _ => {
                        self.pos = saved + 1 + m.len();
                        None
                    }
                }
            }
            _ => None,
        };

        let name = if self.at_end() {
            return Err(DemangleError::UnexpectedEnd);
        } else {
            self.read_identifier()?
        };

        let ty = self.parse_node().ok();

        Ok(Node::Variable {
            name,
            context: context.map(Box::new),
            ty: ty.map(Box::new),
        })
    }

    fn parse_subscript(&mut self) -> Result<Node, DemangleError> {
        let saved = self.pos;
        let context = match self.peek() {
            Some('V' | 'C' | 'O' | 'P' | 'E' | 'a') => Some(self.parse_node()?),
            Some('u') => {
                let m = self.read_module()?;
                match self.peek() {
                    Some('V' | 'C' | 'O' | 'P' | 'E' | 'a') => {
                        self.pos = saved;
                        Some(self.parse_node()?)
                    }
                    _ => {
                        self.pos = saved + 1 + m.len();
                        None
                    }
                }
            }
            _ => None,
        };
        Ok(Node::Subscript {
            context: context.map(Box::new),
        })
    }

    fn parse_sil_function(&mut self) -> Result<Node, DemangleError> {
        let name = self.read_identifier()?;
        Ok(Node::SilFunction {
            name,
            context: None,
        })
    }

    fn parse_constructor(&mut self) -> Result<Node, DemangleError> {
        let context = matches!(self.peek(), Some('V' | 'C' | 'O' | 'P' | 'E' | 'a'))
            .then(|| self.parse_node())
            .transpose()?;
        let params = self.parse_node().ok();
        Ok(Node::Constructor {
            context: context.map(Box::new),
            params: params.map(Box::new),
        })
    }

    fn parse_deallocator(&mut self) -> Result<Node, DemangleError> {
        let context = matches!(self.peek(), Some('V' | 'C' | 'O' | 'P' | 'E' | 'a'))
            .then(|| self.parse_node())
            .transpose()?;
        Ok(Node::Deallocator {
            context: context.map(Box::new),
        })
    }

    fn parse_destructor(&mut self) -> Result<Node, DemangleError> {
        let context = matches!(self.peek(), Some('V' | 'C' | 'O' | 'P' | 'E' | 'a'))
            .then(|| self.parse_node())
            .transpose()?;
        Ok(Node::Destructor {
            context: context.map(Box::new),
        })
    }

    fn parse_initializer(&mut self) -> Result<Node, DemangleError> {
        let context = matches!(self.peek(), Some('V' | 'C' | 'O' | 'P' | 'E' | 'a'))
            .then(|| self.parse_node())
            .transpose()?;
        Ok(Node::Initializer {
            context: context.map(Box::new),
        })
    }

    fn parse_method_lookup(&mut self) -> Result<Node, DemangleError> {
        let class_name = self.read_identifier().unwrap_or_default();
        let method_name = self.read_identifier().unwrap_or_default();
        Ok(Node::MethodLookupFunction {
            class_name,
            method_name,
        })
    }

    fn parse_global_getter(&mut self) -> Result<Node, DemangleError> {
        let context = matches!(self.peek(), Some('V' | 'C' | 'O' | 'P' | 'E' | 'a'))
            .then(|| self.parse_node())
            .transpose()?;
        Ok(Node::GlobalGetter {
            context: context.map(Box::new),
        })
    }

    fn parse_setter(&mut self) -> Result<Node, DemangleError> {
        let context = matches!(self.peek(), Some('V' | 'C' | 'O' | 'P' | 'E' | 'a'))
            .then(|| self.parse_node())
            .transpose()?;
        Ok(Node::Setter {
            context: context.map(Box::new),
        })
    }

    fn parse_modifying(&mut self) -> Result<Node, DemangleError> {
        Ok(Node::Modifying)
    }

    fn parse_keypath(&mut self) -> Result<Node, DemangleError> {
        let getter = self.parse_node().ok().map(Box::new);
        let setter = self.parse_node().ok().map(Box::new);
        let equals = self.parse_node().ok().map(Box::new);
        let hash = self.parse_node().ok().map(Box::new);
        Ok(Node::KeyPath {
            getter,
            setter,
            equals,
            hash,
        })
    }

    fn parse_bound_generic(&mut self) -> Result<Node, DemangleError> {
        let base = self.parse_node()?;
        let count = self.read_natural()? as usize;
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            if self.at_end() {
                break;
            }
            args.push(self.parse_node()?);
        }
        Ok(Node::BoundGeneric {
            base: Box::new(base),
            args,
        })
    }

    fn parse_operator(&mut self) -> Result<Node, DemangleError> {
        let name = self.read_identifier().unwrap_or_default();
        Ok(Node::InfixOperator { name })
    }

    fn parse_postfix_operator(&mut self) -> Result<Node, DemangleError> {
        let name = self.read_identifier().unwrap_or_default();
        Ok(Node::PostfixOperator { name })
    }

    fn parse_prefix_operator(&mut self) -> Result<Node, DemangleError> {
        let name = self.read_identifier().unwrap_or_default();
        Ok(Node::PrefixOperator { name })
    }

    fn parse_typelist(&mut self) -> Result<Node, DemangleError> {
        let count = self.read_natural()? as usize;
        let mut children = Vec::with_capacity(count);
        for _ in 0..count {
            if self.at_end() {
                break;
            }
            children.push(self.parse_node()?);
        }
        Ok(Node::TypeList { children })
    }

    fn parse_tuple(&mut self) -> Result<Node, DemangleError> {
        let count = self.read_natural()? as usize;
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            if self.at_end() {
                break;
            }
            let label = if let Some(c) = self.peek() {
                if c.is_ascii_digit() || c.is_ascii_uppercase() {
                    self.read_identifier().ok()
                } else {
                    None
                }
            } else {
                None
            };
            let ty = self.parse_node()?;
            elements.push(Node::TupleElement {
                name: label,
                ty: Box::new(ty),
            });
        }
        Ok(Node::Tuple { elements })
    }

    fn parse_labellist(&mut self) -> Result<Node, DemangleError> {
        let count = self.read_natural()? as usize;
        let mut labels = Vec::with_capacity(count);
        for _ in 0..count {
            if self.at_end() {
                break;
            }
            let lbl = self.read_identifier()?;
            labels.push(lbl);
        }
        Ok(Node::LabelList { labels })
    }
}

// ---------------------------------------------------------------------------
// Top-level demangling entry point
// ---------------------------------------------------------------------------

/// Result of identifying the mangling scheme.
enum MangleKind {
    /// `$s` or `$S` -- Swift 4+ modern mangling.
    Modern,
    /// `_T0` -- Swift 3.x mangling.
    Swift3,
    /// `__T` or `_Tt` -- Swift 2.x / early Swift mangling.
    Swift2,
}

/// Detect the mangling scheme.
fn detect_mangle_kind(input: &str) -> Option<(MangleKind, usize)> {
    if input.starts_with("$s") || input.starts_with("$S") {
        Some((MangleKind::Modern, 2))
    } else if input.starts_with("_T0") {
        Some((MangleKind::Swift3, 3))
    } else if input.starts_with("__T") {
        Some((MangleKind::Swift2, 3))
    } else if input.starts_with("_Tt") {
        Some((MangleKind::Swift2, 3))
    } else if input.starts_with("_$s") || input.starts_with("_$S") {
        Some((MangleKind::Modern, 3))
    } else {
        None
    }
}

/// Demangle a Swift mangled name.
///
/// # Arguments
///
/// * `mangled` - The mangled symbol name.
///
/// # Returns
///
/// A human-readable demangled name, or a `DemangleError`.
pub fn demangle(mangled: &str) -> Result<String, DemangleError> {
    if mangled.is_empty() {
        return Err(DemangleError::NotMangled);
    }

    // Handle leading underscore (ASM symbol prefix)
    let effective = if mangled.len() > 1
        && mangled.starts_with('_')
        && (mangled.as_bytes()[1] == b'$' || mangled.as_bytes()[1] == b'T')
    {
        &mangled[1..]
    } else {
        mangled
    };

    let (kind, offset) = detect_mangle_kind(effective).ok_or(DemangleError::NotMangled)?;

    let body = &effective[offset..];
    let mut parser = Parser::new(body);

    match kind {
        MangleKind::Modern => demangle_modern(&mut parser),
        MangleKind::Swift3 => demangle_swift3(&mut parser),
        MangleKind::Swift2 => demangle_swift2(&mut parser),
    }
}

/// Demangle Swift 4+ (modern) mangling.
fn demangle_modern(parser: &mut Parser) -> Result<String, DemangleError> {
    let module = parser.read_module()?;
    // After the module, the next token is either a named declaration
    // (V/C/O/P/E/a for type, f for function, etc.) or an identifier.
    // If we see a digit, it's the start of a length-prefixed identifier.
    let node = if let Some(c) = parser.peek() {
        if c.is_ascii_digit() {
            let name = parser.read_identifier()?;
            // Check if followed by a type operator (C/V/O/P/E/a)
            match parser.peek() {
                Some('C') => {
                    parser.advance();
                    // In modern Swift mangling, 'C' indicates a class type.
                    // The module + type name is the full qualified name.
                    // If there's a function after, it would be encoded separately.
                    Node::Class { name: name.clone(), module: module.clone(), generic_args: None }
                }
                Some('V') => {
                    parser.advance();
                    Node::Structure { name: name.clone(), module: module.clone(), generic_args: None }
                }
                Some('O') => {
                    parser.advance();
                    Node::Enum { name: name.clone(), module: module.clone(), generic_args: None }
                }
                _ => {
                    // Just a function in the module
                    let context = if !module.is_empty() {
                        Some(Box::new(Node::Module(module.clone())))
                    } else {
                        None
                    };
                    Node::Function { name, context, params: None, returns: None }
                }
            }
        } else {
            parser.parse_node()?
        }
    } else {
        return Err(DemangleError::UnexpectedEnd);
    };
    let mut result = String::new();
    let has_module = !module.is_empty();
    if has_module {
        result.push_str(&module);
        result.push('.');
    }
    // If we already rendered the module prefix, tell render_node to skip it
    render_node(&node, &mut result, RenderCtx { in_type: has_module });
    Ok(result)
}

/// Demangle Swift 3.x (`_T0`) mangling.
fn demangle_swift3(parser: &mut Parser) -> Result<String, DemangleError> {
    let module = parser.read_module()?;
    let node = parser.parse_node()?;
    let mut result = String::new();
    let has_module = !module.is_empty();
    if has_module {
        result.push_str(&module);
        result.push('.');
    }
    render_node(&node, &mut result, RenderCtx { in_type: has_module });
    Ok(result)
}

/// Demangle Swift 2.x (`_Tt` / `__T`) mangling.
fn demangle_swift2(parser: &mut Parser) -> Result<String, DemangleError> {
    let module = parser.read_module()?;
    let node = parser.parse_node()?;
    let mut result = String::new();
    let has_module = !module.is_empty();
    if has_module {
        result.push_str(&module);
        result.push('.');
    }
    render_node(&node, &mut result, RenderCtx { in_type: has_module });
    Ok(result)
}

// ---------------------------------------------------------------------------
// Rendering / pretty-printing
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct RenderCtx {
    /// True when we are inside a type context (Structure, Class, Enum).
    in_type: bool,
}

fn render_node(node: &Node, out: &mut String, ctx: RenderCtx) {
    match node {
        // ---- Declarations ----
        Node::Structure { name, module, .. } => {
            if !module.is_empty() && !ctx.in_type {
                out.push_str(module);
                out.push('.');
            }
            out.push_str(name);
        }
        Node::Class { name, module, .. } => {
            if !module.is_empty() && !ctx.in_type {
                out.push_str(module);
                out.push('.');
            }
            out.push_str(name);
        }
        Node::Enum { name, module, .. } => {
            if !module.is_empty() && !ctx.in_type {
                out.push_str(module);
                out.push('.');
            }
            out.push_str(name);
        }
        Node::Protocol { name, module } => {
            if !module.is_empty() && !ctx.in_type {
                out.push_str(module);
                out.push('.');
            }
            out.push_str(name);
        }
        Node::Extension { extended, module } => {
            if !module.is_empty() {
                out.push_str("(extension in ");
                out.push_str(module);
                out.push_str("): ");
            }
            render_node(extended, out, ctx);
        }
        Node::TypeAlias { name, .. } => {
            out.push_str(name);
        }
        Node::Actor { name, module } => {
            if !module.is_empty() {
                out.push_str(module);
                out.push('.');
            }
            out.push_str(name);
        }
        Node::DistributedActor { name, module } => {
            if !module.is_empty() {
                out.push_str(module);
                out.push('.');
            }
            out.push_str(name);
        }
        Node::OtherNominalType { name, module } => {
            if !module.is_empty() {
                out.push_str(module);
                out.push('.');
            }
            out.push('<');
            out.push_str(name);
            out.push('>');
        }

        // ---- Functions ----
        Node::Function {
            name,
            context,
            params,
            returns,
        } => {
            if let Some(ctx_node) = context {
                render_node(ctx_node, out, RenderCtx { in_type: true });
                out.push('.');
            }
            out.push_str(name);
            out.push('(');
            if let Some(p) = params {
                render_node(p, out, RenderCtx::default());
            }
            out.push(')');
            if let Some(r) = returns {
                out.push_str(" -> ");
                render_node(r, out, RenderCtx::default());
            }
        }
        Node::Constructor { context, params } => {
            if let Some(ctx_node) = context {
                render_node(ctx_node, out, RenderCtx { in_type: true });
                out.push('.');
            }
            out.push_str("init(");
            if let Some(p) = params {
                render_node(p, out, RenderCtx::default());
            }
            out.push(')');
        }
        Node::Deallocator { context } => {
            if let Some(ctx_node) = context {
                render_node(ctx_node, out, RenderCtx { in_type: true });
                out.push('.');
            }
            out.push_str("dealloc");
        }
        Node::Destructor { context } => {
            if let Some(ctx_node) = context {
                render_node(ctx_node, out, RenderCtx { in_type: true });
                out.push('.');
            }
            out.push_str("deinit");
        }
        Node::Initializer { context } => {
            if let Some(ctx_node) = context {
                render_node(ctx_node, out, RenderCtx { in_type: true });
                out.push('.');
            }
            out.push_str("init");
        }
        Node::MethodLookupFunction {
            class_name,
            method_name,
        } => {
            out.push_str(class_name);
            out.push('.');
            out.push_str(method_name);
        }

        // ---- Variables ----
        Node::Variable { name, context, ty } => {
            if let Some(ctx_node) = context {
                render_node(ctx_node, out, RenderCtx { in_type: true });
                out.push('.');
            }
            out.push_str(name);
            if let Some(t) = ty {
                out.push_str(" : ");
                render_node(t, out, RenderCtx::default());
            }
        }
        Node::Subscript { context } => {
            if let Some(ctx_node) = context {
                render_node(ctx_node, out, RenderCtx { in_type: true });
                out.push('.');
            }
            out.push_str("subscript");
        }
        Node::ProductTypeProperty => {
            out.push_str("(stored property)");
        }

        // ---- Accessors ----
        Node::GlobalGetter { context } => {
            if let Some(ctx_node) = context {
                render_node(ctx_node, out, RenderCtx { in_type: true });
                out.push('.');
            }
            out.push_str("(getter)");
        }
        Node::Setter { context } => {
            if let Some(ctx_node) = context {
                render_node(ctx_node, out, RenderCtx { in_type: true });
                out.push('.');
            }
            out.push_str("(setter)");
        }
        Node::WillSet => {
            out.push_str("willSet");
        }
        Node::DidSet => {
            out.push_str("didSet");
        }
        Node::MaterializeForSet => {
            out.push_str("materializeForSet");
        }
        Node::Modifying => {
            out.push_str("modify");
        }
        Node::UnsafeAddressor => {
            out.push_str("unsafeAddressor");
        }
        Node::UnsafeMutableAddressor => {
            out.push_str("unsafeMutableAddressor");
        }

        // ---- Closures ----
        Node::Closure { index, .. } => {
            write!(out, "closure #{index}").unwrap();
        }
        Node::ImplicitClosure { index, .. } => {
            write!(out, "implicit_closure #{index}").unwrap();
        }
        Node::AutoClosure(inner) => {
            out.push_str("@autoclosure ");
            render_node(inner, out, ctx);
        }

        // ---- Special function attributes ----
        Node::Static { inner } => {
            out.push_str("static ");
            render_node(inner, out, ctx);
        }
        Node::LazyProperty { inner } => {
            out.push_str("lazy ");
            render_node(inner, out, ctx);
        }
        Node::KeyPathGetter { .. } => {
            out.push_str("(keypath.getter)");
        }
        Node::KeyPathSetter { .. } => {
            out.push_str("(keypath.setter)");
        }
        Node::KeyPath { getter, setter, .. } => {
            out.push_str("keypath (");
            if let Some(g) = getter {
                out.push_str("get: ");
                render_node(g, out, ctx);
            }
            if let Some(s) = setter {
                if getter.is_some() {
                    out.push_str(", ");
                }
                out.push_str("set: ");
                render_node(s, out, ctx);
            }
            out.push(')');
        }

        // ---- Operators ----
        Node::InfixOperator { name } => {
            out.push_str("infix ");
            out.push_str(name);
        }
        Node::PrefixOperator { name } => {
            out.push_str("prefix ");
            out.push_str(name);
        }
        Node::PostfixOperator { name } => {
            out.push_str("postfix ");
            out.push_str(name);
        }

        // ---- Type annotations ----
        Node::ThrowsAnnotation => {
            out.push_str(" throws");
        }
        Node::ErrorType => {
            out.push_str("Error");
        }
        Node::Throwing(inner) => {
            render_node(inner, out, ctx);
            out.push_str(" throws");
        }
        Node::AsyncAnnotation(inner) => {
            render_node(inner, out, ctx);
            out.push_str(" async");
        }
        Node::Sendable(inner) => {
            render_node(inner, out, ctx);
            out.push_str(" & Sendable");
        }

        // ---- Ownership ----
        Node::Owned(inner) => {
            out.push_str("__owned ");
            render_node(inner, out, ctx);
        }
        Node::Shared(inner) => {
            out.push_str("__shared ");
            render_node(inner, out, ctx);
        }
        Node::InOut(inner) => {
            out.push_str("inout ");
            render_node(inner, out, ctx);
        }
        Node::Isolated(inner) => {
            out.push_str("__isolated ");
            render_node(inner, out, ctx);
        }
        Node::NoEscape(inner) => {
            out.push_str("@noescape ");
            render_node(inner, out, ctx);
        }
        Node::Differentially(inner) => {
            out.push_str("@differentiable ");
            render_node(inner, out, ctx);
        }
        Node::Weak => {
            out.push_str("weak ");
        }

        // ---- Types ----
        Node::Tuple { elements } => {
            out.push('(');
            for (i, el) in elements.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                if let Node::TupleElement { name, ty } = el {
                    if let Some(n) = name {
                        out.push_str(n);
                        out.push_str(": ");
                    }
                    render_node(ty, out, RenderCtx::default());
                }
            }
            out.push(')');
        }
        Node::TupleElement { name, ty } => {
            if let Some(n) = name {
                out.push_str(n);
                out.push_str(": ");
            }
            render_node(ty, out, ctx);
        }
        Node::ReturnType { inner } => {
            render_node(inner, out, ctx);
        }
        Node::Type(t) => {
            render_node(t, out, ctx);
        }
        Node::BuiltinTypeName(name) => {
            out.push_str(name);
        }
        Node::TypeList { children } => {
            for (i, c) in children.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render_node(c, out, RenderCtx::default());
            }
        }
        Node::LabelList { labels } => {
            for (i, l) in labels.iter().enumerate() {
                if i > 0 {
                    out.push('_');
                }
                out.push_str(l);
            }
            out.push(':');
        }

        // ---- Sugared types ----
        Node::SugaredOptional(inner) => {
            render_node(inner, out, ctx);
            out.push('?');
        }
        Node::SugaredArray(inner) => {
            out.push('[');
            render_node(inner, out, ctx);
            out.push(']');
        }
        Node::SugaredDictionary { key, value } => {
            out.push('[');
            render_node(key, out, ctx);
            out.push_str(": ");
            render_node(value, out, ctx);
            out.push(']');
        }
        Node::SugaredParen(inner) => {
            out.push('(');
            render_node(inner, out, ctx);
            out.push(')');
        }

        // ---- Metatypes ----
        Node::Metatype(inner) => {
            render_node(inner, out, ctx);
            out.push_str(".Type");
        }
        Node::ExistentialMetatype(inner) => {
            render_node(inner, out, ctx);
            out.push_str(".Protocol");
        }

        // ---- DynamicSelf ----
        Node::DynamicallySelf => {
            out.push_str("Self");
        }

        // ---- Generics ----
        Node::DependentGenericConformance { ty, protocol } => {
            render_node(ty, out, ctx);
            out.push_str(" : ");
            render_node(protocol, out, ctx);
        }
        Node::DependentGenericType { ty } => {
            render_node(ty, out, ctx);
        }
        Node::DependentMemberType { base, member } => {
            render_node(base, out, ctx);
            out.push('.');
            out.push_str(member);
        }
        Node::DependentGenericParamCount(n) => {
            write!(out, "<{n} params>").unwrap();
        }
        Node::DependentGenericParamType { depth, index } => {
            write!(out, "tau_{depth}_{index}").unwrap();
        }
        Node::BoundGeneric { base, args } => {
            render_node(base, out, ctx);
            out.push('<');
            for (i, arg) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render_node(arg, out, RenderCtx::default());
            }
            out.push('>');
        }
        Node::DependentAssociatedConformance { ty, protocol } => {
            render_node(ty, out, ctx);
            out.push_str(" : ");
            render_node(protocol, out, ctx);
        }
        Node::DefaultAssociatedConformance(inner) => {
            render_node(inner, out, ctx);
        }

        // ---- Protocol-related ----
        Node::ProtocolList { protocols } => {
            for (i, p) in protocols.iter().enumerate() {
                if i > 0 {
                    out.push_str(" & ");
                }
                render_node(p, out, ctx);
            }
        }
        Node::ProtocolConformance { ty, protocol } => {
            render_node(ty, out, ctx);
            out.push_str(" : ");
            render_node(protocol, out, ctx);
        }
        Node::ProtocolSelfConformance(inner) => {
            out.push_str("Self conforms to ");
            render_node(inner, out, ctx);
        }
        Node::ProtocolWitnessTable {
            conforming_type,
            protocol,
        } => {
            out.push_str("protocol witness table for ");
            render_node(conforming_type, out, ctx);
            out.push_str(" : ");
            render_node(protocol, out, ctx);
        }
        Node::GenericProtocolWitnessTable {
            conforming_type,
            protocol,
        } => {
            out.push_str("generic protocol witness table for ");
            render_node(conforming_type, out, ctx);
            out.push_str(" : ");
            render_node(protocol, out, ctx);
        }
        Node::GenericTypeMetadata(inner) => {
            out.push_str("generic type metadata for ");
            render_node(inner, out, ctx);
        }
        Node::FullTypeMetadata(inner) => {
            out.push_str("full type metadata for ");
            render_node(inner, out, ctx);
        }
        Node::TypeMetadata(inner) => {
            out.push_str("type metadata for ");
            render_node(inner, out, ctx);
        }
        Node::ReflectionMetadata(inner) => {
            out.push_str("reflection metadata for ");
            render_node(inner, out, ctx);
        }
        Node::NominalTypeDescriptor(inner) => {
            out.push_str("nominal type descriptor for ");
            render_node(inner, out, ctx);
        }
        Node::ProtocolDescriptor(inner) => {
            out.push_str("protocol descriptor for ");
            render_node(inner, out, ctx);
        }
        Node::ProtocolConformanceDescriptor { ty, protocol } => {
            out.push_str("protocol conformance descriptor for ");
            render_node(ty, out, ctx);
            out.push_str(" : ");
            render_node(protocol, out, ctx);
        }
        Node::AssociatedType { name, protocol } => {
            render_node(protocol, out, ctx);
            out.push('.');
            out.push_str(name);
        }
        Node::AssociatedConformance { ty, protocol } => {
            render_node(ty, out, ctx);
            out.push_str(" : ");
            render_node(protocol, out, ctx);
        }
        Node::WitnessMethod { protocol, method } => {
            out.push_str("witness_method ");
            render_node(protocol, out, ctx);
            out.push('.');
            render_node(method, out, ctx);
        }
        Node::ValueWitness { ty } => {
            out.push_str("value witness for ");
            render_node(ty, out, ctx);
        }

        // ---- SIL ----
        Node::SilFunction { name, .. } => {
            out.push_str(name);
        }
        Node::SilThunk { inner } => {
            if let Some(i) = inner {
                render_node(i, out, ctx);
            }
            out.push_str("[thunk]");
        }
        Node::SilGlobalVariable => {
            out.push_str("global");
        }
        Node::SilBox { ty } => {
            out.push_str("@box ");
            render_node(ty, out, ctx);
        }

        // ---- ObjC interop ----
        Node::ObjCBlock(inner) => {
            out.push_str("@convention(block) ");
            render_node(inner, out, ctx);
        }
        Node::ObjCAttribute => {
            out.push_str("@objc");
        }

        // ---- VTable / Field ----
        Node::VTable { class, entries } => {
            out.push_str("vtable for ");
            render_node(class, out, ctx);
            if !entries.is_empty() {
                out.push_str(" [");
                for (i, entry) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    if let Some(ref n) = entry.name {
                        out.push_str(n);
                    }
                }
                out.push(']');
            }
        }
        Node::FieldOffset { name, ty, offset } => {
            out.push_str("field offset of ");
            out.push_str(name);
            out.push_str(" : ");
            render_node(ty, out, ctx);
            if *offset > 0 {
                write!(out, " (+{offset})").unwrap();
            }
        }

        // ---- Decl ----
        Node::DeclContext { inner } => {
            render_node(inner, out, ctx);
        }
        Node::Directness { kind, inner } => {
            out.push_str(kind);
            out.push(' ');
            render_node(inner, out, ctx);
        }

        // ---- Primitives ----
        Node::Module(name) => {
            out.push_str(name);
        }
        Node::Identifier(name) => {
            out.push_str(name);
        }
        Node::Index(n) => {
            write!(out, "{n}").unwrap();
        }
        Node::UnknownIndex => {
            out.push_str("_");
        }
        Node::Suffix(s) => {
            out.push_str(s);
        }
        Node::LocalDeclName { number } => {
            write!(out, "#{number}").unwrap();
        }
        Node::PrivateDeclName { file, identifier } => {
            out.push_str(file);
            out.push('.');
            out.push_str(identifier);
        }
        Node::RelatedEntityDeclName { base, related } => {
            out.push_str(base);
            out.push('.');
            out.push_str(related);
        }
        Node::ArgumentTuple { elements } => {
            for (i, el) in elements.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render_node(el, out, ctx);
            }
        }

        // ---- Memory ----
        Node::AllocStack => {
            out.push_str("alloc_stack");
        }
        Node::AnonymousContext => {
            out.push_str("(anonymous context)");
        }

        // ---- IndirectResult ----
        Node::IndirectResult => {
            out.push_str("(indirect result)");
        }

        // ---- Curried / uncurried ----
        Node::CurriedFunctionType { params, result } => {
            render_node(params, out, ctx);
            out.push_str(" -> ");
            render_node(result, out, ctx);
        }
        Node::UncurriedFunctionType { params, result } => {
            out.push('(');
            render_node(params, out, ctx);
            out.push_str(") -> ");
            render_node(result, out, ctx);
        }

        // ---- Fallback ----
        Node::Unknown(s) => {
            out.push('<');
            out.push_str(s);
            out.push('>');
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

/// Quick demangle without full error details. Returns the original string
/// on failure.
pub fn demangle_or_original(mangled: &str) -> String {
    demangle(mangled).unwrap_or_else(|_| mangled.to_string())
}

/// Returns true if the string looks like a Swift mangled name.
pub fn is_swift_mangled(name: &str) -> bool {
    name.starts_with("$s")
        || name.starts_with("$S")
        || name.starts_with("_T0")
        || name.starts_with("_Tt")
        || name.starts_with("__T")
        || name.starts_with("_$s")
        || name.starts_with("_$S")
}

/// Check if a symbol is a known Swift runtime function.
pub fn is_swift_runtime_fn(name: &str) -> bool {
    let swift_runtime_prefixes = ["_swift_", "swift_", "__swift_", "_Swift"];
    swift_runtime_prefixes.iter().any(|p| name.contains(p))
}


// ===========================================================================
// Swift Binary Format Structures
//
// Ported from Ghidra's Java Swift type metadata classes.
// These types model the Swift ABI runtime metadata embedded in Mach-O, ELF,
// and PE binaries, corresponding to the Swift compiler's Metadata.h,
// MetadataValues.h, and RemoteInspection/Records.h headers.
// ===========================================================================

// ---------------------------------------------------------------------------
// Swift Section Names (from SwiftSection.java)
// ---------------------------------------------------------------------------

/// Names for Swift metadata sections, which vary by platform (Mach-O, ELF, PE).
///
/// See: https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/Swift.def
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwiftSection {
    /// Field metadata (swift5_fieldmd).
    FieldMetadata,
    /// Associated type metadata (swift5_assocty).
    AssociatedType,
    /// Built-in type metadata (swift5_builtin).
    Builtin,
    /// Capture descriptor metadata (swift5_capture).
    Capture,
    /// Type reference metadata (swift5_typeref).
    TypeRef,
    /// Reflection string table (swift5_reflstr).
    ReflectionString,
    /// Protocol conformance descriptors (swift5_proto / swift5_protocol_conformances).
    ProtocolConformance,
    /// Protocol descriptors (swift5_protos / swift5_protocols).
    Protocols,
    /// Accessible functions (swift5_acfuncs / swift5_accessible_functions).
    AccessibleFunctions,
    /// Multi-payload enum descriptors (swift5_mpenum).
    MultiPayloadEnum,
    /// Type metadata / type descriptors (__swift5_types / swift5_type_metadata).
    Types,
    /// Entry points (__swift5_entry / swift5_entry).
    Entry,
    /// Swift AST (__swift_ast / .swift_ast / swiftast).
    SwiftAst,
}

impl SwiftSection {
    /// Return the list of possible section names for this kind.
    ///
    /// Different platforms (Mach-O, ELF, PE) use different naming conventions.
    pub fn section_names(&self) -> &'static [&'static str] {
        match self {
            Self::FieldMetadata => &["__swift5_fieldmd", "swift5_fieldmd", ".sw5flmd"],
            Self::AssociatedType => &["__swift5_assocty", "swift5_assocty", ".sw5asty"],
            Self::Builtin => &["__swift5_builtin", "swift5_builtin", ".sw5bltn"],
            Self::Capture => &["__swift5_capture", "swift5_capture", ".sw5cptr"],
            Self::TypeRef => &["__swift5_typeref", "swift5_typeref", ".sw5tyrf"],
            Self::ReflectionString => &["__swift5_reflstr", "swift5_reflstr", ".sw5rfst"],
            Self::ProtocolConformance => &[
                "__swift5_proto",
                "swift5_protocol_conformances",
                ".sw5prtc",
            ],
            Self::Protocols => &["__swift5_protos", "swift5_protocols", ".sw5prt"],
            Self::AccessibleFunctions => &[
                "__swift5_acfuncs",
                "swift5_accessible_functions",
                ".sw5acfn",
            ],
            Self::MultiPayloadEnum => &["__swift5_mpenum", "swift5_mpenum", ".sw5mpen"],
            Self::Types => &[
                "__swift5_types",
                "__swift5_types2",
                "swift5_type_metadata",
                ".sw5tymd",
            ],
            Self::Entry => &["__swift5_entry", "swift5_entry", ".sw5entr"],
            Self::SwiftAst => &["__swift_ast", ".swift_ast", "swiftast"],
        }
    }

    /// Return all Swift section variants.
    pub fn all() -> &'static [SwiftSection] {
        &[
            Self::FieldMetadata,
            Self::AssociatedType,
            Self::Builtin,
            Self::Capture,
            Self::TypeRef,
            Self::ReflectionString,
            Self::ProtocolConformance,
            Self::Protocols,
            Self::AccessibleFunctions,
            Self::MultiPayloadEnum,
            Self::Types,
            Self::Entry,
            Self::SwiftAst,
        ]
    }
}

// ---------------------------------------------------------------------------
// Context Descriptor Kind (from ContextDescriptorKind.java)
// ---------------------------------------------------------------------------

/// The kind of a Swift context descriptor.
///
/// Encoded in the low bits of the context descriptor flags word.
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ContextDescriptorKind {
    /// Module descriptor.
    Module = 0,
    /// Extension descriptor.
    Extension = 1,
    /// Anonymous (possibly generic) context descriptor.
    Anonymous = 2,
    /// Protocol descriptor.
    Protocol = 3,
    /// Opaque type descriptor.
    OpaqueType = 4,
    /// Class descriptor.
    Class = 16,
    /// Struct descriptor.
    Struct = 17,
    /// Enum descriptor.
    Enum = 18,
}

impl ContextDescriptorKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Module),
            1 => Some(Self::Extension),
            2 => Some(Self::Anonymous),
            3 => Some(Self::Protocol),
            4 => Some(Self::OpaqueType),
            16 => Some(Self::Class),
            17 => Some(Self::Struct),
            18 => Some(Self::Enum),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Context Descriptor Flags (from ContextDescriptorFlags.java)
// ---------------------------------------------------------------------------

/// Flags word at the start of every Swift context descriptor.
///
/// This 32-bit value encodes the kind, whether the context is generic,
/// whether it has a unique name, and version information.
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextDescriptorFlags {
    /// Raw flags value.
    pub value: u32,
}

impl ContextDescriptorFlags {
    /// Create from a raw u32.
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    /// The kind of context descriptor (low 8 bits).
    pub fn kind(&self) -> Option<ContextDescriptorKind> {
        ContextDescriptorKind::from_u8((self.value & 0xFF) as u8)
    }

    /// Whether the context is generic (bit 8).
    pub fn is_generic(&self) -> bool {
        (self.value >> 8) & 0x1 != 0
    }

    /// Whether the context has a unique name (bit 9).
    pub fn is_unique(&self) -> bool {
        (self.value >> 9) & 0x1 != 0
    }

    /// The version number (bits 16-23).
    pub fn version(&self) -> u8 {
        ((self.value >> 16) & 0xFF) as u8
    }
}

// ---------------------------------------------------------------------------
// Generic Context Descriptor Flags (from GenericContextDescriptorFlags.java)
// ---------------------------------------------------------------------------

/// Flags for the generic portion of a context descriptor.
///
/// 16-bit value encoding properties of the generic context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericContextDescriptorFlags {
    /// Raw flags value.
    pub value: u16,
}

impl GenericContextDescriptorFlags {
    /// Create from a raw u16.
    pub fn new(value: u16) -> Self {
        Self { value }
    }

    /// Whether the context has at least one type parameter pack.
    pub fn has_type_packs(&self) -> bool {
        self.value & 0x1 != 0
    }

    /// Whether the context has conditional conformances to inverted protocols.
    pub fn has_conditional_inverted_protocols(&self) -> bool {
        (self.value >> 1) & 0x1 != 0
    }

    /// Whether the context has at least one value parameter.
    pub fn has_values(&self) -> bool {
        (self.value >> 2) & 0x1 != 0
    }
}

// ---------------------------------------------------------------------------
// Conformance Flags (from ConformanceFlags.java)
// ---------------------------------------------------------------------------

/// Flags for a protocol conformance descriptor.
///
/// 32-bit value encoding the type reference kind, retroactivity,
/// number of conditional requirements, and witness table information.
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConformanceFlags {
    /// Raw flags value.
    pub value: u32,
}

impl ConformanceFlags {
    /// Create from a raw u32.
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    /// The type reference kind (bits 3-4).
    pub fn kind(&self) -> Option<TypeReferenceKind> {
        TypeReferenceKind::from_u8(((self.value >> 3) & 0x3) as u8)
    }

    /// Whether the conformance is retroactive (bit 6).
    pub fn is_retroactive(&self) -> bool {
        (self.value >> 6) & 0x1 != 0
    }

    /// Whether the conformance is synthesized non-unique (bit 7).
    pub fn is_synthesized_non_unique(&self) -> bool {
        (self.value >> 7) & 0x1 != 0
    }

    /// Number of conditional requirements (bits 8-15).
    pub fn num_conditional_requirements(&self) -> u32 {
        (self.value >> 8) & 0xFF
    }

    /// Whether the conformance has resilient witnesses (bit 16).
    pub fn has_resilient_witnesses(&self) -> bool {
        (self.value >> 16) & 0x1 != 0
    }

    /// Whether the conformance has a generic witness table (bit 17).
    pub fn has_generic_witness_table(&self) -> bool {
        (self.value >> 17) & 0x1 != 0
    }

    /// Whether the conformance is of a protocol (bit 18).
    pub fn is_conformance_of_protocol(&self) -> bool {
        (self.value >> 18) & 0x1 != 0
    }

    /// Whether the conformance has global actor isolation (bit 19).
    pub fn has_global_actor_isolation(&self) -> bool {
        (self.value >> 19) & 0x1 != 0
    }
}

// ---------------------------------------------------------------------------
// Type Reference Kind (from TypeReferenceKind.java)
// ---------------------------------------------------------------------------

/// How a conformance descriptor references its type.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TypeReferenceKind {
    /// Direct pointer to the type descriptor.
    DirectTypeDescriptor = 0,
    /// Indirect pointer (through a global) to the type descriptor.
    IndirectTypeDescriptor = 1,
    /// Direct pointer to an Objective-C class name string.
    DirectObjCClassName = 2,
    /// Indirect pointer (through a global) to an Objective-C class.
    IndirectObjCClass = 3,
}

impl TypeReferenceKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::DirectTypeDescriptor),
            1 => Some(Self::IndirectTypeDescriptor),
            2 => Some(Self::DirectObjCClassName),
            3 => Some(Self::IndirectObjCClass),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Generic Requirement Kind (from GenericRequirementKind.java)
// ---------------------------------------------------------------------------

/// The kind of a generic requirement.
///
/// Encoded in the low bits of GenericRequirementFlags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GenericRequirementKind {
    /// The type conforms to the protocol.
    Protocol = 0,
    /// The type is the same as the type.
    SameType = 1,
    /// The type is a superclass of the type.
    BaseClass = 2,
    /// The type has the same layout as the type.
    SameConformance = 3,
    /// The type has a layout constraint.
    Layout = 0x1F,
}

impl GenericRequirementKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Protocol),
            1 => Some(Self::SameType),
            2 => Some(Self::BaseClass),
            3 => Some(Self::SameConformance),
            0x1F => Some(Self::Layout),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Generic Requirement Flags (from GenericRequirementFlags.java)
// ---------------------------------------------------------------------------

/// Flags for a generic requirement.
///
/// 32-bit value encoding the kind and whether it is a pack requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericRequirementFlags {
    /// Raw flags value.
    pub value: u32,
}

impl GenericRequirementFlags {
    /// Create from a raw u32.
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    /// The requirement kind (low 6 bits).
    pub fn kind(&self) -> Option<GenericRequirementKind> {
        GenericRequirementKind::from_u8((self.value & 0x3F) as u8)
    }

    /// Whether this is a pack requirement (bit 6).
    pub fn is_pack_requirement(&self) -> bool {
        (self.value >> 6) & 0x1 != 0
    }

    /// Whether this requirement has an extra argument (bit 7).
    pub fn has_extra_argument(&self) -> bool {
        (self.value >> 7) & 0x1 != 0
    }
}

// ---------------------------------------------------------------------------
// Protocol Requirement Kind (from ProtocolRequirementKind.java)
// ---------------------------------------------------------------------------

/// The kind of a protocol requirement.
///
/// Encoded in the low bits of ProtocolRequirementFlags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProtocolRequirementKind {
    /// A method requirement.
    Method = 0,
    /// An init requirement.
    Init = 1,
    /// A getter requirement.
    Getter = 2,
    /// A setter requirement.
    Setter = 3,
    /// A read coroutine requirement.
    ReadCoroutine = 4,
    /// A modify coroutine requirement.
    ModifyCoroutine = 5,
    /// A associated type requirement.
    AssociatedType = 6,
    /// A base protocol requirement.
    BaseProtocol = 7,
    /// An associated conformance requirement.
    AssociatedConformance = 8,
}

impl ProtocolRequirementKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Method),
            1 => Some(Self::Init),
            2 => Some(Self::Getter),
            3 => Some(Self::Setter),
            4 => Some(Self::ReadCoroutine),
            5 => Some(Self::ModifyCoroutine),
            6 => Some(Self::AssociatedType),
            7 => Some(Self::BaseProtocol),
            8 => Some(Self::AssociatedConformance),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol Requirement Flags (from ProtocolRequirementFlags.java)
// ---------------------------------------------------------------------------

/// Flags for a protocol requirement.
///
/// 32-bit value encoding the kind, instance flag, async flag,
/// and extra discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolRequirementFlags {
    /// Raw flags value.
    pub value: u32,
}

impl ProtocolRequirementFlags {
    /// Create from a raw u32.
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    /// The requirement kind (low 4 bits).
    pub fn kind(&self) -> Option<ProtocolRequirementKind> {
        ProtocolRequirementKind::from_u8((self.value & 0x0F) as u8)
    }

    /// Whether the requirement is an instance member (bit 4).
    pub fn is_instance(&self) -> bool {
        (self.value >> 4) & 0x1 != 0
    }

    /// Whether the requirement is async (bit 5).
    pub fn is_async(&self) -> bool {
        (self.value >> 5) & 0x1 != 0
    }

    /// Extra discriminator (bits 16-31).
    pub fn extra_discriminator(&self) -> u16 {
        ((self.value >> 16) & 0xFFFF) as u16
    }
}

// ---------------------------------------------------------------------------
// Method Descriptor Kind (from MethodDescriptorKind.java)
// ---------------------------------------------------------------------------

/// The kind of a method descriptor entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MethodDescriptorKind {
    /// A method.
    Method = 0,
    /// An init.
    Init = 1,
    /// A getter.
    Getter = 2,
    /// A setter.
    Setter = 3,
    /// A modify coroutine.
    ModifyCoroutine = 4,
    /// A read coroutine.
    ReadCoroutine = 5,
}

impl MethodDescriptorKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Method),
            1 => Some(Self::Init),
            2 => Some(Self::Getter),
            3 => Some(Self::Setter),
            4 => Some(Self::ModifyCoroutine),
            5 => Some(Self::ReadCoroutine),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Method Descriptor Flags (from MethodDescriptorFlags.java)
// ---------------------------------------------------------------------------

/// Flags for a method descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodDescriptorFlags {
    /// Raw flags value.
    pub value: u32,
}

impl MethodDescriptorFlags {
    /// Create from a raw u32.
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    /// The method kind (low 4 bits).
    pub fn kind(&self) -> Option<MethodDescriptorKind> {
        MethodDescriptorKind::from_u8((self.value & 0x0F) as u8)
    }

    /// Whether the method is instance (bit 4).
    pub fn is_instance(&self) -> bool {
        (self.value >> 4) & 0x1 != 0
    }

    /// Whether the method is dynamic (bit 5).
    pub fn is_dynamic(&self) -> bool {
        (self.value >> 5) & 0x1 != 0
    }

    /// Extra discriminator (bits 16-31).
    pub fn extra_discriminator(&self) -> u16 {
        ((self.value >> 16) & 0xFFFF) as u16
    }
}

// ---------------------------------------------------------------------------
// Field Record Flags (from FieldRecord.java)
// ---------------------------------------------------------------------------

/// Indirectable flags for a field record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRecordFlags {
    /// Raw flags value.
    pub value: u32,
}

impl FieldRecordFlags {
    /// Create from a raw u32.
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    /// Whether the field is an indirect case (bit 0).
    pub fn is_indirect_case(&self) -> bool {
        self.value & 0x1 != 0
    }

    /// Whether the field has a variable offset (bit 1).
    pub fn is_var(&self) -> bool {
        (self.value >> 1) & 0x1 != 0
    }
}

// ---------------------------------------------------------------------------
// Metadata Initialization Kind (from MetadataInitializationKind.java)
// ---------------------------------------------------------------------------

/// How a type's metadata is initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MetadataInitializationKind {
    /// No special initialization.
    None = 0,
    /// Singleton initialization.
    Singleton = 1,
    /// Foreign metadata initialization.
    Foreign = 2,
}

impl MetadataInitializationKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::None),
            1 => Some(Self::Singleton),
            2 => Some(Self::Foreign),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Target Context Descriptor (from TargetContextDescriptor.java)
// ---------------------------------------------------------------------------

/// Base for all Swift context descriptors.
///
/// Every context descriptor begins with a flags word and an optional parent
/// pointer (as a relative offset).
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetContextDescriptor {
    /// The context descriptor flags.
    pub flags: ContextDescriptorFlags,
    /// Relative offset to the parent context descriptor (0 = no parent).
    pub parent: i32,
    /// The virtual address where this descriptor was read from.
    pub address: u64,
}

impl TargetContextDescriptor {
    /// Create a new context descriptor.
    pub fn new(flags: ContextDescriptorFlags, parent: i32, address: u64) -> Self {
        Self {
            flags,
            parent,
            address,
        }
    }

    /// The kind of this context descriptor.
    pub fn kind(&self) -> Option<ContextDescriptorKind> {
        self.flags.kind()
    }
}

// ---------------------------------------------------------------------------
// Target Type Context Descriptor (from TargetTypeContextDescriptor.java)
// ---------------------------------------------------------------------------

/// A context descriptor for a nominal type (class, struct, or enum).
///
/// Extends TargetContextDescriptor with a name pointer, access function
/// pointer, and fields pointer.
#[derive(Debug, Clone)]
pub struct TargetTypeContextDescriptor {
    /// Base context descriptor.
    pub base: TargetContextDescriptor,
    /// Relative offset to the type name string.
    pub name: String,
    /// Relative offset to the metadata access function.
    pub access_function_ptr: i32,
    /// Relative offset to the fields descriptor.
    pub fields_ptr: i32,
    /// Flags specific to the type context.
    pub type_flags: u32,
}

impl TargetTypeContextDescriptor {
    /// Create a new type context descriptor.
    pub fn new(base: TargetContextDescriptor) -> Self {
        Self {
            base,
            name: String::new(),
            access_function_ptr: 0,
            fields_ptr: 0,
            type_flags: 0,
        }
    }

    /// Get the type name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this type has a metadata initialization function.
    pub fn has_metadata_initialization(&self) -> bool {
        (self.type_flags >> 16) & 0x3 != 0
    }

    /// The metadata initialization kind.
    pub fn metadata_initialization_kind(&self) -> Option<MetadataInitializationKind> {
        MetadataInitializationKind::from_u8(((self.type_flags >> 16) & 0x3) as u8)
    }

    /// Whether the type has a layout string.
    pub fn has_layout_string(&self) -> bool {
        (self.type_flags >> 23) & 0x1 != 0
    }
}

// ---------------------------------------------------------------------------
// Target Class Descriptor (from TargetClassDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for a Swift class type.
///
/// Extends the type context descriptor with class-specific fields:
/// superclass, class flags, instance size, instance alignment,
/// runtime metadata kind, and vtable information.
#[derive(Debug, Clone)]
pub struct TargetClassDescriptor {
    /// Base type context descriptor.
    pub base: TargetTypeContextDescriptor,
    /// Relative offset to the superclass type descriptor.
    pub superclass_type: i32,
    /// Extra class-specific flags.
    pub class_flags: u32,
    /// Instance size in words (not including metadata header).
    pub instance_size: u32,
    /// Instance alignment in bytes.
    pub instance_align_mask: u16,
    /// Runtime-reserved metadata kind.
    pub runtime_reserved_byte: u16,
    /// Size of the class object in the metadata.
    pub class_object_size: u32,
    /// Offset to the vtable descriptor.
    pub vtable_descriptor_offset: u32,
    /// The class name (resolved).
    pub class_name: String,
}

impl TargetClassDescriptor {
    /// Create a new class descriptor.
    pub fn new(base: TargetTypeContextDescriptor) -> Self {
        let class_name = base.name.clone();
        Self {
            base,
            superclass_type: 0,
            class_flags: 0,
            instance_size: 0,
            instance_align_mask: 0,
            runtime_reserved_byte: 0,
            class_object_size: 0,
            vtable_descriptor_offset: 0,
            class_name,
        }
    }

    /// Whether the class is a Swift root class (no superclass in Swift).
    pub fn is_type_specific_metadata(&self) -> bool {
        self.class_flags & 0x1 != 0
    }

    /// Whether the class uses Swift refcounting (vs. Objective-C).
    pub fn uses_native_refcounting(&self) -> bool {
        (self.class_flags >> 1) & 0x1 != 0
    }

    /// Whether the class has a custom Objective-C name.
    pub fn has_custom_objc_name(&self) -> bool {
        (self.class_flags >> 2) & 0x1 != 0
    }

    /// Get the class name.
    pub fn name(&self) -> &str {
        &self.class_name
    }
}

// ---------------------------------------------------------------------------
// Target Struct Descriptor (from TargetStructDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for a Swift struct type.
///
/// Extends the type context descriptor with struct-specific fields:
/// number of stored properties, field offset vector offset.
#[derive(Debug, Clone)]
pub struct TargetStructDescriptor {
    /// Base type context descriptor.
    pub base: TargetTypeContextDescriptor,
    /// Number of stored properties in this struct.
    pub num_fields: u32,
    /// Offset to the field offset vector in the metadata.
    pub field_offset_vector_offset: u32,
}

impl TargetStructDescriptor {
    /// Create a new struct descriptor.
    pub fn new(base: TargetTypeContextDescriptor) -> Self {
        Self {
            base,
            num_fields: 0,
            field_offset_vector_offset: 0,
        }
    }

    /// Get the struct name.
    pub fn name(&self) -> &str {
        &self.base.name
    }
}

// ---------------------------------------------------------------------------
// Target Enum Descriptor (from TargetEnumDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for a Swift enum type.
///
/// Extends the type context descriptor with enum-specific fields:
/// number of cases, field offset vector offset, and multi-payload
/// enum information.
#[derive(Debug, Clone)]
pub struct TargetEnumDescriptor {
    /// Base type context descriptor.
    pub base: TargetTypeContextDescriptor,
    /// Number of cases in this enum.
    pub num_cases: u32,
    /// Offset to the field offset vector in the metadata.
    pub field_offset_vector_offset: u32,
    /// Offset to the multi-payload enum descriptor (0 if not multi-payload).
    pub multi_payload_enum_descriptor_offset: u32,
}

impl TargetEnumDescriptor {
    /// Create a new enum descriptor.
    pub fn new(base: TargetTypeContextDescriptor) -> Self {
        Self {
            base,
            num_cases: 0,
            field_offset_vector_offset: 0,
            multi_payload_enum_descriptor_offset: 0,
        }
    }

    /// Whether this is a multi-payload enum.
    pub fn is_multi_payload(&self) -> bool {
        self.multi_payload_enum_descriptor_offset != 0
    }

    /// Get the enum name.
    pub fn name(&self) -> &str {
        &self.base.name
    }
}

// ---------------------------------------------------------------------------
// Target Protocol Descriptor (from TargetProtocolDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for a Swift protocol.
///
/// Contains the protocol name, number of requirements in the requirement
/// signature, number of requirements, associated type names, and trailing
/// requirement descriptors.
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetProtocolDescriptor {
    /// Base context descriptor.
    pub base: TargetContextDescriptor,
    /// The protocol name (resolved from relative string reference).
    pub name: String,
    /// Number of requirements in the requirement signature.
    pub num_requirements_in_signature: u32,
    /// Number of requirements in the protocol.
    pub num_requirements: u32,
    /// Associated type names.
    pub associated_type_names: u32,
    /// Generic requirements in the requirement signature.
    pub requirements_in_signature: Vec<TargetGenericRequirementsDescriptor>,
    /// Protocol requirements.
    pub requirements: Vec<TargetProtocolRequirement>,
}

impl TargetProtocolDescriptor {
    /// Create a new protocol descriptor.
    pub fn new(base: TargetContextDescriptor, name: String) -> Self {
        Self {
            base,
            name,
            num_requirements_in_signature: 0,
            num_requirements: 0,
            associated_type_names: 0,
            requirements_in_signature: Vec::new(),
            requirements: Vec::new(),
        }
    }

    /// Get the protocol name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ---------------------------------------------------------------------------
// Target Protocol Conformance Descriptor
// (from TargetProtocolConformanceDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for a type's conformance to a protocol.
///
/// Contains the protocol descriptor, conforming type, witness table pattern,
/// and conformance flags.
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetProtocolConformanceDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// Conformance flags.
    pub conformance_flags: ConformanceFlags,
    /// The protocol being conformed to (relative offset to protocol descriptor).
    pub protocol: i32,
    /// The conforming type reference (interpretation depends on conformance_flags.kind()).
    pub type_ref: i32,
    /// The witness table pattern (relative offset).
    pub witness_table_pattern: i32,
}

impl TargetProtocolConformanceDescriptor {
    /// Create a new protocol conformance descriptor.
    pub fn new(address: u64, flags: u32) -> Self {
        Self {
            address,
            conformance_flags: ConformanceFlags::new(flags),
            protocol: 0,
            type_ref: 0,
            witness_table_pattern: 0,
        }
    }

    /// The type reference kind.
    pub fn type_reference_kind(&self) -> Option<TypeReferenceKind> {
        self.conformance_flags.kind()
    }

    /// Whether the conformance is retroactive.
    pub fn is_retroactive(&self) -> bool {
        self.conformance_flags.is_retroactive()
    }

    /// Whether the conformance has resilient witnesses.
    pub fn has_resilient_witnesses(&self) -> bool {
        self.conformance_flags.has_resilient_witnesses()
    }

    /// Whether the conformance has a generic witness table.
    pub fn has_generic_witness_table(&self) -> bool {
        self.conformance_flags.has_generic_witness_table()
    }
}

// ---------------------------------------------------------------------------
// Target Generic Requirements Descriptor
// (from TargetGenericRequirementsDescriptor.java)
// ---------------------------------------------------------------------------

/// A generic requirement (protocol conformance, same-type, or layout).
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetGenericRequirementsDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// Requirement flags.
    pub flags: GenericRequirementFlags,
    /// The parameter type.
    pub param_type: i32,
    /// The requirement argument (protocol descriptor, type, or layout).
    pub requirement_arg: i32,
}

impl TargetGenericRequirementsDescriptor {
    /// Create a new generic requirements descriptor.
    pub fn new(address: u64, flags: u32) -> Self {
        Self {
            address,
            flags: GenericRequirementFlags::new(flags),
            param_type: 0,
            requirement_arg: 0,
        }
    }

    /// The requirement kind.
    pub fn kind(&self) -> Option<GenericRequirementKind> {
        self.flags.kind()
    }
}

// ---------------------------------------------------------------------------
// Target Protocol Requirement (from TargetProtocolRequirement.java)
// ---------------------------------------------------------------------------

/// A single requirement in a protocol's witness table.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetProtocolRequirement {
    /// The address where this requirement was found.
    pub address: u64,
    /// Requirement flags.
    pub flags: ProtocolRequirementFlags,
    /// Default implementation (relative offset to function, 0 = none).
    pub default_impl: i32,
}

impl TargetProtocolRequirement {
    /// Create a new protocol requirement.
    pub fn new(address: u64, flags: u32) -> Self {
        Self {
            address,
            flags: ProtocolRequirementFlags::new(flags),
            default_impl: 0,
        }
    }

    /// The requirement kind.
    pub fn kind(&self) -> Option<ProtocolRequirementKind> {
        self.flags.kind()
    }

    /// Whether this is an instance requirement.
    pub fn is_instance(&self) -> bool {
        self.flags.is_instance()
    }

    /// Whether this is an async requirement.
    pub fn is_async(&self) -> bool {
        self.flags.is_async()
    }
}

// ---------------------------------------------------------------------------
// Target VTable Descriptor Header
// (from TargetVTableDescriptorHeader.java)
// ---------------------------------------------------------------------------

/// Header for a class's virtual method table.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetVTableDescriptorHeader {
    /// The address where this header was found.
    pub address: u64,
    /// Offset of the vtable from the class metadata start.
    pub vtable_offset: u32,
    /// Size of the vtable in words.
    pub vtable_size: u32,
}

impl TargetVTableDescriptorHeader {
    /// Create a new vtable descriptor header.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            vtable_offset: 0,
            vtable_size: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Target Method Descriptor (from TargetMethodDescriptor.java)
// ---------------------------------------------------------------------------

/// A method descriptor in a vtable.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetMethodDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// Method flags.
    pub flags: MethodDescriptorFlags,
    /// Relative offset to the method implementation.
    pub impl_offset: i32,
}

impl TargetMethodDescriptor {
    /// Create a new method descriptor.
    pub fn new(address: u64, flags: u32) -> Self {
        Self {
            address,
            flags: MethodDescriptorFlags::new(flags),
            impl_offset: 0,
        }
    }

    /// The method kind.
    pub fn kind(&self) -> Option<MethodDescriptorKind> {
        self.flags.kind()
    }

    /// Whether this is a virtual method.
    pub fn is_instance(&self) -> bool {
        self.flags.is_instance()
    }

    /// Whether this method is dynamic dispatch.
    pub fn is_dynamic(&self) -> bool {
        self.flags.is_dynamic()
    }
}

// ---------------------------------------------------------------------------
// Target Method Override Descriptor
// (from TargetMethodOverrideDescriptor.java)
// ---------------------------------------------------------------------------

/// A method override descriptor linking a class method to its superclass
/// implementation.
#[derive(Debug, Clone)]
pub struct TargetMethodOverrideDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// Relative offset to the overridden method class.
    pub overridden_class: i32,
    /// Relative offset to the overridden method descriptor.
    pub overridden_method: i32,
}

impl TargetMethodOverrideDescriptor {
    /// Create a new method override descriptor.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            overridden_class: 0,
            overridden_method: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Target Override Table Header
// (from TargetOverrideTableHeader.java)
// ---------------------------------------------------------------------------

/// Header for a class's method override table.
#[derive(Debug, Clone)]
pub struct TargetOverrideTableHeader {
    /// The address where this header was found.
    pub address: u64,
    /// Number of entries in the override table.
    pub num_entries: u32,
}

impl TargetOverrideTableHeader {
    /// Create a new override table header.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            num_entries: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Field Descriptor (from FieldDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for the fields of a type (struct/class/enum).
///
/// Contains the field type name, super class, kind, and number of fields,
/// followed by field records.
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h
#[derive(Debug, Clone)]
pub struct FieldDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// Mangled type name (relative pointer to string).
    pub mangled_type_name: String,
    /// Super class name (relative pointer to string, may be empty).
    pub super_class: String,
    /// The kind of the field descriptor's type.
    pub kind: FieldDescriptorKind,
    /// Number of fields.
    pub num_fields: u32,
    /// The field records.
    pub field_records: Vec<FieldRecord>,
}

impl FieldDescriptor {
    /// Create a new field descriptor.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            mangled_type_name: String::new(),
            super_class: String::new(),
            kind: FieldDescriptorKind::Unknown,
            num_fields: 0,
            field_records: Vec::new(),
        }
    }

    /// Get the base (mangled type name).
    pub fn base(&self) -> &str {
        &self.mangled_type_name
    }
}

/// The kind of a field descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FieldDescriptorKind {
    /// A struct.
    Struct,
    /// A class.
    Class,
    /// An enum.
    Enum,
    /// A multi-payload enum variant.
    MultiPayloadEnum,
    /// A protocol.
    Protocol,
    /// A class protocol (Objective-C).
    ClassProtocol,
    /// An existential protocol (Objective-C).
    ExistentialProtocol,
    /// Unknown.
    Unknown,
}

impl FieldDescriptorKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Struct),
            1 => Some(Self::Class),
            2 => Some(Self::Enum),
            3 => Some(Self::MultiPayloadEnum),
            4 => Some(Self::Protocol),
            5 => Some(Self::ClassProtocol),
            6 => Some(Self::ExistentialProtocol),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Field Record (from FieldRecord.java)
// ---------------------------------------------------------------------------

/// A single field record within a field descriptor.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h
#[derive(Debug, Clone)]
pub struct FieldRecord {
    /// The address where this record was found.
    pub address: u64,
    /// Field flags.
    pub flags: FieldRecordFlags,
    /// Mangled type name of this field (relative pointer to string).
    pub mangled_type_name: String,
    /// Field name (relative pointer to string).
    pub field_name: String,
}

impl FieldRecord {
    /// Create a new field record.
    pub fn new(address: u64, flags: u32) -> Self {
        Self {
            address,
            flags: FieldRecordFlags::new(flags),
            mangled_type_name: String::new(),
            field_name: String::new(),
        }
    }

    /// Whether this field is an indirect case.
    pub fn is_indirect(&self) -> bool {
        self.flags.is_indirect_case()
    }

    /// Whether this field has a variable offset.
    pub fn is_var(&self) -> bool {
        self.flags.is_var()
    }
}

// ---------------------------------------------------------------------------
// Associated Type Descriptor (from AssociatedTypeDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for associated types of a type.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h
#[derive(Debug, Clone)]
pub struct AssociatedTypeDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// The conforming type (conformance owner).
    pub conforming_type: i32,
    /// Number of associated type records.
    pub num_associated_types: u32,
    /// Associated type records.
    pub associated_type_records: Vec<AssociatedTypeRecord>,
}

impl AssociatedTypeDescriptor {
    /// Create a new associated type descriptor.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            conforming_type: 0,
            num_associated_types: 0,
            associated_type_records: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Associated Type Record (from AssociatedTypeRecord.java)
// ---------------------------------------------------------------------------

/// A single associated type record within an associated type descriptor.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h
#[derive(Debug, Clone)]
pub struct AssociatedTypeRecord {
    /// The address where this record was found.
    pub address: u64,
    /// Name of the associated type (relative pointer to string).
    pub name: String,
    /// Mangled name of the substituted type (relative pointer to string).
    pub substituted_type: String,
}

impl AssociatedTypeRecord {
    /// Create a new associated type record.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            name: String::new(),
            substituted_type: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Builtin Type Descriptor (from BuiltinTypeDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for a built-in Swift type (e.g., Builtin.Int32).
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h
#[derive(Debug, Clone)]
pub struct BuiltinTypeDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// Type name (relative pointer to string).
    pub type_name: String,
    /// Size in bytes.
    pub size: u32,
    /// Alignment in bytes.
    pub alignment: u32,
    /// Stride in bytes.
    pub stride: u32,
    /// Extra inhabitant count.
    pub num_extra_inhabitants: u32,
}

impl BuiltinTypeDescriptor {
    /// Create a new builtin type descriptor.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            type_name: String::new(),
            size: 0,
            alignment: 0,
            stride: 0,
            num_extra_inhabitants: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Capture Descriptor (from CaptureDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for a closure capture.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h
#[derive(Debug, Clone)]
pub struct CaptureDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// Number of capture type records.
    pub num_capture_types: u32,
    /// Number of capture name records.
    pub num_capture_names: u32,
    /// Capture type records.
    pub capture_types: Vec<CaptureTypeRecord>,
}

impl CaptureDescriptor {
    /// Create a new capture descriptor.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            num_capture_types: 0,
            num_capture_names: 0,
            capture_types: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Capture Type Record (from CaptureTypeRecord.java)
// ---------------------------------------------------------------------------

/// A single capture type within a capture descriptor.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h
#[derive(Debug, Clone)]
pub struct CaptureTypeRecord {
    /// The address where this record was found.
    pub address: u64,
    /// Mangled type name (relative pointer to string).
    pub mangled_type_name: String,
}

impl CaptureTypeRecord {
    /// Create a new capture type record.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            mangled_type_name: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry Point (from EntryPoint.java)
// ---------------------------------------------------------------------------

/// A Swift entry point descriptor.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct EntryPoint {
    /// The address where this entry point was found.
    pub address: u64,
    /// Init offset (relative pointer to initialization function).
    pub init_offset: i32,
}

impl EntryPoint {
    /// Create a new entry point.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            init_offset: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata Source Record (from MetadataSourceRecord.java)
// ---------------------------------------------------------------------------

/// A metadata source record for type metadata.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct MetadataSourceRecord {
    /// The address where this record was found.
    pub address: u64,
    /// Mangled type name (relative pointer to string).
    pub mangled_type_name: String,
    /// Relative pointer to the metadata accessor.
    pub accessor: i32,
}

impl MetadataSourceRecord {
    /// Create a new metadata source record.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            mangled_type_name: String::new(),
            accessor: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-Payload Enum Descriptor
// (from MultiPayloadEnumDescriptor.java)
// ---------------------------------------------------------------------------

/// A descriptor for a multi-payload enum.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h
#[derive(Debug, Clone)]
pub struct MultiPayloadEnumDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// Mangled type name (relative pointer to string).
    pub mangled_type_name: String,
    /// Number of payloads.
    pub num_payloads: u32,
    /// Payload size in bytes.
    pub payload_size: u32,
    /// Payload offsets.
    pub offsets: Vec<u32>,
}

impl MultiPayloadEnumDescriptor {
    /// Create a new multi-payload enum descriptor.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            mangled_type_name: String::new(),
            num_payloads: 0,
            payload_size: 0,
            offsets: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Extra Class Descriptor Flags
// (from ExtraClassDescriptorFlags.java)
// ---------------------------------------------------------------------------

/// Extra flags for class descriptors.
///
/// Encodes information about the class's type descriptor, ObjC interop,
/// and other metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraClassDescriptorFlags {
    /// Raw flags value.
    pub value: u32,
}

impl ExtraClassDescriptorFlags {
    /// Create from a raw u32.
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    /// Whether the class has an Objective-C resilient class stub.
    pub fn has_objc_resilient_class_stub(&self) -> bool {
        self.value & 0x1 != 0
    }

    /// Whether the class has a variant superclass.
    pub fn has_variant_superclass(&self) -> bool {
        (self.value >> 1) & 0x1 != 0
    }

    /// Whether the class is a retroactive conformance.
    pub fn has_transient_pointer(&self) -> bool {
        (self.value >> 2) & 0x1 != 0
    }
}

// ---------------------------------------------------------------------------
// Resilient Superclass (from TargetResilientSuperclass.java)
// ---------------------------------------------------------------------------

/// A resilient superclass reference.
///
/// For classes whose superclass is in a different resilience domain,
/// this provides an indirect pointer.
#[derive(Debug, Clone)]
pub struct TargetResilientSuperclass {
    /// The address where this record was found.
    pub address: u64,
    /// Relative offset to the superclass descriptor.
    pub superclass: i32,
}

impl TargetResilientSuperclass {
    /// Create a new resilient superclass record.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            superclass: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Resilient Witness Header
// (from TargetResilientWitnessHeader.java)
// ---------------------------------------------------------------------------

/// Header for a resilient witness table.
#[derive(Debug, Clone)]
pub struct TargetResilientWitnessHeader {
    /// The address where this header was found.
    pub address: u64,
    /// Number of witnesses.
    pub num_witnesses: u32,
    /// Witness entries.
    pub witnesses: Vec<TargetResilientWitness>,
}

impl TargetResilientWitnessHeader {
    /// Create a new resilient witness header.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            num_witnesses: 0,
            witnesses: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Resilient Witness (from TargetResilientWitness.java)
// ---------------------------------------------------------------------------

/// A single resilient witness table entry.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetResilientWitness {
    /// The address where this witness was found.
    pub address: u64,
    /// Requirement descriptor (relative offset).
    pub requirement: i32,
    /// Implementation function (relative offset).
    pub impl_function: i32,
}

impl TargetResilientWitness {
    /// Create a new resilient witness.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            requirement: 0,
            impl_function: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Generic Witness Table
// (from TargetGenericWitnessTable.java)
// ---------------------------------------------------------------------------

/// A generic protocol witness table.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetGenericWitnessTable {
    /// The address where this table was found.
    pub address: u64,
    /// Witness table size in words.
    pub witness_table_size: u16,
    /// Witness table private size in words.
    pub witness_table_private_size: u16,
    /// Requires instantiation (bit 0 of flags).
    pub requires_runtime_instantiation: bool,
    /// Relative offset to the instantiator.
    pub instantiator: i32,
    /// Relative offset to the private data.
    pub private_data: i32,
}

impl TargetGenericWitnessTable {
    /// Create a new generic witness table.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            witness_table_size: 0,
            witness_table_private_size: 0,
            requires_runtime_instantiation: false,
            instantiator: 0,
            private_data: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Singleton Metadata Initialization
// (from TargetSingletonMetadataInitialization.java)
// ---------------------------------------------------------------------------

/// Metadata for initializing singleton (non-generic) type metadata.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetSingletonMetadataInitialization {
    /// The address where this record was found.
    pub address: u64,
    /// Relative offset to the initialization cache.
    pub initialization_cache: i32,
    /// Relative offset to the incomplete metadata.
    pub incomplete_metadata: i32,
    /// Relative offset to the completion function.
    pub completion_function: i32,
}

impl TargetSingletonMetadataInitialization {
    /// Create a new singleton metadata initialization.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            initialization_cache: 0,
            incomplete_metadata: 0,
            completion_function: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Foreign Metadata Initialization
// (from TargetForeignMetadataInitialization.java)
// ---------------------------------------------------------------------------

/// Metadata initialization for foreign types (C/ObjC).
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct TargetForeignMetadataInitialization {
    /// The address where this record was found.
    pub address: u64,
    /// Relative offset to the completion function.
    pub completion_function: i32,
}

impl TargetForeignMetadataInitialization {
    /// Create a new foreign metadata initialization.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            completion_function: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Invertible Protocol Kind (from InvertibleProtocolKind.java)
// ---------------------------------------------------------------------------

/// A protocol that can be inverted for conformance checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InvertibleProtocolKind {
    /// Sendable protocol.
    Sendable = 0,
    /// Class protocol.
    Class = 1,
    /// Escapable protocol.
    Escapable = 2,
    /// Copyable protocol.
    Copyable = 3,
    /// BitwiseCopyable protocol.
    BitwiseCopyable = 4,
    /// Noncopyable protocol.
    Noncopyable = 5,
    /// NonEscapable protocol.
    NonEscapable = 6,
}

impl InvertibleProtocolKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Sendable),
            1 => Some(Self::Class),
            2 => Some(Self::Escapable),
            3 => Some(Self::Copyable),
            4 => Some(Self::BitwiseCopyable),
            5 => Some(Self::Noncopyable),
            6 => Some(Self::NonEscapable),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Generic Param Kind (from GenericParamKind.java)
// ---------------------------------------------------------------------------

/// The kind of a generic parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GenericParamKind {
    /// A type parameter.
    Type = 0,
    /// A type pack parameter.
    TypePack = 1,
    /// A value parameter.
    Value = 2,
}

impl GenericParamKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Type),
            1 => Some(Self::TypePack),
            2 => Some(Self::Value),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Generic Param Descriptor (from GenericParamDescriptor.java)
// ---------------------------------------------------------------------------

/// A generic parameter descriptor.
///
/// See: https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h
#[derive(Debug, Clone)]
pub struct GenericParamDescriptor {
    /// The address where this descriptor was found.
    pub address: u64,
    /// The parameter kind.
    pub kind: GenericParamKind,
    /// Whether this is a type pack parameter.
    pub has_type_pack: bool,
    /// Generic parameter depth (outermost = 0).
    pub depth: u16,
    /// Generic parameter index within its depth.
    pub index: u16,
}

impl GenericParamDescriptor {
    /// Create a new generic param descriptor.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            kind: GenericParamKind::Type,
            has_type_pack: false,
            depth: 0,
            index: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Target Context / Protocol Relative Pointers
// ---------------------------------------------------------------------------

/// A relative pointer to a context descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetRelativeContextPointer {
    /// Relative offset from the pointer's own position.
    pub offset: i32,
}

impl TargetRelativeContextPointer {
    /// Create from a relative offset.
    pub fn new(offset: i32) -> Self {
        Self { offset }
    }

    /// Resolve the target address given the pointer's own address.
    pub fn resolve(&self, base_address: u64) -> u64 {
        (base_address as i64 + self.offset as i64) as u64
    }
}

/// A relative pointer to a protocol requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetRelativeProtocolRequirementPointer {
    /// Relative offset from the pointer's own position.
    pub offset: i32,
}

impl TargetRelativeProtocolRequirementPointer {
    /// Create from a relative offset.
    pub fn new(offset: i32) -> Self {
        Self { offset }
    }

    /// Resolve the target address given the pointer's own address.
    pub fn resolve(&self, base_address: u64) -> u64 {
        (base_address as i64 + self.offset as i64) as u64
    }
}

// ---------------------------------------------------------------------------
// Target ObjC Resilient Class Stub Info
// (from TargetObjCResilientClassStubInfo.java)
// ---------------------------------------------------------------------------

/// Objective-C resilient class stub information.
///
/// Contains the stub pointer used for Objective-C interop.
#[derive(Debug, Clone)]
pub struct TargetObjCResilientClassStubInfo {
    /// The address where this info was found.
    pub address: u64,
    /// Relative offset to the class stub.
    pub stub: i32,
}

impl TargetObjCResilientClassStubInfo {
    /// Create a new ObjC resilient class stub info.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            stub: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Target Generic Context Descriptor Header
// (from TargetGenericContextDescriptorHeader.java)
// ---------------------------------------------------------------------------

/// Header for the generic portion of a context descriptor.
///
/// Precedes the generic parameters and requirements arrays.
#[derive(Debug, Clone)]
pub struct TargetGenericContextDescriptorHeader {
    /// The address where this header was found.
    pub address: u64,
    /// Number of generic parameters.
    pub num_params: u16,
    /// Number of generic requirements.
    pub num_requirements: u16,
    /// Number of key arguments.
    pub num_key_arguments: u16,
    /// Generic context descriptor flags.
    pub flags: GenericContextDescriptorFlags,
}

impl TargetGenericContextDescriptorHeader {
    /// Create a new generic context descriptor header.
    pub fn new(address: u64, flags: u16) -> Self {
        Self {
            address,
            num_params: 0,
            num_requirements: 0,
            num_key_arguments: 0,
            flags: GenericContextDescriptorFlags::new(flags),
        }
    }

    /// Whether the context has type parameter packs.
    pub fn has_type_packs(&self) -> bool {
        self.flags.has_type_packs()
    }

    /// Whether the context has conditional inverted protocols.
    pub fn has_conditional_inverted_protocols(&self) -> bool {
        self.flags.has_conditional_inverted_protocols()
    }

    /// Whether the context has value parameters.
    pub fn has_values(&self) -> bool {
        self.flags.has_values()
    }
}

// ---------------------------------------------------------------------------
// Target Type Generic Context Descriptor Header
// (from TargetTypeGenericContextDescriptorHeader.java)
// ---------------------------------------------------------------------------

/// A type-specific generic context descriptor header.
///
/// Adds type metadata initialization info to the generic context header.
#[derive(Debug, Clone)]
pub struct TargetTypeGenericContextDescriptorHeader {
    /// Base generic context descriptor header.
    pub base: TargetGenericContextDescriptorHeader,
    /// Metadata initialization kind.
    pub metadata_initialization: MetadataInitializationKind,
}

impl TargetTypeGenericContextDescriptorHeader {
    /// Create a new type generic context descriptor header.
    pub fn new(base: TargetGenericContextDescriptorHeader) -> Self {
        Self {
            base,
            metadata_initialization: MetadataInitializationKind::None,
        }
    }
}

// ---------------------------------------------------------------------------
// Generic Requirement Layout Kind
// (from GenericRequirementLayoutKind.java)
// ---------------------------------------------------------------------------

/// Layout constraint kinds for generic requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GenericRequirementLayoutKind {
    /// Native object pointer (thin).
    NativeObject = 0,
    /// Objective-C object pointer.
    ObjCPointer = 1,
    /// Trivial layout constraint.
    TrivialOfExactSize = 2,
    /// Trivial with a specific alignment.
    TrivialOfAlignSize = 3,
    /// Unknown.
    Unknown = 0xFF,
}

impl GenericRequirementLayoutKind {
    /// Create from a raw integer value.
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::NativeObject,
            1 => Self::ObjCPointer,
            2 => Self::TrivialOfExactSize,
            3 => Self::TrivialOfAlignSize,
            _ => Self::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Invertible Protocol Set (from InvertibleProtocolSet.java)
// ---------------------------------------------------------------------------

/// A bit set of invertible protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvertibleProtocolSet {
    /// Raw bits.
    pub bits: u32,
}

impl InvertibleProtocolSet {
    /// Create from a raw u32.
    pub fn new(bits: u32) -> Self {
        Self { bits }
    }

    /// Check whether a specific protocol kind is present.
    pub fn contains(&self, kind: InvertibleProtocolKind) -> bool {
        (self.bits >> (kind as u32)) & 0x1 != 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_swift_mangled() {
        assert!(is_swift_mangled(
            "$s10MyModule14MyViewControllerC5titleSSvp"
        ));
        assert!(is_swift_mangled("_T0s10MyModule5ModelV"));
        assert!(!is_swift_mangled("_ZN3foo3barE"));
    }

    #[test]
    fn test_demangle_not_swift() {
        assert_eq!(
            demangle("_ZN3std6string3newE").unwrap_err(),
            DemangleError::NotMangled
        );
    }

    #[test]
    fn test_demangle_simple_function() {
        let result = demangle("_$s4main3fooyyF").unwrap();
        assert!(result.contains("main.foo"), "got: {result}");
    }

    #[test]
    fn test_demangle_method() {
        // In modern Swift mangling, 'C' marks a class type.
        // '3foo' after the type is part of the qualified name context.
        let result = demangle("_$s4main7MyClassC3fooyyF").unwrap();
        assert!(result.contains("MyClass"), "got: {result}");
    }

    #[test]
    fn test_demangle_structure() {
        let result = demangle("_$s4main5PointV").unwrap();
        assert!(result.contains("Point"), "got: {result}");
    }

    #[test]
    fn test_builtin_types() {
        let result = demangle("_$sSbN").unwrap_or_else(|e| e.to_string());
        assert!(result.contains("Bool"), "got: {result}");
    }

    #[test]
    fn test_demangle_or_original() {
        let result = demangle_or_original("not_mangled");
        assert_eq!(result, "not_mangled");
    }

    #[test]
    fn test_swift_calling_convention() {
        let conv = SwiftCallingConvention::Swift;
        assert_eq!(conv.name(), "swiftcall");
        assert_eq!(conv.implicit_param_count(), 1);

        let async_conv = SwiftCallingConvention::SwiftAsync;
        assert_eq!(async_conv.name(), "swiftasynccall");
        assert_eq!(async_conv.implicit_param_count(), 2);
    }

    #[test]
    fn test_swift_type_metadata() {
        let mut md = SwiftTypeMetadata::new(0x10000, MetadataKind::Struct);
        md.mangled_name = Some("$s4main5PointV".into());
        md.demangle_name();
        assert_eq!(md.demangled_name.as_deref(), Some("main.Point"));
    }

    #[test]
    fn test_is_swift_runtime_fn() {
        assert!(is_swift_runtime_fn("_swift_allocObject"));
        assert!(is_swift_runtime_fn("swift_retain"));
        assert!(!is_swift_runtime_fn("malloc"));
    }

    #[test]
    fn test_metadata_kind_display() {
        let mut md = SwiftTypeMetadata::new(0x20000, MetadataKind::Class);
        md.mangled_name = Some("$s4main7MyClassC".into());
        md.demangle_name();
        let summary = md.summary();
        assert!(summary.contains("class"), "got: {summary}");
    }

    #[test]
    fn test_empty_demangle() {
        assert_eq!(demangle(""), Err(DemangleError::NotMangled));
    }

    #[test]
    fn test_swift5_prefix_variants() {
        assert!(is_swift_mangled("$s4main3foo"));
        assert!(is_swift_mangled("$S4main3foo"));
        assert!(is_swift_mangled("_$s4main3foo"));
        assert!(is_swift_mangled("_$S4main3foo"));
    }

    // ---- Swift Section Tests ----

    #[test]
    fn test_swift_section_names() {
        let sec = SwiftSection::FieldMetadata;
        let names = sec.section_names();
        assert!(names.contains(&"__swift5_fieldmd"));
        assert!(names.contains(&"swift5_fieldmd"));
        assert!(names.contains(&".sw5flmd"));

        let types = SwiftSection::Types;
        assert!(types.section_names().contains(&"__swift5_types"));
        assert!(types.section_names().contains(&"swift5_type_metadata"));
    }

    #[test]
    fn test_swift_section_all() {
        let all = SwiftSection::all();
        assert_eq!(all.len(), 13);
        assert!(all.contains(&SwiftSection::FieldMetadata));
        assert!(all.contains(&SwiftSection::ProtocolConformance));
        assert!(all.contains(&SwiftSection::Types));
    }

    // ---- Context Descriptor Kind Tests ----

    #[test]
    fn test_context_descriptor_kind() {
        assert_eq!(ContextDescriptorKind::from_u8(0), Some(ContextDescriptorKind::Module));
        assert_eq!(ContextDescriptorKind::from_u8(16), Some(ContextDescriptorKind::Class));
        assert_eq!(ContextDescriptorKind::from_u8(17), Some(ContextDescriptorKind::Struct));
        assert_eq!(ContextDescriptorKind::from_u8(18), Some(ContextDescriptorKind::Enum));
        assert_eq!(ContextDescriptorKind::from_u8(3), Some(ContextDescriptorKind::Protocol));
        assert_eq!(ContextDescriptorKind::from_u8(99), None);
    }

    // ---- Context Descriptor Flags Tests ----

    #[test]
    fn test_context_descriptor_flags() {
        // kind=Class(16), generic=true(1<<8=256), unique=false, version=0
        let flags = ContextDescriptorFlags::new(16 | 256);
        assert_eq!(flags.kind(), Some(ContextDescriptorKind::Class));
        assert!(flags.is_generic());
        assert!(!flags.is_unique());
        assert_eq!(flags.version(), 0);

        // kind=Struct(17), not generic, unique, version=2
        let flags = ContextDescriptorFlags::new(17 | (1 << 9) | (2 << 16));
        assert_eq!(flags.kind(), Some(ContextDescriptorKind::Struct));
        assert!(!flags.is_generic());
        assert!(flags.is_unique());
        assert_eq!(flags.version(), 2);
    }

    // ---- Generic Context Descriptor Flags Tests ----

    #[test]
    fn test_generic_context_descriptor_flags() {
        let flags = GenericContextDescriptorFlags::new(0x7);
        assert!(flags.has_type_packs());
        assert!(flags.has_conditional_inverted_protocols());
        assert!(flags.has_values());

        let flags = GenericContextDescriptorFlags::new(0x0);
        assert!(!flags.has_type_packs());
        assert!(!flags.has_conditional_inverted_protocols());
        assert!(!flags.has_values());
    }

    // ---- Conformance Flags Tests ----

    #[test]
    fn test_conformance_flags() {
        // kind=DirectTypeDescriptor(0), retroactive=false, unique=false,
        // num_conditional=0, resilient=false, generic_witness=false, protocol=false
        let flags = ConformanceFlags::new(0);
        assert_eq!(flags.kind(), Some(TypeReferenceKind::DirectTypeDescriptor));
        assert!(!flags.is_retroactive());
        assert!(!flags.is_synthesized_non_unique());

        // kind=IndirectObjCClass(3) = (3 << 3) = 24
        let flags = ConformanceFlags::new(24);
        assert_eq!(flags.kind(), Some(TypeReferenceKind::IndirectObjCClass));

        // retroactive=true (bit 6 = 64)
        let flags = ConformanceFlags::new(64);
        assert!(flags.is_retroactive());
    }

    // ---- Type Reference Kind Tests ----

    #[test]
    fn test_type_reference_kind() {
        assert_eq!(TypeReferenceKind::from_u8(0), Some(TypeReferenceKind::DirectTypeDescriptor));
        assert_eq!(TypeReferenceKind::from_u8(1), Some(TypeReferenceKind::IndirectTypeDescriptor));
        assert_eq!(TypeReferenceKind::from_u8(2), Some(TypeReferenceKind::DirectObjCClassName));
        assert_eq!(TypeReferenceKind::from_u8(3), Some(TypeReferenceKind::IndirectObjCClass));
        assert_eq!(TypeReferenceKind::from_u8(99), None);
    }

    // ---- Generic Requirement Kind Tests ----

    #[test]
    fn test_generic_requirement_kind() {
        assert_eq!(GenericRequirementKind::from_u8(0), Some(GenericRequirementKind::Protocol));
        assert_eq!(GenericRequirementKind::from_u8(1), Some(GenericRequirementKind::SameType));
        assert_eq!(GenericRequirementKind::from_u8(0x1F), Some(GenericRequirementKind::Layout));
        assert_eq!(GenericRequirementKind::from_u8(99), None);
    }

    // ---- Generic Requirement Flags Tests ----

    #[test]
    fn test_generic_requirement_flags() {
        // kind=Protocol(0), pack=false, extra=false
        let flags = GenericRequirementFlags::new(0);
        assert_eq!(flags.kind(), Some(GenericRequirementKind::Protocol));
        assert!(!flags.is_pack_requirement());

        // kind=SameType(1), pack=true(bit 6=64)
        let flags = GenericRequirementFlags::new(1 | 64);
        assert_eq!(flags.kind(), Some(GenericRequirementKind::SameType));
        assert!(flags.is_pack_requirement());

        // has_extra_argument = bit 7 = 128
        let flags = GenericRequirementFlags::new(128);
        assert!(flags.has_extra_argument());
    }

    // ---- Protocol Requirement Kind Tests ----

    #[test]
    fn test_protocol_requirement_kind() {
        assert_eq!(ProtocolRequirementKind::from_u8(0), Some(ProtocolRequirementKind::Method));
        assert_eq!(ProtocolRequirementKind::from_u8(1), Some(ProtocolRequirementKind::Init));
        assert_eq!(ProtocolRequirementKind::from_u8(2), Some(ProtocolRequirementKind::Getter));
        assert_eq!(ProtocolRequirementKind::from_u8(3), Some(ProtocolRequirementKind::Setter));
        assert_eq!(ProtocolRequirementKind::from_u8(99), None);
    }

    // ---- Protocol Requirement Flags Tests ----

    #[test]
    fn test_protocol_requirement_flags() {
        // kind=Method(0), instance=false, async=false
        let flags = ProtocolRequirementFlags::new(0);
        assert_eq!(flags.kind(), Some(ProtocolRequirementKind::Method));
        assert!(!flags.is_instance());
        assert!(!flags.is_async());

        // kind=Getter(2), instance=true(bit 4=16)
        let flags = ProtocolRequirementFlags::new(2 | 16);
        assert_eq!(flags.kind(), Some(ProtocolRequirementKind::Getter));
        assert!(flags.is_instance());

        // async=true(bit 5=32)
        let flags = ProtocolRequirementFlags::new(32);
        assert!(flags.is_async());

        // extra_discriminator = bits 16-31 = (0x1234 << 16)
        let flags = ProtocolRequirementFlags::new(0x1234 << 16);
        assert_eq!(flags.extra_discriminator(), 0x1234);
    }

    // ---- Method Descriptor Flags Tests ----

    #[test]
    fn test_method_descriptor_flags() {
        let flags = MethodDescriptorFlags::new(0);
        assert_eq!(flags.kind(), Some(MethodDescriptorKind::Method));
        assert!(!flags.is_instance());
        assert!(!flags.is_dynamic());

        // kind=Init(1), instance=true(16), dynamic=true(32)
        let flags = MethodDescriptorFlags::new(1 | 16 | 32);
        assert_eq!(flags.kind(), Some(MethodDescriptorKind::Init));
        assert!(flags.is_instance());
        assert!(flags.is_dynamic());
    }

    // ---- Field Record Flags Tests ----

    #[test]
    fn test_field_record_flags() {
        let flags = FieldRecordFlags::new(0);
        assert!(!flags.is_indirect_case());
        assert!(!flags.is_var());

        let flags = FieldRecordFlags::new(0x3); // indirect=true, var=true
        assert!(flags.is_indirect_case());
        assert!(flags.is_var());
    }

    // ---- Field Descriptor Kind Tests ----

    #[test]
    fn test_field_descriptor_kind() {
        assert_eq!(FieldDescriptorKind::from_u8(0), Some(FieldDescriptorKind::Struct));
        assert_eq!(FieldDescriptorKind::from_u8(1), Some(FieldDescriptorKind::Class));
        assert_eq!(FieldDescriptorKind::from_u8(2), Some(FieldDescriptorKind::Enum));
        assert_eq!(FieldDescriptorKind::from_u8(99), None);
    }

    // ---- Metadata Initialization Kind Tests ----

    #[test]
    fn test_metadata_initialization_kind() {
        assert_eq!(MetadataInitializationKind::from_u8(0), Some(MetadataInitializationKind::None));
        assert_eq!(MetadataInitializationKind::from_u8(1), Some(MetadataInitializationKind::Singleton));
        assert_eq!(MetadataInitializationKind::from_u8(2), Some(MetadataInitializationKind::Foreign));
        assert_eq!(MetadataInitializationKind::from_u8(99), None);
    }

    // ---- Invertible Protocol Kind Tests ----

    #[test]
    fn test_invertible_protocol_kind() {
        assert_eq!(InvertibleProtocolKind::from_u8(0), Some(InvertibleProtocolKind::Sendable));
        assert_eq!(InvertibleProtocolKind::from_u8(1), Some(InvertibleProtocolKind::Class));
        assert_eq!(InvertibleProtocolKind::from_u8(6), Some(InvertibleProtocolKind::NonEscapable));
        assert_eq!(InvertibleProtocolKind::from_u8(99), None);
    }

    // ---- Invertible Protocol Set Tests ----

    #[test]
    fn test_invertible_protocol_set() {
        let set = InvertibleProtocolSet::new(0b101); // bit 0 (Sendable) and bit 2 (Escapable)
        assert!(set.contains(InvertibleProtocolKind::Sendable));
        assert!(!set.contains(InvertibleProtocolKind::Class));
        assert!(set.contains(InvertibleProtocolKind::Escapable));
    }

    // ---- Generic Param Kind Tests ----

    #[test]
    fn test_generic_param_kind() {
        assert_eq!(GenericParamKind::from_u8(0), Some(GenericParamKind::Type));
        assert_eq!(GenericParamKind::from_u8(1), Some(GenericParamKind::TypePack));
        assert_eq!(GenericParamKind::from_u8(2), Some(GenericParamKind::Value));
        assert_eq!(GenericParamKind::from_u8(99), None);
    }

    // ---- Generic Requirement Layout Kind Tests ----

    #[test]
    fn test_generic_requirement_layout_kind() {
        assert_eq!(GenericRequirementLayoutKind::from_u8(0), GenericRequirementLayoutKind::NativeObject);
        assert_eq!(GenericRequirementLayoutKind::from_u8(1), GenericRequirementLayoutKind::ObjCPointer);
        assert_eq!(GenericRequirementLayoutKind::from_u8(0xFF), GenericRequirementLayoutKind::Unknown);
    }

    // ---- Target Context Descriptor Tests ----

    #[test]
    fn test_target_context_descriptor() {
        let flags = ContextDescriptorFlags::new(16); // Class
        let desc = TargetContextDescriptor::new(flags, 0, 0x1000);
        assert_eq!(desc.kind(), Some(ContextDescriptorKind::Class));
        assert_eq!(desc.address, 0x1000);
    }

    // ---- Target Class Descriptor Tests ----

    #[test]
    fn test_target_class_descriptor() {
        let flags = ContextDescriptorFlags::new(16); // Class
        let base = TargetContextDescriptor::new(flags, 0, 0x1000);
        let type_ctx = TargetTypeContextDescriptor {
            base,
            name: "MyClass".into(),
            access_function_ptr: 0,
            fields_ptr: 0,
            type_flags: 0,
        };
        let cls = TargetClassDescriptor::new(type_ctx);
        assert_eq!(cls.name(), "MyClass");
        assert!(!cls.is_type_specific_metadata());
        assert!(!cls.uses_native_refcounting());
    }

    // ---- Target Struct Descriptor Tests ----

    #[test]
    fn test_target_struct_descriptor() {
        let flags = ContextDescriptorFlags::new(17); // Struct
        let base = TargetContextDescriptor::new(flags, 0, 0x2000);
        let type_ctx = TargetTypeContextDescriptor {
            base,
            name: "MyStruct".into(),
            access_function_ptr: 0,
            fields_ptr: 0,
            type_flags: 0,
        };
        let mut s = TargetStructDescriptor::new(type_ctx);
        s.num_fields = 3;
        assert_eq!(s.name(), "MyStruct");
        assert_eq!(s.num_fields, 3);
    }

    // ---- Target Enum Descriptor Tests ----

    #[test]
    fn test_target_enum_descriptor() {
        let flags = ContextDescriptorFlags::new(18); // Enum
        let base = TargetContextDescriptor::new(flags, 0, 0x3000);
        let type_ctx = TargetTypeContextDescriptor {
            base,
            name: "MyEnum".into(),
            access_function_ptr: 0,
            fields_ptr: 0,
            type_flags: 0,
        };
        let mut e = TargetEnumDescriptor::new(type_ctx);
        e.num_cases = 5;
        assert_eq!(e.name(), "MyEnum");
        assert_eq!(e.num_cases, 5);
        assert!(!e.is_multi_payload());
    }

    // ---- Target Protocol Descriptor Tests ----

    #[test]
    fn test_target_protocol_descriptor() {
        let flags = ContextDescriptorFlags::new(3); // Protocol
        let base = TargetContextDescriptor::new(flags, 0, 0x4000);
        let mut desc = TargetProtocolDescriptor::new(base, "MyProtocol".into());
        desc.num_requirements = 4;
        assert_eq!(desc.name(), "MyProtocol");
        assert_eq!(desc.num_requirements, 4);
    }

    // ---- Target Protocol Conformance Descriptor Tests ----

    #[test]
    fn test_target_protocol_conformance_descriptor() {
        let mut desc = TargetProtocolConformanceDescriptor::new(0x5000, 0);
        desc.protocol = 0x100;
        desc.type_ref = 0x200;
        assert_eq!(desc.address, 0x5000);
        assert_eq!(desc.protocol, 0x100);
        assert!(!desc.is_retroactive());
        assert!(!desc.has_resilient_witnesses());
    }

    // ---- Target Generic Requirements Descriptor Tests ----

    #[test]
    fn test_target_generic_requirements_descriptor() {
        // flags = kind=Protocol(0)
        let desc = TargetGenericRequirementsDescriptor::new(0x6000, 0);
        assert_eq!(desc.address, 0x6000);
        assert_eq!(desc.kind(), Some(GenericRequirementKind::Protocol));
    }

    // ---- Target Protocol Requirement Tests ----

    #[test]
    fn test_target_protocol_requirement() {
        // flags = kind=Method(0), instance=true(16)
        let req = TargetProtocolRequirement::new(0x7000, 0 | 16);
        assert_eq!(req.address, 0x7000);
        assert_eq!(req.kind(), Some(ProtocolRequirementKind::Method));
        assert!(req.is_instance());
        assert!(!req.is_async());
    }

    // ---- Field Descriptor Tests ----

    #[test]
    fn test_field_descriptor() {
        let mut fd = FieldDescriptor::new(0x8000);
        fd.mangled_type_name = "4main7MyClassC".into();
        fd.kind = FieldDescriptorKind::Class;
        fd.num_fields = 2;
        fd.field_records.push(FieldRecord::new(0x8010, 0));
        assert_eq!(fd.base(), "4main7MyClassC");
        assert_eq!(fd.kind, FieldDescriptorKind::Class);
        assert_eq!(fd.num_fields, 2);
        assert_eq!(fd.field_records.len(), 1);
    }

    // ---- Field Record Tests ----

    #[test]
    fn test_field_record() {
        let fr = FieldRecord::new(0x9000, 0);
        assert_eq!(fr.address, 0x9000);
        assert!(!fr.is_indirect());
        assert!(!fr.is_var());

        let fr = FieldRecord::new(0x9000, 0x3);
        assert!(fr.is_indirect());
        assert!(fr.is_var());
    }

    // ---- Builtin Type Descriptor Tests ----

    #[test]
    fn test_builtin_type_descriptor() {
        let mut btd = BuiltinTypeDescriptor::new(0xA000);
        btd.type_name = "Builtin.Int32".into();
        btd.size = 4;
        btd.alignment = 4;
        btd.stride = 4;
        assert_eq!(btd.type_name, "Builtin.Int32");
        assert_eq!(btd.size, 4);
    }

    // ---- Associated Type Descriptor Tests ----

    #[test]
    fn test_associated_type_descriptor() {
        let mut atd = AssociatedTypeDescriptor::new(0xB000);
        atd.num_associated_types = 1;
        let mut atr = AssociatedTypeRecord::new(0xB010);
        atr.name = "Element".into();
        atr.substituted_type = "Si".into();
        atd.associated_type_records.push(atr);
        assert_eq!(atd.num_associated_types, 1);
        assert_eq!(atd.associated_type_records[0].name, "Element");
    }

    // ---- Capture Descriptor Tests ----

    #[test]
    fn test_capture_descriptor() {
        let mut cd = CaptureDescriptor::new(0xC000);
        cd.num_capture_types = 2;
        let ctr = CaptureTypeRecord::new(0xC010);
        cd.capture_types.push(ctr);
        assert_eq!(cd.num_capture_types, 2);
        assert_eq!(cd.capture_types.len(), 1);
    }

    // ---- Entry Point Tests ----

    #[test]
    fn test_entry_point() {
        let ep = EntryPoint::new(0xD000);
        assert_eq!(ep.address, 0xD000);
        assert_eq!(ep.init_offset, 0);
    }

    // ---- Extra Class Descriptor Flags Tests ----

    #[test]
    fn test_extra_class_descriptor_flags() {
        let flags = ExtraClassDescriptorFlags::new(0);
        assert!(!flags.has_objc_resilient_class_stub());
        assert!(!flags.has_variant_superclass());

        let flags = ExtraClassDescriptorFlags::new(0x7);
        assert!(flags.has_objc_resilient_class_stub());
        assert!(flags.has_variant_superclass());
        assert!(flags.has_transient_pointer());
    }

    // ---- Generic Context Header Tests ----

    #[test]
    fn test_generic_context_header() {
        let mut hdr = TargetGenericContextDescriptorHeader::new(0xE000, 0x7);
        hdr.num_params = 3;
        hdr.num_requirements = 5;
        assert!(hdr.has_type_packs());
        assert!(hdr.has_conditional_inverted_protocols());
        assert!(hdr.has_values());
        assert_eq!(hdr.num_params, 3);
        assert_eq!(hdr.num_requirements, 5);
    }

    // ---- Relative Pointer Tests ----

    #[test]
    fn test_relative_pointers() {
        let rp = TargetRelativeContextPointer::new(0x10);
        assert_eq!(rp.resolve(0x1000), 0x1010);

        let rp2 = TargetRelativeContextPointer::new(-4);
        assert_eq!(rp2.resolve(0x1000), 0x0FFC);

        let rpr = TargetRelativeProtocolRequirementPointer::new(0x20);
        assert_eq!(rpr.resolve(0x2000), 0x2020);
    }

    // ---- Multi-Payload Enum Descriptor Tests ----

    #[test]
    fn test_multi_payload_enum_descriptor() {
        let mut mp = MultiPayloadEnumDescriptor::new(0xF000);
        mp.num_payloads = 3;
        mp.payload_size = 8;
        mp.offsets = vec![0, 8, 16];
        assert_eq!(mp.num_payloads, 3);
        assert_eq!(mp.offsets.len(), 3);
    }

    // ---- Metadata Source Record Tests ----

    #[test]
    fn test_metadata_source_record() {
        let mut msr = MetadataSourceRecord::new(0x10000);
        msr.mangled_type_name = "4main5PointV".into();
        msr.accessor = 0x10;
        assert_eq!(msr.mangled_type_name, "4main5PointV");
    }

    // ---- VTable Descriptor Header Tests ----

    #[test]
    fn test_vtable_descriptor_header() {
        let mut vdh = TargetVTableDescriptorHeader::new(0x11000);
        vdh.vtable_offset = 64;
        vdh.vtable_size = 20;
        assert_eq!(vdh.vtable_offset, 64);
        assert_eq!(vdh.vtable_size, 20);
    }

    // ---- Method Override Descriptor Tests ----

    #[test]
    fn test_method_override_descriptor() {
        let mut mod_ = TargetMethodOverrideDescriptor::new(0x12000);
        mod_.overridden_class = 0x100;
        mod_.overridden_method = 0x200;
        assert_eq!(mod_.overridden_class, 0x100);
        assert_eq!(mod_.overridden_method, 0x200);
    }

    // ---- Resilient Superclass Tests ----

    #[test]
    fn test_resilient_superclass() {
        let mut rs = TargetResilientSuperclass::new(0x13000);
        rs.superclass = 0x300;
        assert_eq!(rs.superclass, 0x300);
    }

    // ---- Resilient Witness Header Tests ----

    #[test]
    fn test_resilient_witness_header() {
        let mut rwh = TargetResilientWitnessHeader::new(0x14000);
        rwh.num_witnesses = 2;
        rwh.witnesses.push(TargetResilientWitness::new(0x14010));
        rwh.witnesses.push(TargetResilientWitness::new(0x14020));
        assert_eq!(rwh.num_witnesses, 2);
        assert_eq!(rwh.witnesses.len(), 2);
    }

    // ---- Generic Witness Table Tests ----

    #[test]
    fn test_generic_witness_table() {
        let mut gwt = TargetGenericWitnessTable::new(0x15000);
        gwt.witness_table_size = 10;
        gwt.witness_table_private_size = 2;
        gwt.requires_runtime_instantiation = true;
        assert!(gwt.requires_runtime_instantiation);
        assert_eq!(gwt.witness_table_size, 10);
    }

    // ---- ObjC Resilient Class Stub Info Tests ----

    #[test]
    fn test_objc_resilient_class_stub_info() {
        let mut info = TargetObjCResilientClassStubInfo::new(0x16000);
        info.stub = 0x500;
        assert_eq!(info.stub, 0x500);
    }

    // ---- Singleton Metadata Initialization Tests ----

    #[test]
    fn test_singleton_metadata_initialization() {
        let mut smi = TargetSingletonMetadataInitialization::new(0x17000);
        smi.initialization_cache = 0x100;
        smi.completion_function = 0x200;
        assert_eq!(smi.initialization_cache, 0x100);
        assert_eq!(smi.completion_function, 0x200);
    }

    // ---- Foreign Metadata Initialization Tests ----

    #[test]
    fn test_foreign_metadata_initialization() {
        let mut fmi = TargetForeignMetadataInitialization::new(0x18000);
        fmi.completion_function = 0x300;
        assert_eq!(fmi.completion_function, 0x300);
    }

    // ---- Type Context Descriptor Tests ----

    #[test]
    fn test_type_context_descriptor() {
        let flags = ContextDescriptorFlags::new(17); // Struct
        let base = TargetContextDescriptor::new(flags, 0, 0x19000);
        let tcd = TargetTypeContextDescriptor {
            base,
            name: "MyType".into(),
            access_function_ptr: 0x100,
            fields_ptr: 0x200,
            type_flags: 0,
        };
        assert_eq!(tcd.name(), "MyType");
        assert!(!tcd.has_metadata_initialization());
        assert!(!tcd.has_layout_string());
    }

    // ---- Type Generic Context Descriptor Header Tests ----

    #[test]
    fn test_type_generic_context_descriptor_header() {
        let base = TargetGenericContextDescriptorHeader::new(0x1A000, 0);
        let mut tgc = TargetTypeGenericContextDescriptorHeader::new(base);
        tgc.metadata_initialization = MetadataInitializationKind::Singleton;
        assert_eq!(
            tgc.metadata_initialization,
            MetadataInitializationKind::Singleton
        );
    }

    // ---- Method Descriptor Tests ----

    #[test]
    fn test_method_descriptor() {
        // kind=Init(1), instance=true(16)
        let md = TargetMethodDescriptor::new(0x1B000, 1 | 16);
        assert_eq!(md.kind(), Some(MethodDescriptorKind::Init));
        assert!(md.is_instance());
        assert!(!md.is_dynamic());
    }

    // ---- Override Table Header Tests ----

    #[test]
    fn test_override_table_header() {
        let mut oth = TargetOverrideTableHeader::new(0x1C000);
        oth.num_entries = 5;
        assert_eq!(oth.num_entries, 5);
    }
}
