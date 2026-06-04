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

/// A single field within a type.
#[derive(Debug, Clone)]
pub struct FieldRecord {
    /// Field name (if known).
    pub name: Option<String>,
    /// Byte offset from the start of the type.
    pub offset: u32,
    /// The mangled type name of this field.
    pub field_type: Option<String>,
}

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
}
