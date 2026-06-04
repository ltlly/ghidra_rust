//! Objective-C runtime structures parser.
//!
//! Parses the Objective-C runtime metadata embedded in Mach-O binaries.
//! This metadata is used by the Objective-C runtime for message dispatch,
//! class introspection, and dynamic method resolution.
//!
//! # Parsed Sections
//!
//! - `__objc_classlist` -- list of class pointers
//! - `__objc_catlist`  -- list of category pointers
//! - `__objc_protolist` -- list of protocol pointers
//! - `__objc_classrefs` -- class references used in code
//! - `__objc_selrefs` -- selector string references
//! - `__objc_methlist` -- method lists
//! - `__objc_data` -- class, category, and protocol data
//! - `__objc_imageinfo` -- Objective-C image flags
//! - `__objc_nlclslist` -- non-lazy class list
//!
//! # Type Encodings
//!
//! The Objective-C runtime uses a compact character encoding to describe
//! method signatures. These type encodings are parsed into Rust types.

use std::collections::{BTreeMap, HashMap};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Class flags (from `class_ro_t`).
pub mod class_flags {
    /// Class is a metaclass.
    pub const RO_META: u32 = 1 << 0;
    /// Class has Swift extensions.
    pub const RO_HAS_SWIFT_EXTENSIONS: u32 = 1 << 1;
    /// Class root (no superclass).
    pub const RO_ROOT: u32 = 1 << 2;
    /// Hidden class.
    pub const RO_HIDDEN: u32 = 1 << 3;
    /// Exception class.
    pub const RO_EXCEPTION: u32 = 1 << 4;
    /// Class is in an ARC compiled image.
    pub const RO_IS_ARC: u32 = 1 << 5;
    /// Class has C++ constructors/destructors.
    pub const RO_HAS_CXX_STRUCTORS: u32 = 1 << 6;
    /// Class has associated objects.
    pub const RO_HAS_ASSOC_OBJECTS: u32 = 1 << 7;
    /// Class is a realised / runtime-allocated class.
    pub const RO_REALIZED: u32 = 1 << 31;

    /// Return a human-readable list of flag names.
    pub fn describe_flags(flags: u32) -> Vec<&'static str> {
        let mut names = Vec::new();
        if flags & RO_META != 0 {
            names.push("META");
        }
        if flags & RO_HAS_SWIFT_EXTENSIONS != 0 {
            names.push("SWIFT_EXTENSIONS");
        }
        if flags & RO_ROOT != 0 {
            names.push("ROOT");
        }
        if flags & RO_HIDDEN != 0 {
            names.push("HIDDEN");
        }
        if flags & RO_EXCEPTION != 0 {
            names.push("EXCEPTION");
        }
        if flags & RO_IS_ARC != 0 {
            names.push("ARC");
        }
        if flags & RO_HAS_CXX_STRUCTORS != 0 {
            names.push("CXX_STRUCTORS");
        }
        if flags & RO_HAS_ASSOC_OBJECTS != 0 {
            names.push("ASSOC_OBJECTS");
        }
        if flags & RO_REALIZED != 0 {
            names.push("REALIZED");
        }
        names
    }
}

/// Image info flags (from `__objc_imageinfo`).
pub mod image_flags {
    /// Image supports garbage collection (deprecated).
    pub const SUPPORTS_GC: u32 = 1 << 0;
    /// Image requires garbage collection (deprecated).
    pub const REQUIRES_GC: u32 = 1 << 1;
    /// Image is compiled for ARC.
    pub const SUPPORTS_ARC: u32 = 1 << 2;
    /// Image is compiled with Swift.
    pub const SUPPORTS_SWIFT: u32 = 1 << 3;
    /// Image has category class properties.
    pub const HAS_CATEGORY_CLASS_PROPERTIES: u32 = 1 << 4;

    /// Describe the flags in human-readable form.
    pub fn describe(flags: u32) -> Vec<&'static str> {
        let mut names = Vec::new();
        if flags & SUPPORTS_GC != 0 {
            names.push("GC");
        }
        if flags & REQUIRES_GC != 0 {
            names.push("REQUIRES_GC");
        }
        if flags & SUPPORTS_ARC != 0 {
            names.push("ARC");
        }
        if flags & SUPPORTS_SWIFT != 0 {
            names.push("SWIFT");
        }
        if flags & HAS_CATEGORY_CLASS_PROPERTIES != 0 {
            names.push("CATEGORY_CLASS_PROPS");
        }
        names
    }
}

// ---------------------------------------------------------------------------
// Type encoding
// ---------------------------------------------------------------------------

/// An Objective-C type encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeEncoding {
    /// `c` -- char
    Char,
    /// `i` -- int
    Int,
    /// `s` -- short
    Short,
    /// `l` -- long
    Long,
    /// `q` -- long long
    LongLong,
    /// `C` -- unsigned char
    UnsignedChar,
    /// `I` -- unsigned int
    UnsignedInt,
    /// `S` -- unsigned short
    UnsignedShort,
    /// `L` -- unsigned long
    UnsignedLong,
    /// `Q` -- unsigned long long
    UnsignedLongLong,
    /// `f` -- float
    Float,
    /// `d` -- double
    Double,
    /// `B` -- bool (_Bool)
    Bool,
    /// `v` -- void
    Void,
    /// `*` -- char* (C string)
    CString,
    /// `@` -- object (id)
    Object,
    /// `#` -- Class
    Class,
    /// `:` -- SEL (selector)
    Selector,
    /// `[N type]` -- array
    Array {
        count: usize,
        element_type: Box<TypeEncoding>,
    },
    /// `{name=fields...}` -- struct
    Struct {
        name: String,
        fields: Vec<FieldEncoding>,
    },
    /// `(fields...)` -- union
    Union { fields: Vec<FieldEncoding> },
    /// `^type` -- pointer
    Pointer { target: Box<TypeEncoding> },
    /// `?` -- unknown
    Unknown,
    /// `bN` -- bitfield
    BitField { size: usize },
    /// `r` -- const
    Const { inner: Box<TypeEncoding> },
    /// `n` -- in
    In { inner: Box<TypeEncoding> },
    /// `N` -- inout
    InOut { inner: Box<TypeEncoding> },
    /// `o` -- out
    Out { inner: Box<TypeEncoding> },
    /// `O` -- bycopy
    ByCopy { inner: Box<TypeEncoding> },
    /// `R` -- byref
    ByRef { inner: Box<TypeEncoding> },
    /// `V` -- oneway
    OneWay { inner: Box<TypeEncoding> },
    /// `"..."@?` -- block
    Block,
}

impl TypeEncoding {
    /// Return a human-readable description of this type encoding.
    pub fn to_type_string(&self) -> String {
        match self {
            Self::Char => "char".into(),
            Self::Int => "int".into(),
            Self::Short => "short".into(),
            Self::Long => "long".into(),
            Self::LongLong => "long long".into(),
            Self::UnsignedChar => "unsigned char".into(),
            Self::UnsignedInt => "unsigned int".into(),
            Self::UnsignedShort => "unsigned short".into(),
            Self::UnsignedLong => "unsigned long".into(),
            Self::UnsignedLongLong => "unsigned long long".into(),
            Self::Float => "float".into(),
            Self::Double => "double".into(),
            Self::Bool => "bool".into(),
            Self::Void => "void".into(),
            Self::CString => "char*".into(),
            Self::Object => "id".into(),
            Self::Class => "Class".into(),
            Self::Selector => "SEL".into(),
            Self::Array {
                count,
                element_type,
            } => {
                format!("{}[{}]", element_type.to_type_string(), count)
            }
            Self::Struct { name, fields } => {
                let field_strs: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        format!(
                            "{} {}",
                            f.ty.to_type_string(),
                            f.name.as_deref().unwrap_or("")
                        )
                    })
                    .collect();
                format!(
                    "{{{}}}",
                    std::iter::once(name.as_str())
                        .chain(field_strs.iter().map(|s| s.as_str()))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            Self::Union { fields } => {
                let field_strs: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        format!(
                            "{} {}",
                            f.ty.to_type_string(),
                            f.name.as_deref().unwrap_or("")
                        )
                    })
                    .collect();
                format!("({})", field_strs.join(" "))
            }
            Self::Pointer { target } => format!("{}*", target.to_type_string()),
            Self::Unknown => "?".into(),
            Self::BitField { size } => format!("b{size}"),
            Self::Const { inner } => format!("const {}", inner.to_type_string()),
            Self::In { inner } => format!("in {}", inner.to_type_string()),
            Self::InOut { inner } => format!("inout {}", inner.to_type_string()),
            Self::Out { inner } => format!("out {}", inner.to_type_string()),
            Self::ByCopy { inner } => format!("bycopy {}", inner.to_type_string()),
            Self::ByRef { inner } => format!("byref {}", inner.to_type_string()),
            Self::OneWay { inner } => format!("oneway {}", inner.to_type_string()),
            Self::Block => "block".into(),
        }
    }
}

/// A field inside a struct or union encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldEncoding {
    pub name: Option<String>,
    pub ty: TypeEncoding,
}

/// Parse an Objective-C type encoding string into a `TypeEncoding` tree.
///
/// # Arguments
///
/// * `encoding` - An Objective-C type encoding string (e.g. `"@16@0:8"`).
///
/// Returns the full encoding and the number of characters consumed.
pub fn parse_type_encoding(encoding: &str) -> Result<(TypeEncoding, usize), String> {
    let chars: Vec<char> = encoding.chars().collect();
    let mut pos = 0;
    let ty = parse_type_encoding_at(&chars, &mut pos)?;
    Ok((ty, pos))
}

fn parse_type_encoding_at(chars: &[char], pos: &mut usize) -> Result<TypeEncoding, String> {
    if *pos >= chars.len() {
        return Ok(TypeEncoding::Unknown);
    }

    // Handle stack frame offsets (digits before the type)
    let mut _frame_offset: u32 = 0;
    while *pos < chars.len() && chars[*pos].is_ascii_digit() {
        _frame_offset = _frame_offset * 10 + (chars[*pos] as u32 - b'0' as u32);
        *pos += 1;
    }

    if *pos >= chars.len() {
        return Ok(TypeEncoding::Unknown);
    }

    let c = chars[*pos];
    match c {
        'r' => {
            *pos += 1;
            Ok(TypeEncoding::Const {
                inner: Box::new(parse_type_encoding_at(chars, pos)?),
            })
        }
        'n' => {
            *pos += 1;
            Ok(TypeEncoding::In {
                inner: Box::new(parse_type_encoding_at(chars, pos)?),
            })
        }
        'N' => {
            *pos += 1;
            Ok(TypeEncoding::InOut {
                inner: Box::new(parse_type_encoding_at(chars, pos)?),
            })
        }
        'o' => {
            *pos += 1;
            Ok(TypeEncoding::Out {
                inner: Box::new(parse_type_encoding_at(chars, pos)?),
            })
        }
        'O' => {
            *pos += 1;
            Ok(TypeEncoding::ByCopy {
                inner: Box::new(parse_type_encoding_at(chars, pos)?),
            })
        }
        'R' => {
            *pos += 1;
            Ok(TypeEncoding::ByRef {
                inner: Box::new(parse_type_encoding_at(chars, pos)?),
            })
        }
        'V' => {
            *pos += 1;
            Ok(TypeEncoding::OneWay {
                inner: Box::new(parse_type_encoding_at(chars, pos)?),
            })
        }
        '^' => {
            *pos += 1;
            Ok(TypeEncoding::Pointer {
                target: Box::new(parse_type_encoding_at(chars, pos)?),
            })
        }
        '@' => {
            *pos += 1;
            if *pos < chars.len() && chars[*pos] == '"' {
                *pos += 1;
                while *pos < chars.len() && chars[*pos] != '"' {
                    *pos += 1;
                }
                if *pos < chars.len() {
                    *pos += 1;
                }
            }
            if *pos < chars.len() && chars[*pos] == '?' {
                *pos += 1;
                return Ok(TypeEncoding::Block);
            }
            Ok(TypeEncoding::Object)
        }
        '#' => {
            *pos += 1;
            Ok(TypeEncoding::Class)
        }
        ':' => {
            *pos += 1;
            Ok(TypeEncoding::Selector)
        }
        '[' => {
            *pos += 1;
            let mut count = 0usize;
            while *pos < chars.len() && chars[*pos].is_ascii_digit() {
                count = count * 10 + (chars[*pos] as usize - '0' as usize);
                *pos += 1;
            }
            let element_type = parse_type_encoding_at(chars, pos)?;
            if *pos < chars.len() && chars[*pos] == ']' {
                *pos += 1;
            }
            Ok(TypeEncoding::Array {
                count,
                element_type: Box::new(element_type),
            })
        }
        '{' => {
            *pos += 1;
            let mut name = String::new();
            while *pos < chars.len() && chars[*pos] != '=' && chars[*pos] != '}' {
                name.push(chars[*pos]);
                *pos += 1;
            }
            let mut fields = Vec::new();
            if *pos < chars.len() && chars[*pos] == '=' {
                *pos += 1;
                while *pos < chars.len() && chars[*pos] != '}' {
                    let field_name = if *pos < chars.len() && chars[*pos] == '"' {
                        *pos += 1;
                        let mut n = String::new();
                        while *pos < chars.len() && chars[*pos] != '"' {
                            n.push(chars[*pos]);
                            *pos += 1;
                        }
                        if *pos < chars.len() {
                            *pos += 1;
                        }
                        Some(n)
                    } else {
                        None
                    };
                    let field_ty = parse_type_encoding_at(chars, pos)?;
                    fields.push(FieldEncoding {
                        name: field_name,
                        ty: field_ty,
                    });
                }
            }
            if *pos < chars.len() && chars[*pos] == '}' {
                *pos += 1;
            }
            Ok(TypeEncoding::Struct { name, fields })
        }
        '(' => {
            *pos += 1;
            let mut fields = Vec::new();
            while *pos < chars.len() && chars[*pos] != ')' {
                let field_ty = parse_type_encoding_at(chars, pos)?;
                fields.push(FieldEncoding {
                    name: None,
                    ty: field_ty,
                });
            }
            if *pos < chars.len() && chars[*pos] == ')' {
                *pos += 1;
            }
            Ok(TypeEncoding::Union { fields })
        }
        'b' => {
            *pos += 1;
            let mut size = 0usize;
            while *pos < chars.len() && chars[*pos].is_ascii_digit() {
                size = size * 10 + (chars[*pos] as usize - '0' as usize);
                *pos += 1;
            }
            Ok(TypeEncoding::BitField { size })
        }
        'c' => {
            *pos += 1;
            Ok(TypeEncoding::Char)
        }
        'i' => {
            *pos += 1;
            Ok(TypeEncoding::Int)
        }
        's' => {
            *pos += 1;
            Ok(TypeEncoding::Short)
        }
        'l' => {
            *pos += 1;
            Ok(TypeEncoding::Long)
        }
        'q' => {
            *pos += 1;
            Ok(TypeEncoding::LongLong)
        }
        'C' => {
            *pos += 1;
            Ok(TypeEncoding::UnsignedChar)
        }
        'I' => {
            *pos += 1;
            Ok(TypeEncoding::UnsignedInt)
        }
        'S' => {
            *pos += 1;
            Ok(TypeEncoding::UnsignedShort)
        }
        'L' => {
            *pos += 1;
            Ok(TypeEncoding::UnsignedLong)
        }
        'Q' => {
            *pos += 1;
            Ok(TypeEncoding::UnsignedLongLong)
        }
        'f' => {
            *pos += 1;
            Ok(TypeEncoding::Float)
        }
        'd' => {
            *pos += 1;
            Ok(TypeEncoding::Double)
        }
        'B' => {
            *pos += 1;
            Ok(TypeEncoding::Bool)
        }
        'v' => {
            *pos += 1;
            Ok(TypeEncoding::Void)
        }
        '*' => {
            *pos += 1;
            Ok(TypeEncoding::CString)
        }
        '?' => {
            *pos += 1;
            Ok(TypeEncoding::Unknown)
        }
        _ => {
            *pos += 1;
            Ok(TypeEncoding::Unknown)
        }
    }
}

// ---------------------------------------------------------------------------
// Objective-C data structures
// ---------------------------------------------------------------------------

/// Represents the `objc_class` structure at a known address.
#[derive(Debug, Clone)]
pub struct ObjcClass {
    /// Address of the class structure in memory.
    pub address: u64,
    /// Pointer to the metaclass object.
    pub isa: u64,
    /// Pointer to the superclass structure.
    pub super_class: u64,
    /// Pointer to the method cache.
    pub cache: u64,
    /// Pointer to the vtable.
    pub vtable: u64,
    /// Pointer to the `class_ro_t` read-only data.
    pub data: u64,
    /// Resolved class name (populated during parsing).
    pub name: Option<String>,
    /// Read-only class metadata.
    pub class_ro: Option<ClassRO>,
    /// Whether this is a metaclass.
    pub is_meta: bool,
    /// Whether this class has been realised by the runtime.
    pub is_realised: bool,
    /// Whether this class has associated objects.
    pub has_assoc_objects: bool,
    /// Whether this class has C++ ctors/dtors.
    pub has_cxx_structors: bool,
}

impl ObjcClass {
    /// Create a new empty class descriptor.
    pub fn new(address: u64) -> Self {
        ObjcClass {
            address,
            isa: 0,
            super_class: 0,
            cache: 0,
            vtable: 0,
            data: 0,
            name: None,
            class_ro: None,
            is_meta: false,
            is_realised: false,
            has_assoc_objects: false,
            has_cxx_structors: false,
        }
    }

    /// Derive flags from the class_ro data.
    pub fn apply_ro_flags(&mut self) {
        if let Some(ref ro) = self.class_ro {
            self.is_meta = (ro.flags & class_flags::RO_META) != 0;
            self.is_realised = (ro.flags & class_flags::RO_REALIZED) != 0;
            self.has_assoc_objects = (ro.flags & class_flags::RO_HAS_ASSOC_OBJECTS) != 0;
            self.has_cxx_structors = (ro.flags & class_flags::RO_HAS_CXX_STRUCTORS) != 0;
        }
    }
}

/// Read-only class metadata (`class_ro_t`).
#[derive(Debug, Clone, Default)]
pub struct ClassRO {
    /// Flags (see `class_flags`).
    pub flags: u32,
    /// Starting offset of instance variables.
    pub instance_start: u32,
    /// Total size of an instance in bytes.
    pub instance_size: u32,
    /// Reserved (alignment padding).
    pub reserved: u32,
    /// Class name (as a C string pointer -- stored as resolved string here).
    pub name: Option<String>,
    /// Methods defined on this class.
    pub methods: Vec<Method>,
    /// Protocols adopted by this class.
    pub protocols: Vec<u64>,
    /// Instance variables.
    pub ivars: Vec<Ivar>,
    /// Weak ivar layout (raw bytes).
    pub weak_ivar_layout: Vec<u8>,
    /// Properties declared on this class.
    pub properties: Vec<Property>,
}

/// An Objective-C method (`method_t`).
#[derive(Debug, Clone)]
pub struct Method {
    /// Selector name (e.g. `"init"`, `"setFrame:"`).
    pub name: String,
    /// Type encoding string (e.g. `"@16@0:8"`).
    pub types: String,
    /// Parsed type encoding.
    pub parsed_type: Option<TypeEncoding>,
    /// Implementation address (IMP).
    pub imp: u64,
    /// Whether this is a class method (vs instance method).
    pub is_class_method: bool,
    /// Whether this method is optional (in a protocol).
    pub is_optional: bool,
}

impl Method {
    /// Create a new method descriptor.
    pub fn new(name: String, types: String, imp: u64) -> Self {
        let parsed_type = parse_type_encoding(&types).ok().map(|(t, _)| t);
        Self {
            name,
            types,
            parsed_type,
            imp,
            is_class_method: false,
            is_optional: false,
        }
    }

    /// Return a human-readable method signature.
    pub fn signature(&self) -> String {
        let type_str = self
            .parsed_type
            .as_ref()
            .map(|t| t.to_type_string())
            .unwrap_or_else(|| self.types.clone());
        let prefix = match (self.is_class_method, self.is_optional) {
            (true, true) => "+? ",
            (true, false) => "+ ",
            (false, true) => "-? ",
            (false, false) => "- ",
        };
        format!(
            "{prefix}[{name} {type_str}]",
            name = self.name,
            type_str = type_str
        )
    }

    /// Return the selector (method name) suitable for lookup.
    pub fn selector(&self) -> &str {
        &self.name
    }
}

/// An instance variable (`ivar_t`).
#[derive(Debug, Clone)]
pub struct Ivar {
    /// Offset from the object start (pointer).
    pub offset: u32,
    /// Name of the ivar.
    pub name: Option<String>,
    /// Type encoding string.
    pub ty: Option<String>,
    /// Parsed type encoding.
    pub parsed_type: Option<TypeEncoding>,
    /// Log2 alignment.
    pub alignment: u32,
    /// Size in bytes.
    pub size: u32,
}

impl Ivar {
    /// Return a human-readable ivar declaration.
    pub fn declaration(&self) -> String {
        let ty_str = self
            .parsed_type
            .as_ref()
            .map(|t| t.to_type_string())
            .or_else(|| self.ty.clone())
            .unwrap_or_else(|| "?".to_string());
        let name = self.name.as_deref().unwrap_or("?");
        format!("{ty_str} {name}")
    }
}

/// A declared property (`property_t`).
#[derive(Debug, Clone)]
pub struct Property {
    /// Property name.
    pub name: String,
    /// Attribute string (raw).
    pub attributes: String,
    /// Parsed attributes.
    pub parsed_attributes: Vec<PropertyAttribute>,
}

impl Property {
    /// Create a new property descriptor.
    pub fn new(name: String, attributes: String) -> Self {
        let parsed_attributes = parse_property_attributes(&attributes);
        Self {
            name,
            attributes,
            parsed_attributes,
        }
    }

    /// Return a human-readable property declaration.
    pub fn declaration(&self) -> String {
        let mut decl = String::new();

        let type_attr = self
            .parsed_attributes
            .iter()
            .find_map(|attr| {
                if let PropertyAttribute::Type(ref t) = attr {
                    Some(t.to_type_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "id".to_string());

        let is_readonly = self
            .parsed_attributes
            .iter()
            .any(|a| matches!(a, PropertyAttribute::ReadOnly));
        let is_atomic = !self
            .parsed_attributes
            .iter()
            .any(|a| matches!(a, PropertyAttribute::NonAtomic));
        let is_weak = self
            .parsed_attributes
            .iter()
            .any(|a| matches!(a, PropertyAttribute::Weak));
        let is_copy = self
            .parsed_attributes
            .iter()
            .any(|a| matches!(a, PropertyAttribute::Copy));
        let is_strong = !is_weak && !is_copy;

        if !is_atomic {
            decl.push_str("(nonatomic");
        } else {
            decl.push_str("(atomic");
        }
        if is_readonly {
            decl.push_str(", readonly");
        } else {
            decl.push_str(", readwrite");
        }
        if is_weak {
            decl.push_str(", weak");
        } else if is_copy {
            decl.push_str(", copy");
        } else if is_strong {
            decl.push_str(", strong");
        }

        for attr in &self.parsed_attributes {
            match attr {
                PropertyAttribute::Getter(name) => {
                    decl.push_str(&format!(", getter={name}"));
                }
                PropertyAttribute::Setter(name) => {
                    decl.push_str(&format!(", setter={name}"));
                }
                _ => {}
            }
        }

        decl.push_str(&format!(") {type_attr} {}", self.name));
        decl
    }
}

/// Parsed property attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyAttribute {
    /// `T<encoding>` -- property type
    Type(TypeEncoding),
    /// `R` -- readonly
    ReadOnly,
    /// `C` -- copy
    Copy,
    /// `&` -- retain / strong
    Retain,
    /// `N` -- nonatomic
    NonAtomic,
    /// `G<name>` -- custom getter
    Getter(String),
    /// `S<name>` -- custom setter
    Setter(String),
    /// `D` -- dynamic
    Dynamic,
    /// `W` -- weak
    Weak,
    /// `P` -- eligible for garbage collection
    GarbageCollectionEligible,
    /// `t<encoding>` -- old-style type encoding
    OldStyleType(TypeEncoding),
    /// `V<name>` -- ivar backing name
    IvarName(String),
}

/// Parse the property attribute string.
pub fn parse_property_attributes(raw: &str) -> Vec<PropertyAttribute> {
    let mut attrs = Vec::new();
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            'T' => {
                i += 1;
                let enc_chars = &chars[i..];
                let mut pos = 0;
                if let Ok(ty) = parse_type_encoding_at(enc_chars, &mut pos) {
                    attrs.push(PropertyAttribute::Type(ty));
                    i += pos;
                } else {
                    i += 1;
                }
            }
            'R' => {
                attrs.push(PropertyAttribute::ReadOnly);
                i += 1;
            }
            'C' => {
                attrs.push(PropertyAttribute::Copy);
                i += 1;
            }
            '&' => {
                attrs.push(PropertyAttribute::Retain);
                i += 1;
            }
            'N' => {
                attrs.push(PropertyAttribute::NonAtomic);
                i += 1;
            }
            'G' => {
                i += 1;
                let mut name = String::new();
                while i < chars.len() && chars[i] != ',' {
                    name.push(chars[i]);
                    i += 1;
                }
                attrs.push(PropertyAttribute::Getter(name));
            }
            'S' => {
                i += 1;
                let mut name = String::new();
                while i < chars.len() && chars[i] != ',' {
                    name.push(chars[i]);
                    i += 1;
                }
                attrs.push(PropertyAttribute::Setter(name));
            }
            'D' => {
                attrs.push(PropertyAttribute::Dynamic);
                i += 1;
            }
            'W' => {
                attrs.push(PropertyAttribute::Weak);
                i += 1;
            }
            'P' => {
                attrs.push(PropertyAttribute::GarbageCollectionEligible);
                i += 1;
            }
            'V' => {
                i += 1;
                let mut name = String::new();
                while i < chars.len() && chars[i] != ',' {
                    name.push(chars[i]);
                    i += 1;
                }
                attrs.push(PropertyAttribute::IvarName(name));
            }
            ',' => {
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    attrs
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// An Objective-C protocol.
#[derive(Debug, Clone)]
pub struct ObjcProtocol {
    /// Address of the protocol structure.
    pub address: u64,
    /// ISA pointer.
    pub isa: u64,
    /// Protocol name (C string, resolved).
    pub name: Option<String>,
    /// List of adopted protocols (pointer references).
    pub protocols: Vec<u64>,
    /// Instance methods.
    pub instance_methods: Vec<Method>,
    /// Class methods.
    pub class_methods: Vec<Method>,
    /// Optional instance methods.
    pub optional_instance_methods: Vec<Method>,
    /// Optional class methods.
    pub optional_class_methods: Vec<Method>,
    /// Instance properties.
    pub instance_properties: Vec<Property>,
}

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

/// A category (`category_t`).
#[derive(Debug, Clone)]
pub struct ObjcCategory {
    /// Address of the category structure.
    pub address: u64,
    /// Category name.
    pub name: Option<String>,
    /// Class being extended (pointer).
    pub cls: u64,
    /// Instance methods added by this category.
    pub instance_methods: Vec<Method>,
    /// Class methods added by this category.
    pub class_methods: Vec<Method>,
    /// Protocols adopted by this category.
    pub protocols: Vec<u64>,
    /// Properties added by this category.
    pub properties: Vec<Property>,
}

impl ObjcCategory {
    /// Create a new empty category descriptor.
    pub fn new(address: u64) -> Self {
        ObjcCategory {
            address,
            name: None,
            cls: 0,
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            protocols: Vec::new(),
            properties: Vec::new(),
        }
    }

    /// Return a human-readable summary.
    pub fn summary(&self) -> String {
        let name = self.name.as_deref().unwrap_or("<unknown>");
        format!(
            "category {} @ {:#x} ({} inst methods, {} class methods, {} props)",
            name,
            self.address,
            self.instance_methods.len(),
            self.class_methods.len(),
            self.properties.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Image Info
// ---------------------------------------------------------------------------

/// Objective-C image info (`__objc_imageinfo` section).
#[derive(Debug, Clone)]
pub struct ObjcImageInfo {
    /// Version of the image info.
    pub version: u32,
    /// Flags describing the image.
    pub flags: u32,
}

impl ObjcImageInfo {
    /// Check if the image supports ARC.
    pub fn is_arc(&self) -> bool {
        (self.flags & image_flags::SUPPORTS_ARC) != 0
    }

    /// Check if the image is compiled with Swift.
    pub fn has_swift(&self) -> bool {
        (self.flags & image_flags::SUPPORTS_SWIFT) != 0
    }

    /// Return a human-readable description of the image flags.
    pub fn flag_descriptions(&self) -> Vec<&'static str> {
        image_flags::describe(self.flags)
    }
}

// ---------------------------------------------------------------------------
// Class hierarchy
// ---------------------------------------------------------------------------

/// A node in the class hierarchy tree.
#[derive(Debug, Clone)]
pub struct ClassHierarchyNode {
    /// The class data.
    pub class: ObjcClass,
    /// Immediate subclasses (by address).
    pub children: Vec<u64>,
}

/// Build a class hierarchy from a list of parsed classes.
pub fn build_class_hierarchy(classes: &[ObjcClass]) -> BTreeMap<u64, ClassHierarchyNode> {
    let mut hierarchy: BTreeMap<u64, ClassHierarchyNode> = BTreeMap::new();
    let mut super_to_sub: HashMap<u64, Vec<u64>> = HashMap::new();

    for cls in classes {
        if cls.super_class != 0 {
            super_to_sub
                .entry(cls.super_class)
                .or_default()
                .push(cls.address);
        }
    }

    for cls in classes {
        let children = super_to_sub.get(&cls.address).cloned().unwrap_or_default();
        hierarchy.insert(
            cls.address,
            ClassHierarchyNode {
                class: cls.clone(),
                children,
            },
        );
    }

    hierarchy
}

/// Walk the class hierarchy and produce an indented text representation.
pub fn format_class_hierarchy(hierarchy: &BTreeMap<u64, ClassHierarchyNode>) -> String {
    let roots: Vec<u64> = hierarchy
        .values()
        .filter(|n| n.class.super_class == 0)
        .map(|n| n.class.address)
        .collect();

    let mut out = String::new();
    for root in &roots {
        format_node(*root, hierarchy, &mut out, 0);
        out.push('\n');
    }
    out
}

fn format_node(
    addr: u64,
    hierarchy: &BTreeMap<u64, ClassHierarchyNode>,
    out: &mut String,
    depth: usize,
) {
    if let Some(node) = hierarchy.get(&addr) {
        let indent = "  ".repeat(depth);
        let name = node.class.name.as_deref().unwrap_or("<unknown>");
        let meta_marker = if node.class.is_meta { " (meta)" } else { "" };
        let method_count = node
            .class
            .class_ro
            .as_ref()
            .map(|ro| ro.methods.len())
            .unwrap_or(0);
        let prop_count = node
            .class
            .class_ro
            .as_ref()
            .map(|ro| ro.properties.len())
            .unwrap_or(0);
        out.push_str(&format!(
            "{indent}+ {name}{meta_marker} [{method_count} methods, {prop_count} props]\n"
        ));

        for child in &node.children {
            format_node(*child, hierarchy, out, depth + 1);
        }
    }
}

/// Search for a class by name in the parsed class list.
pub fn find_class_by_name<'a>(classes: &'a [ObjcClass], name: &str) -> Option<&'a ObjcClass> {
    classes.iter().find(|c| c.name.as_deref() == Some(name))
}

/// List all method names for a class (instance + class methods combined).
pub fn list_class_methods(class: &ObjcClass) -> Vec<&Method> {
    let mut methods: Vec<&Method> = Vec::new();
    if let Some(ro) = &class.class_ro {
        methods.extend(&ro.methods);
    }
    methods
}

// ---------------------------------------------------------------------------
// Section-level analysis
// ---------------------------------------------------------------------------

/// A parsed Objective-C class list section (`__objc_classlist`).
#[derive(Debug, Clone, Default)]
pub struct ObjcClassList {
    /// Address of the section in the binary.
    pub section_address: u64,
    /// Size of the section.
    pub section_size: usize,
    /// All class structures parsed from this section.
    pub classes: Vec<ObjcClass>,
    /// Number of non-lazy classes.
    pub non_lazy_count: usize,
    /// Number of metaclasses.
    pub metaclass_count: usize,
    /// Number of root classes (super_class == 0).
    pub root_class_count: usize,
}

impl ObjcClassList {
    /// Analyze the class list and compute summary statistics.
    pub fn analyze(&mut self) {
        let mut non_lazy = 0usize;
        let mut meta = 0usize;
        let mut root = 0usize;

        for cls in &self.classes {
            if cls.is_realised {
                non_lazy += 1;
            }
            if cls.is_meta {
                meta += 1;
            }
            if cls.super_class == 0 {
                root += 1;
            }
        }

        self.non_lazy_count = non_lazy;
        self.metaclass_count = meta;
        self.root_class_count = root;
    }

    /// Return a summary of the class list section.
    pub fn summary(&self) -> String {
        format!(
            "{} classes ({} metaclasses, {} root, {} non-lazy) @ {:#x}",
            self.classes.len(),
            self.metaclass_count,
            self.root_class_count,
            self.non_lazy_count,
            self.section_address,
        )
    }
}

// ---------------------------------------------------------------------------
// Selector table
// ---------------------------------------------------------------------------

/// A table mapping selector names to their addresses.
#[derive(Debug, Clone, Default)]
pub struct SelectorTable {
    /// Selector name -> address.
    pub by_name: BTreeMap<String, u64>,
    /// Selector address -> name.
    pub by_address: BTreeMap<u64, String>,
}

impl SelectorTable {
    /// Insert a selector reference.
    pub fn insert(&mut self, name: String, address: u64) {
        self.by_name.insert(name.clone(), address);
        self.by_address.insert(address, name);
    }

    /// Look up a selector name by address.
    pub fn lookup_address(&self, addr: u64) -> Option<&str> {
        self.by_address.get(&addr).map(|s| s.as_str())
    }

    /// Look up a selector address by name.
    pub fn lookup_name(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }

    /// Return all selector entries sorted by address.
    pub fn entries_sorted_by_address(&self) -> Vec<(u64, &str)> {
        let mut entries: Vec<_> = self
            .by_address
            .iter()
            .map(|(addr, name)| (*addr, name.as_str()))
            .collect();
        entries.sort_by_key(|(addr, _)| *addr);
        entries
    }
}

// ---------------------------------------------------------------------------
// Selector reference resolution
// ---------------------------------------------------------------------------

/// A resolved selector reference from the `__objc_selrefs` section.
#[derive(Debug, Clone)]
pub struct SelectorReference {
    /// Address of the selector reference pointer in the binary.
    pub reference_address: u64,
    /// Address of the selector string in the `__objc_methname` section.
    pub string_address: u64,
    /// The resolved selector string.
    pub selector: Option<String>,
}

/// A collection of selector references found in the binary.
#[derive(Debug, Clone, Default)]
pub struct SelectorReferenceTable {
    /// All selector references, keyed by reference address.
    pub refs: BTreeMap<u64, SelectorReference>,
    /// The underlying selector table for resolution.
    pub selector_table: SelectorTable,
}

impl SelectorReferenceTable {
    /// Add a selector reference and attempt to resolve it.
    pub fn add_reference(&mut self, ref_addr: u64, string_addr: u64, string_value: Option<String>) {
        let selector = string_value.clone();
        let sref = SelectorReference {
            reference_address: ref_addr,
            string_address: string_addr,
            selector,
        };
        if let Some(ref name) = string_value {
            self.selector_table.insert(name.clone(), string_addr);
        }
        self.refs.insert(ref_addr, sref);
    }

    /// Return the selector for a given reference address, if known.
    pub fn get_selector(&self, ref_addr: u64) -> Option<&str> {
        self.refs.get(&ref_addr).and_then(|r| r.selector.as_deref())
    }

    /// Return all unresolved references.
    pub fn unresolved(&self) -> Vec<&SelectorReference> {
        self.refs
            .values()
            .filter(|r| r.selector.is_none())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Class reference table
// ---------------------------------------------------------------------------

/// A resolved class reference from the `__objc_classrefs` section.
#[derive(Debug, Clone)]
pub struct ClassReference {
    /// Address of the class reference pointer.
    pub reference_address: u64,
    /// Address of the class structure.
    pub class_address: u64,
    /// The resolved class name (if available).
    pub class_name: Option<String>,
}

/// A collection of class references found in the binary.
#[derive(Debug, Clone, Default)]
pub struct ClassReferenceTable {
    /// All class references, keyed by reference address.
    pub refs: BTreeMap<u64, ClassReference>,
}

impl ClassReferenceTable {
    /// Add a class reference.
    pub fn add(&mut self, ref_addr: u64, class_addr: u64, class_name: Option<String>) {
        self.refs.insert(
            ref_addr,
            ClassReference {
                reference_address: ref_addr,
                class_address: class_addr,
                class_name,
            },
        );
    }

    /// Resolve class names from a list of parsed classes.
    pub fn resolve_from_classes(&mut self, classes: &[ObjcClass]) {
        let class_map: HashMap<u64, &str> = classes
            .iter()
            .filter_map(|c| c.name.as_ref().map(|n| (c.address, n.as_str())))
            .collect();

        for cref in self.refs.values_mut() {
            if let Some(name) = class_map.get(&cref.class_address) {
                cref.class_name = Some(name.to_string());
            }
        }
    }

    /// Find the class name for a given reference address.
    pub fn class_for_ref(&self, ref_addr: u64) -> Option<&str> {
        self.refs
            .get(&ref_addr)
            .and_then(|r| r.class_name.as_deref())
    }
}

// ---------------------------------------------------------------------------
// @selector / @protocol handling
// ---------------------------------------------------------------------------

/// Represents a decoded `@selector(...)` expression in assembly.
#[derive(Debug, Clone)]
pub struct SelectorExpression {
    /// Address of the instruction referencing the selector.
    pub instruction_address: u64,
    /// The raw selector string.
    pub selector_name: String,
    /// Whether this is a `@selector()` reference (as opposed to a plain
    /// method call where the selector is inferred).
    pub is_literal: bool,
}

/// Represents a decoded `@protocol(...)` expression in assembly.
#[derive(Debug, Clone)]
pub struct ProtocolExpression {
    /// Address of the instruction referencing the protocol.
    pub instruction_address: u64,
    /// The protocol name.
    pub protocol_name: String,
}

/// Decode a selector reference from the `__objc_methname` cstring section.
///
/// Given a pointer into the method name section, attempt to read the
/// null-terminated selector string.
pub fn decode_selector_from_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    let slice = &data[offset..end];
    String::from_utf8(slice.to_vec()).ok()
}

/// Decode a class name from the `__objc_classname` cstring section.
pub fn decode_class_name(data: &[u8], offset: usize) -> Option<String> {
    decode_selector_from_cstring(data, offset)
}

/// Format an Objective-C method call for display in decompilation output.
///
/// Returns a string like `[targetClassName selectorName]`.
pub fn format_objc_method_call(
    class_name: Option<&str>,
    selector: &str,
    is_super: bool,
    is_class_method: bool,
) -> String {
    let prefix = if is_class_method { "+" } else { "-" };
    let target = match class_name {
        Some(name) => {
            if is_super {
                format!("{name} (super)")
            } else {
                name.to_string()
            }
        }
        None => "?".to_string(),
    };
    format!("{prefix}[{target} {selector}]")
}

// ---------------------------------------------------------------------------
// Section names recognised by the parser
// ---------------------------------------------------------------------------

/// Mach-O section names containing Objective-C runtime data.
pub mod section_names {
    pub const OBJC_CLASSLIST: &str = "__objc_classlist";
    pub const OBJC_CATLIST: &str = "__objc_catlist";
    pub const OBJC_PROTOLIST: &str = "__objc_protolist";
    pub const OBJC_CLASSREFS: &str = "__objc_classrefs";
    pub const OBJC_SUPERREFS: &str = "__objc_superrefs";
    pub const OBJC_SELREFS: &str = "__objc_selrefs";
    pub const OBJC_DATA: &str = "__objc_data";
    pub const OBJC_CONST: &str = "__objc_const";
    pub const OBJC_METHNAME: &str = "__objc_methname";
    pub const OBJC_METHTYPE: &str = "__objc_methtype";
    pub const OBJC_CLASSNAME: &str = "__objc_classname";
    pub const OBJC_IVARS: &str = "__objc_ivars";
    pub const OBJC_NLCLSLIST: &str = "__objc_nlclslist";
    pub const OBJC_NLCATLIST: &str = "__objc_nlcatlist";
    pub const OBJC_IMAGEINFO: &str = "__objc_imageinfo";

    /// Swift reflection sections embedded in __TEXT.
    pub const SWIFT_REFLECTION: &str = "__swift5_refstr";
    pub const SWIFT_PROTO: &str = "__swift5_proto";
    pub const SWIFT_TYPES: &str = "__swift5_types";
    pub const SWIFT_FIELDS: &str = "__swift5_fieldmd";
    pub const SWIFT_ENTRY: &str = "__swift5_entry";
    pub const SWIFT_ASSOC: &str = "__swift5_assocty";
    pub const SWIFT_BUILTIN: &str = "__swift5_builtin";
    pub const SWIFT_CAPTURE: &str = "__swift5_capture";
    pub const SWIFT_MPROTO: &str = "__swift5_mpenm";
    pub const SWIFT_PROTOS: &str = "__swift5_protos";
    pub const SWIFT_TYPEREF: &str = "__swift5_typeref";
    pub const SWIFT_REFLPROTO: &str = "__swift5_reflstr";

    /// Returns true if the section name is an Objective-C runtime section.
    pub fn is_objc_section(name: &str) -> bool {
        name.starts_with("__objc_")
    }

    /// Returns true if the section name is a Swift runtime section
    /// embedded in __TEXT/__DATA alongside Objective-C sections.
    pub fn is_swift_objc_section(name: &str) -> bool {
        name.starts_with("__swift5_")
    }

    /// Returns true for any Objective-C or Swift metadata section.
    pub fn is_runtime_metadata_section(name: &str) -> bool {
        is_objc_section(name) || is_swift_objc_section(name)
    }
}

// ---------------------------------------------------------------------------
// Message sends (from disassembly context)
// ---------------------------------------------------------------------------

/// Represents a message-send site detected in disassembly.
#[derive(Debug, Clone)]
pub struct MessageSend {
    /// Address of the message-send instruction (e.g. `call _objc_msgSend`).
    pub address: u64,
    /// Target class (if known).
    pub target_class: Option<String>,
    /// Selector being sent.
    pub selector: Option<String>,
    /// Whether this is a `super` call.
    pub is_super: bool,
    /// Whether this is a `stret` (struct-return) variant.
    pub is_stret: bool,
    /// Whether this is a floating-point return variant.
    pub is_fpret: bool,
}

/// Recognised Objective-C message-send functions.
pub const KNOWN_MSG_SEND_FNS: &[&str] = &[
    "_objc_msgSend",
    "_objc_msgSend_stret",
    "_objc_msgSendSuper",
    "_objc_msgSendSuper_stret",
    "_objc_msgSend_fpret",
    "_objc_msgSend_fp2ret",
    "objc_msgSend",
    "objc_msgSend_stret",
    "objc_msgSendSuper",
    "objc_msgSendSuper_stret",
    "objc_msgSend_fpret",
    "objc_msgSend_fp2ret",
];

/// Returns true if the function name is a known message-send trampoline.
pub fn is_msg_send_fn(name: &str) -> bool {
    KNOWN_MSG_SEND_FNS.contains(&name)
}

/// Classify the kind of `objc_msgSend` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgSendKind {
    /// Standard message send.
    Normal,
    /// Struct-return message send.
    Stret,
    /// Super message send.
    Super,
    /// Super struct-return message send.
    SuperStret,
    /// Floating-point return message send.
    Fpret,
    /// Two-floating-point-return message send.
    Fp2ret,
    /// Not a message send at all.
    Unknown,
}

/// Classify a function name into its message-send kind.
pub fn classify_msg_send(name: &str) -> MsgSendKind {
    match name {
        "_objc_msgSend" | "objc_msgSend" => MsgSendKind::Normal,
        "_objc_msgSend_stret" | "objc_msgSend_stret" => MsgSendKind::Stret,
        "_objc_msgSendSuper" | "objc_msgSendSuper" => MsgSendKind::Super,
        "_objc_msgSendSuper_stret" | "objc_msgSendSuper_stret" => MsgSendKind::SuperStret,
        "_objc_msgSend_fpret" | "objc_msgSend_fpret" => MsgSendKind::Fpret,
        "_objc_msgSend_fp2ret" | "objc_msgSend_fp2ret" => MsgSendKind::Fp2ret,
        _ => MsgSendKind::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Convenience API
// ---------------------------------------------------------------------------

/// Parse a selector name from a C string.
/// Objective-C selectors are colon-separated names, e.g. `"initWithFrame:"`.
pub fn parse_selector(sel_str: &str) -> String {
    sel_str.to_string()
}

/// Format a selector for display: replace underscores with colons
/// for the method-style selectors used in disassembly.
pub fn format_selector_for_display(sel: &str) -> String {
    sel.replace('_', ":")
}

/// Convert a selector string to its method-style form.
/// e.g. `initWithFrame:` stays `initWithFrame:`.
pub fn normalize_selector(sel: &str) -> String {
    sel.trim().to_string()
}

/// Encode a method name as an Objective-C selector string.
/// e.g. `["init", "WithFrame:"]` -> `"initWithFrame:"`
pub fn encode_selector(parts: &[&str]) -> String {
    parts.iter().fold(String::new(), |mut acc, part| {
        acc.push_str(part);
        acc
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_types() {
        assert_eq!(parse_type_encoding("c").unwrap().0, TypeEncoding::Char);
        assert_eq!(parse_type_encoding("i").unwrap().0, TypeEncoding::Int);
        assert_eq!(parse_type_encoding("v").unwrap().0, TypeEncoding::Void);
        assert_eq!(parse_type_encoding("@").unwrap().0, TypeEncoding::Object);
        assert_eq!(parse_type_encoding("#").unwrap().0, TypeEncoding::Class);
        assert_eq!(parse_type_encoding(":").unwrap().0, TypeEncoding::Selector);
    }

    #[test]
    fn test_parse_pointer() {
        let (ty, _) = parse_type_encoding("^i").unwrap();
        assert!(matches!(ty, TypeEncoding::Pointer { .. }));
    }

    #[test]
    fn test_parse_struct() {
        let (ty, _) = parse_type_encoding("{CGRect={CGPoint=dd}{CGSize=dd}}").unwrap();
        assert!(matches!(ty, TypeEncoding::Struct { .. }));
    }

    #[test]
    fn test_parse_array() {
        let (ty, _) = parse_type_encoding("[16c]").unwrap();
        assert!(matches!(ty, TypeEncoding::Array { count: 16, .. }));
    }

    #[test]
    fn test_method_new() {
        let m = Method::new("init".into(), "@16@0:8".into(), 0x1000);
        assert_eq!(m.name, "init");
        assert_eq!(m.imp, 0x1000);
    }

    #[test]
    fn test_property_attributes() {
        let attrs = parse_property_attributes("T@\"NSString\",C,N,V_name");
        assert!(!attrs.is_empty());
        assert!(attrs.iter().any(|a| matches!(a, PropertyAttribute::Copy)));
        assert!(attrs
            .iter()
            .any(|a| matches!(a, PropertyAttribute::NonAtomic)));
    }

    #[test]
    fn test_build_class_hierarchy() {
        let cls_a = ObjcClass {
            address: 0x1000,
            isa: 0x2000,
            super_class: 0,
            cache: 0,
            vtable: 0,
            data: 0x3000,
            name: Some("NSObject".into()),
            class_ro: None,
            is_meta: false,
            is_realised: false,
            has_assoc_objects: false,
            has_cxx_structors: false,
        };
        let cls_b = ObjcClass {
            address: 0x1100,
            isa: 0x2100,
            super_class: 0x1000,
            cache: 0,
            vtable: 0,
            data: 0x3100,
            name: Some("MyClass".into()),
            class_ro: None,
            is_meta: false,
            is_realised: false,
            has_assoc_objects: false,
            has_cxx_structors: false,
        };
        let classes = vec![cls_a, cls_b];
        let hierarchy = build_class_hierarchy(&classes);
        if let Some(node) = hierarchy.get(&0x1000) {
            assert!(node.children.contains(&0x1100));
        }
    }

    #[test]
    fn test_find_class() {
        let cls = ObjcClass {
            address: 0x1000,
            isa: 0x2000,
            super_class: 0,
            cache: 0,
            vtable: 0,
            data: 0x3000,
            name: Some("UIViewController".into()),
            class_ro: None,
            is_meta: false,
            is_realised: false,
            has_assoc_objects: false,
            has_cxx_structors: false,
        };
        let classes = [cls];
        let found = find_class_by_name(&classes, "UIViewController");
        assert!(found.is_some());
        assert_eq!(found.unwrap().address, 0x1000);
    }

    #[test]
    fn test_is_msg_send() {
        assert!(is_msg_send_fn("_objc_msgSend"));
        assert!(is_msg_send_fn("objc_msgSend_stret"));
        assert!(!is_msg_send_fn("malloc"));
    }

    #[test]
    fn test_section_names() {
        assert!(section_names::is_objc_section("__objc_classlist"));
        assert!(section_names::is_swift_objc_section("__swift5_types"));
        assert!(!section_names::is_objc_section("__text"));
    }

    #[test]
    fn test_selector_table() {
        let mut table = SelectorTable::default();
        table.insert("init".into(), 0x4000);
        table.insert("alloc".into(), 0x4008);

        assert_eq!(table.lookup_address(0x4000), Some("init"));
        assert_eq!(table.lookup_name("alloc"), Some(0x4008));
        assert_eq!(table.lookup_address(0x9999), None);
    }

    #[test]
    fn test_format_class_hierarchy() {
        let cls = ObjcClass {
            address: 0x1000,
            isa: 0x2000,
            super_class: 0,
            cache: 0,
            vtable: 0,
            data: 0x3000,
            name: Some("NSObject".into()),
            class_ro: None,
            is_meta: false,
            is_realised: false,
            has_assoc_objects: false,
            has_cxx_structors: false,
        };
        let classes = vec![cls];
        let hierarchy = build_class_hierarchy(&classes);
        let formatted = format_class_hierarchy(&hierarchy);
        assert!(formatted.contains("NSObject"));
    }

    #[test]
    fn test_property_declaration() {
        let prop = Property::new("title".into(), "T@\"NSString\",C,N,V_title".into());
        let decl = prop.declaration();
        assert!(decl.contains("title"));
        assert!(decl.contains("copy") || decl.contains("nonnatomic"));
    }

    #[test]
    fn test_classify_msg_send_kinds() {
        assert_eq!(classify_msg_send("_objc_msgSend"), MsgSendKind::Normal);
        assert_eq!(classify_msg_send("objc_msgSend_stret"), MsgSendKind::Stret);
        assert_eq!(classify_msg_send("_objc_msgSendSuper"), MsgSendKind::Super);
        assert_eq!(
            classify_msg_send("objc_msgSendSuper_stret"),
            MsgSendKind::SuperStret
        );
        assert_eq!(classify_msg_send("malloc"), MsgSendKind::Unknown);
    }

    #[test]
    fn test_format_objc_method_call() {
        let call = format_objc_method_call(Some("NSString"), "stringWithUTF8String:", false, true);
        assert!(call.contains("NSString"));
        assert!(call.contains("stringWithUTF8String"));
        assert!(call.starts_with("+"));
    }

    #[test]
    fn test_decode_selector() {
        let data = b"init\0alloc\0";
        assert_eq!(decode_selector_from_cstring(data, 0), Some("init".into()));
        assert_eq!(decode_selector_from_cstring(data, 5), Some("alloc".into()));
        assert_eq!(decode_selector_from_cstring(data, 20), None);
    }

    #[test]
    fn test_class_flags_describe() {
        let flags = class_flags::RO_META | class_flags::RO_ROOT;
        let desc = class_flags::describe_flags(flags);
        assert!(desc.contains(&"META"));
        assert!(desc.contains(&"ROOT"));
    }

    #[test]
    fn test_image_flags_describe() {
        let flags = image_flags::SUPPORTS_ARC | image_flags::SUPPORTS_SWIFT;
        let desc = image_flags::describe(flags);
        assert!(desc.contains(&"ARC"));
        assert!(desc.contains(&"SWIFT"));
    }

    #[test]
    fn test_objc_class_list_analyze() {
        let mut list = ObjcClassList {
            section_address: 0x10000,
            section_size: 0x100,
            classes: vec![ObjcClass {
                address: 0x20000,
                isa: 0x21000,
                super_class: 0,
                cache: 0,
                vtable: 0,
                data: 0x22000,
                name: Some("NSObject".into()),
                class_ro: None,
                is_meta: false,
                is_realised: true,
                has_assoc_objects: false,
                has_cxx_structors: false,
            }],
            non_lazy_count: 0,
            metaclass_count: 0,
            root_class_count: 0,
        };
        list.analyze();
        assert_eq!(list.non_lazy_count, 1);
        assert_eq!(list.root_class_count, 1);
    }

    #[test]
    fn test_selector_reference_table() {
        let mut table = SelectorReferenceTable::default();
        table.add_reference(0x4000, 0x5000, Some("init".into()));
        table.add_reference(0x4008, 0x5008, None);

        assert_eq!(table.get_selector(0x4000), Some("init"));
        assert_eq!(table.get_selector(0x4008), None);
        assert_eq!(table.unresolved().len(), 1);
    }

    #[test]
    fn test_class_reference_table() {
        let mut table = ClassReferenceTable::default();
        table.add(0x4000, 0x5000, Some("NSString".into()));
        table.add(0x4008, 0x5008, None);

        assert_eq!(table.class_for_ref(0x4000), Some("NSString"));
        assert_eq!(table.class_for_ref(0x4008), None);

        // Test resolution
        let classes = vec![ObjcClass {
            address: 0x5008,
            isa: 0,
            super_class: 0,
            cache: 0,
            vtable: 0,
            data: 0,
            name: Some("NSArray".into()),
            class_ro: None,
            is_meta: false,
            is_realised: false,
            has_assoc_objects: false,
            has_cxx_structors: false,
        }];
        table.resolve_from_classes(&classes);
        assert_eq!(table.class_for_ref(0x4008), Some("NSArray"));
    }

    #[test]
    fn test_category_summary() {
        let cat = ObjcCategory {
            address: 0x1000,
            name: Some("MyCategory".into()),
            cls: 0x2000,
            instance_methods: vec![Method::new("foo".into(), "v@:".into(), 0x3000)],
            class_methods: vec![],
            protocols: vec![],
            properties: vec![],
        };
        let s = cat.summary();
        assert!(s.contains("MyCategory"));
        assert!(s.contains("1 inst methods"));
    }

    #[test]
    fn test_encode_selector() {
        assert_eq!(encode_selector(&["init"]), "init");
        assert_eq!(encode_selector(&["init", "WithFrame:"]), "initWithFrame:");
    }

    #[test]
    fn test_objc_image_info() {
        let info = ObjcImageInfo {
            version: 0,
            flags: image_flags::SUPPORTS_ARC | image_flags::SUPPORTS_SWIFT,
        };
        assert!(info.is_arc());
        assert!(info.has_swift());
    }

    #[test]
    fn test_format_selector_for_display() {
        assert_eq!(
            format_selector_for_display("initWith_frame"),
            "initWith:frame"
        );
        assert_eq!(format_selector_for_display("setFrame"), "setFrame");
    }

    #[test]
    fn test_runtime_metadata_section_check() {
        assert!(section_names::is_runtime_metadata_section(
            "__objc_classlist"
        ));
        assert!(section_names::is_runtime_metadata_section("__swift5_types"));
        assert!(!section_names::is_runtime_metadata_section("__text"));
    }
}
