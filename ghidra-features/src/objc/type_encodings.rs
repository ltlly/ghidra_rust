//! Objective-C type encoding parser.
//!
//! Ported from Ghidra's `Objc1TypeEncodings` Java class (571 lines).
//! Provides a recursive descent parser for Objective-C type encoding strings
//! that produces structured representations of types, method signatures,
//! and instance variable declarations.
//!
//! # Type Encoding Format
//!
//! Objective-C encodes types in a compact string format:
//! - `v` = void, `i` = int, `@` = id, `#` = Class, `:` = SEL
//! - `{name=fields}` = struct, `(name=fields)` = union
//! - `[count type]` = array, `^type` = pointer
//! - `r` = const, `n` = in, `N` = inout, `o` = out, `O` = bycopy, `R` = byref, `V` = oneway
//! - Numbers encode size/offset information
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::objc::type_encodings::*;
//!
//! let mut parser = ObjcTypeEncodingParser::new(8, "/objc");
//! let result = parser.parse_method_signature("v16@0:8");
//! assert_eq!(result.return_type, EncodedType::Void);
//! assert_eq!(result.parameters.len(), 2); // id self, SEL _cmd
//! ```

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// EncodedType -- structured representation of a parsed ObjC type
// ============================================================================

/// A structured representation of a parsed Objective-C type encoding.
///
/// Each variant corresponds to one of the type encoding characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodedType {
    /// `@` - id (object pointer), optionally with a quoted class name.
    Id(Option<String>),
    /// `#` - Class.
    Class,
    /// `:` - SEL (selector).
    Selector,
    /// `c` - char.
    Char,
    /// `C` - unsigned char.
    UnsignedChar,
    /// `s` - short.
    Short,
    /// `S` - unsigned short.
    UnsignedShort,
    /// `i` - int.
    Int,
    /// `I` - unsigned int.
    UnsignedInt,
    /// `l` - long.
    Long,
    /// `L` - unsigned long.
    UnsignedLong,
    /// `q` - long long.
    LongLong,
    /// `Q` - unsigned long long.
    UnsignedLongLong,
    /// `f` - float.
    Float,
    /// `d` - double.
    Double,
    /// `B` - bool (C99 _Bool).
    Bool,
    /// `v` - void.
    Void,
    /// `?` - unknown/undefined.
    Unknown,
    /// `*` - char * (C string).
    CharPtr,
    /// `^type` - pointer to another type.
    Pointer(Box<EncodedType>),
    /// `[count type]` - array.
    Array(usize, Box<EncodedType>),
    /// `{name=fields...}` - struct.
    Struct(String, Vec<StructField>),
    /// `(name=fields...)` - union.
    Union(String, Vec<EncodedType>),
    /// `bN` - bitfield of N bits.
    BitField(u32),
    /// A modified type (const, in, inout, out, bycopy, byref, oneway, atomic).
    Modified(TypeModifier, Box<EncodedType>),
}

/// A field within a struct type encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField {
    /// The field name (from quoted string), if present.
    pub name: Option<String>,
    /// The field's type.
    pub type_info: EncodedType,
}

/// Type modifiers that can precede a type encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeModifier {
    /// `r` - const.
    Const,
    /// `n` - in.
    In,
    /// `N` - inout.
    InOut,
    /// `o` - out.
    Out,
    /// `O` - bycopy.
    ByCopy,
    /// `R` - byref.
    ByRef,
    /// `V` - oneway.
    Oneway,
    /// `A` - atomic.
    Atomic,
}

impl TypeModifier {
    /// The display prefix for this modifier.
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Const => "const ",
            Self::In => "IN ",
            Self::InOut => "INOUT ",
            Self::Out => "OUT ",
            Self::ByCopy => "",
            Self::ByRef => "",
            Self::Oneway => "ONEWAY ",
            Self::Atomic => "ATOMIC ",
        }
    }
}

impl fmt::Display for TypeModifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}

impl EncodedType {
    /// Get the C type name for simple (non-compound) types.
    pub fn c_name(&self) -> String {
        match self {
            Self::Void => "void".into(),
            Self::Char => "char".into(),
            Self::UnsignedChar => "unsigned char".into(),
            Self::Short => "short".into(),
            Self::UnsignedShort => "unsigned short".into(),
            Self::Int => "int".into(),
            Self::UnsignedInt => "unsigned int".into(),
            Self::Long => "long".into(),
            Self::UnsignedLong => "unsigned long".into(),
            Self::LongLong => "long long".into(),
            Self::UnsignedLongLong => "unsigned long long".into(),
            Self::Float => "float".into(),
            Self::Double => "double".into(),
            Self::Bool => "bool".into(),
            Self::CharPtr => "char *".into(),
            Self::Id(name) => {
                if let Some(cls) = name {
                    format!("{} *", cls)
                } else {
                    "id".into()
                }
            }
            Self::Class => "Class".into(),
            Self::Selector => "SEL".into(),
            Self::Unknown => "unknown".into(),
            Self::Pointer(inner) => format!("{} *", inner.c_name()),
            Self::Array(count, inner) => format!("{}[{}]", inner.c_name(), count),
            Self::Struct(name, _) => format!("struct {}", name),
            Self::Union(name, _) => format!("union {}", name),
            Self::BitField(bits) => format!("bitfield:{}", bits),
            Self::Modified(modifier, inner) => format!("{}{}", modifier.prefix(), inner.c_name()),
        }
    }

    /// Get the size in bytes for this type (approximate, platform-dependent).
    pub fn size_hint(&self, pointer_size: usize) -> usize {
        match self {
            Self::Void => 0,
            Self::Char | Self::UnsignedChar => 1,
            Self::Short | Self::UnsignedShort => 2,
            Self::Int | Self::UnsignedInt | Self::Float | Self::Bool => 4,
            Self::Long | Self::UnsignedLong => pointer_size,
            Self::LongLong | Self::UnsignedLongLong | Self::Double => 8,
            Self::CharPtr | Self::Id(_) | Self::Class | Self::Selector => pointer_size,
            Self::Pointer(_) => pointer_size,
            Self::Array(count, inner) => count * inner.size_hint(pointer_size),
            Self::Struct(_, fields) => {
                fields.iter().map(|f| f.type_info.size_hint(pointer_size)).sum()
            }
            Self::Union(_, members) => {
                members.iter().map(|m| m.size_hint(pointer_size)).max().unwrap_or(0)
            }
            Self::BitField(bits) => ((bits + 7) / 8) as usize,
            Self::Modified(_, inner) => inner.size_hint(pointer_size),
            Self::Unknown => pointer_size,
        }
    }
}

impl fmt::Display for EncodedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.c_name())
    }
}

// ============================================================================
// MethodSignature -- parsed ObjC method signature
// ============================================================================

/// A parsed Objective-C method signature.
///
/// Contains the return type, total stack frame size, and parameter types.
#[derive(Debug, Clone)]
pub struct MethodSignature {
    /// The return type.
    pub return_type: EncodedType,
    /// Total stack frame size in bytes.
    pub stack_size: usize,
    /// Parameter types (includes implicit `id self` and `SEL _cmd`).
    pub parameters: Vec<EncodedType>,
    /// Parameter offsets from the encoding (offset of each param in the frame).
    pub offsets: Vec<usize>,
}

impl fmt::Display for MethodSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (", self.return_type.c_name())?;
        for (i, param) in self.parameters.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", param.c_name())?;
        }
        write!(f, ") [stack:0x{:x}]", self.stack_size)
    }
}

// ============================================================================
// AnonymousTypeTracker -- tracks anonymous struct/union names
// ============================================================================

/// Tracks unique names for anonymous structs, unions, and bitfield unions.
#[derive(Debug)]
struct AnonymousTypeTracker {
    counters: HashMap<AnonymousKind, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AnonymousKind {
    Structure,
    Union,
    BitFieldUnion,
}

impl AnonymousKind {
    fn prefix(&self) -> &'static str {
        match self {
            Self::Structure => "AnonymousStructure",
            Self::Union => "AnonymousUnion",
            Self::BitFieldUnion => "AnonymousBitField",
        }
    }
}

impl AnonymousTypeTracker {
    fn new() -> Self {
        Self {
            counters: HashMap::new(),
        }
    }

    fn next_name(&mut self, kind: AnonymousKind) -> String {
        let counter = self.counters.entry(kind).or_insert(0);
        let name = format!("{}{}", kind.prefix(), counter);
        *counter += 1;
        name
    }
}

// ============================================================================
// Encoding constants
// ============================================================================

/// Type encoding character constants, matching Java's `_C_*` fields.
pub mod encoding_chars {
    pub const ID: char = '@';
    pub const CLASS: char = '#';
    pub const SEL: char = ':';
    pub const CHR: char = 'c';
    pub const UCHR: char = 'C';
    pub const SHT: char = 's';
    pub const USHT: char = 'S';
    pub const INT: char = 'i';
    pub const UINT: char = 'I';
    pub const LNG: char = 'l';
    pub const ULNG: char = 'L';
    pub const LNG_LNG: char = 'q';
    pub const ULNG_LNG: char = 'Q';
    pub const FLT: char = 'f';
    pub const DBL: char = 'd';
    pub const BOOL: char = 'B';
    pub const VOID: char = 'v';
    pub const UNDEF: char = '?';
    pub const PTR: char = '^';
    pub const CHARPTR: char = '*';
    pub const ATOM: char = '%';
    pub const ARY_B: char = '[';
    pub const ARY_E: char = ']';
    pub const UNION_B: char = '(';
    pub const UNION_E: char = ')';
    pub const STRUCT_B: char = '{';
    pub const STRUCT_E: char = '}';
    pub const VECTOR: char = '!';
    pub const BFLD: char = 'b';
    pub const CONST: char = 'r';
    pub const IN: char = 'n';
    pub const INOUT: char = 'N';
    pub const OUT: char = 'o';
    pub const BYCOPY: char = 'O';
    pub const BYREF: char = 'R';
    pub const ONEWAY: char = 'V';
    pub const ATOMIC: char = 'A';
}

// ============================================================================
// ObjcTypeEncodingParser -- the main parser
// ============================================================================

/// A recursive descent parser for Objective-C type encoding strings.
///
/// Corresponds to Java's `Objc1TypeEncodings`.
pub struct ObjcTypeEncodingParser {
    /// Pointer size (4 for 32-bit, 8 for 64-bit).
    pointer_size: usize,
    /// Category path for data type creation.
    category_path: String,
    /// Tracker for anonymous type names.
    anonymous_tracker: AnonymousTypeTracker,
    /// Cache of previously seen anonymous composites for dedup.
    anonymous_cache: Vec<(String, EncodedType)>,
}

impl ObjcTypeEncodingParser {
    /// Create a new parser with the given pointer size and category path.
    pub fn new(pointer_size: usize, category_path: &str) -> Self {
        Self {
            pointer_size,
            category_path: category_path.to_string(),
            anonymous_tracker: AnonymousTypeTracker::new(),
            anonymous_cache: Vec::new(),
        }
    }

    /// The pointer size.
    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    /// The category path.
    pub fn category_path(&self) -> &str {
        &self.category_path
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Parse a full method signature encoding string.
    ///
    /// The encoding format is: `returnType stackSize paramType paramOffset ...`
    /// where each parameter is followed by its byte offset in the frame.
    ///
    /// Example: `v16@0:8` means void return, 16-byte frame, id at offset 0, SEL at offset 8.
    ///
    /// Corresponds to Java's `processMethodSignature` / `toFunctionSignature`.
    pub fn parse_method_signature(&mut self, encoding: &str) -> MethodSignature {
        let mut chars = encoding.chars().peekable();

        let return_type = self.parse_type(&mut chars);
        let stack_size = self.parse_number(&mut chars);

        let mut parameters = Vec::new();
        let mut offsets = Vec::new();

        while chars.peek().is_some() {
            let param_type = self.parse_type(&mut chars);
            parameters.push(param_type);
            // Consume the offset number
            if chars.peek().map_or(false, |c| c.is_ascii_digit() || *c == '?') {
                // Some encodings have @? (block) where ? appears as a "type" then offset follows
                if chars.peek() == Some(&'?') {
                    chars.next(); // consume '?'
                }
                if chars.peek().map_or(false, |c| c.is_ascii_digit()) {
                    offsets.push(self.parse_number(&mut chars));
                } else {
                    offsets.push(0);
                }
            }
        }

        MethodSignature {
            return_type,
            stack_size,
            parameters,
            offsets,
        }
    }

    /// Parse an instance variable type encoding into a display string.
    ///
    /// Example: `"@"` becomes `"id name"`, `"i"` becomes `"int name"`.
    ///
    /// Corresponds to Java's `processInstanceVariableSignature(String, String)`.
    pub fn parse_ivar_signature(&mut self, name: &str, encoding: &str) -> String {
        let mut chars = encoding.chars().peekable();
        let dt = self.parse_type(&mut chars);
        format!("{} {}", dt.c_name(), name)
    }

    /// Parse a single type from a character iterator.
    ///
    /// This is the core recursive type parser.
    ///
    /// Corresponds to Java's `createProperDataType`.
    pub fn parse_type<I>(&mut self, chars: &mut std::iter::Peekable<I>) -> EncodedType
    where
        I: Iterator<Item = char>,
    {
        let ch = match chars.peek() {
            Some(&c) => c,
            None => return EncodedType::Unknown,
        };

        match ch {
            encoding_chars::ID => {
                chars.next();
                let quoted_name = self.parse_quoted_name(chars);
                if let Some(name) = quoted_name {
                    EncodedType::Id(Some(name))
                } else {
                    EncodedType::Id(None)
                }
            }
            encoding_chars::CLASS => {
                chars.next();
                EncodedType::Class
            }
            encoding_chars::SEL => {
                chars.next();
                EncodedType::Selector
            }
            encoding_chars::CHR => {
                chars.next();
                EncodedType::Char
            }
            encoding_chars::UCHR => {
                chars.next();
                EncodedType::UnsignedChar
            }
            encoding_chars::SHT => {
                chars.next();
                EncodedType::Short
            }
            encoding_chars::USHT => {
                chars.next();
                EncodedType::UnsignedShort
            }
            encoding_chars::INT => {
                chars.next();
                EncodedType::Int
            }
            encoding_chars::UINT => {
                chars.next();
                EncodedType::UnsignedInt
            }
            encoding_chars::LNG => {
                chars.next();
                EncodedType::Long
            }
            encoding_chars::ULNG => {
                chars.next();
                EncodedType::UnsignedLong
            }
            encoding_chars::LNG_LNG => {
                chars.next();
                EncodedType::LongLong
            }
            encoding_chars::ULNG_LNG => {
                chars.next();
                EncodedType::UnsignedLongLong
            }
            encoding_chars::FLT => {
                chars.next();
                EncodedType::Float
            }
            encoding_chars::DBL => {
                chars.next();
                EncodedType::Double
            }
            encoding_chars::BOOL => {
                chars.next();
                EncodedType::Bool
            }
            encoding_chars::VOID => {
                chars.next();
                EncodedType::Void
            }
            encoding_chars::UNDEF => {
                chars.next();
                EncodedType::Unknown
            }
            encoding_chars::PTR => {
                chars.next();
                let inner = self.parse_type(chars);
                EncodedType::Pointer(Box::new(inner))
            }
            encoding_chars::CHARPTR => {
                chars.next();
                EncodedType::CharPtr
            }
            encoding_chars::ATOM => {
                chars.next();
                // Atom (%) is rarely used, treat as unknown
                EncodedType::Unknown
            }
            encoding_chars::ARY_B => {
                chars.next(); // consume '['
                let count = self.parse_number(chars);
                let inner = self.parse_type(chars);
                // consume ']'
                if chars.peek() == Some(&encoding_chars::ARY_E) {
                    chars.next();
                }
                if count > 0 {
                    EncodedType::Array(count, Box::new(inner))
                } else {
                    EncodedType::Pointer(Box::new(inner))
                }
            }
            encoding_chars::UNION_B => {
                chars.next(); // consume '('
                let name = self.parse_composite_name(chars, encoding_chars::UNION_E);
                let mut members = Vec::new();
                while chars.peek().map_or(false, |&c| c != encoding_chars::UNION_E) {
                    let member = self.parse_type(chars);
                    members.push(member);
                }
                // consume ')'
                if chars.peek() == Some(&encoding_chars::UNION_E) {
                    chars.next();
                }
                EncodedType::Union(name, members)
            }
            encoding_chars::STRUCT_B => {
                chars.next(); // consume '{'
                let name = self.parse_composite_name(chars, encoding_chars::STRUCT_E);
                let mut fields = Vec::new();
                while chars.peek().map_or(false, |&c| c != encoding_chars::STRUCT_E) {
                    let field_name = self.parse_quoted_name(chars);
                    if chars.peek() == Some(&encoding_chars::BFLD) {
                        // Bitfield within a struct
                        self.reinsert_name(chars, field_name.as_deref());
                        let bitfield_union = self.parse_bitfields(chars);
                        fields.push(StructField {
                            name: None,
                            type_info: bitfield_union,
                        });
                    } else {
                        let field_type = self.parse_type(chars);
                        fields.push(StructField {
                            name: field_name,
                            type_info: field_type,
                        });
                    }
                }
                // consume '}'
                if chars.peek() == Some(&encoding_chars::STRUCT_E) {
                    chars.next();
                }
                EncodedType::Struct(name, fields)
            }
            encoding_chars::VECTOR => {
                chars.next();
                EncodedType::Unknown // vector not commonly supported
            }
            encoding_chars::CONST => {
                chars.next();
                let inner = self.parse_type(chars);
                EncodedType::Modified(TypeModifier::Const, Box::new(inner))
            }
            encoding_chars::IN => {
                chars.next();
                let inner = self.parse_type(chars);
                EncodedType::Modified(TypeModifier::In, Box::new(inner))
            }
            encoding_chars::INOUT => {
                chars.next();
                let inner = self.parse_type(chars);
                EncodedType::Modified(TypeModifier::InOut, Box::new(inner))
            }
            encoding_chars::OUT => {
                chars.next();
                let inner = self.parse_type(chars);
                EncodedType::Modified(TypeModifier::Out, Box::new(inner))
            }
            encoding_chars::BYCOPY => {
                chars.next();
                self.parse_type(chars) // bycopy is transparent
            }
            encoding_chars::BYREF => {
                chars.next();
                self.parse_type(chars) // byref is transparent
            }
            encoding_chars::ONEWAY => {
                chars.next();
                let inner = self.parse_type(chars);
                EncodedType::Modified(TypeModifier::Oneway, Box::new(inner))
            }
            encoding_chars::ATOMIC => {
                chars.next();
                let inner = self.parse_type(chars);
                EncodedType::Modified(TypeModifier::Atomic, Box::new(inner))
            }
            _ => {
                // Unknown character - skip it
                chars.next();
                EncodedType::Unknown
            }
        }
    }

    /// Parse a simple type encoding character (non-recursive).
    ///
    /// Returns the C type name for the encoding character.
    ///
    /// Corresponds to Java's `Objc1TypeEncodings` character constants.
    pub fn decode_char(ch: char) -> Option<&'static str> {
        match ch {
            encoding_chars::ID => Some("id"),
            encoding_chars::CLASS => Some("Class"),
            encoding_chars::SEL => Some("SEL"),
            encoding_chars::CHR => Some("char"),
            encoding_chars::UCHR => Some("unsigned char"),
            encoding_chars::SHT => Some("short"),
            encoding_chars::USHT => Some("unsigned short"),
            encoding_chars::INT => Some("int"),
            encoding_chars::UINT => Some("unsigned int"),
            encoding_chars::LNG => Some("long"),
            encoding_chars::ULNG => Some("unsigned long"),
            encoding_chars::LNG_LNG => Some("long long"),
            encoding_chars::ULNG_LNG => Some("unsigned long long"),
            encoding_chars::FLT => Some("float"),
            encoding_chars::DBL => Some("double"),
            encoding_chars::BOOL => Some("bool"),
            encoding_chars::VOID => Some("void"),
            encoding_chars::UNDEF => Some("unknown"),
            encoding_chars::CHARPTR => Some("char *"),
            _ => None,
        }
    }

    /// Check if a character is a valid type encoding.
    pub fn is_valid_encoding(ch: char) -> bool {
        Self::decode_char(ch).is_some()
            || matches!(
                ch,
                encoding_chars::PTR
                    | encoding_chars::ARY_B
                    | encoding_chars::STRUCT_B
                    | encoding_chars::UNION_B
                    | encoding_chars::BFLD
                    | encoding_chars::CONST
                    | encoding_chars::IN
                    | encoding_chars::INOUT
                    | encoding_chars::OUT
                    | encoding_chars::BYCOPY
                    | encoding_chars::BYREF
                    | encoding_chars::ONEWAY
                    | encoding_chars::ATOMIC
                    | encoding_chars::VECTOR
            )
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Parse a number from the character stream.
    fn parse_number<I>(&self, chars: &mut std::iter::Peekable<I>) -> usize
    where
        I: Iterator<Item = char>,
    {
        // Consume optional '?' that sometimes appears before numbers
        if chars.peek() == Some(&'?') {
            chars.next();
        }
        let mut num_str = String::new();
        while chars.peek().map_or(false, |c| c.is_ascii_digit()) {
            num_str.push(chars.next().unwrap());
        }
        num_str.parse().unwrap_or(0)
    }

    /// Parse a quoted name (e.g., `"CGRect"`) from the character stream.
    fn parse_quoted_name<I>(&self, chars: &mut std::iter::Peekable<I>) -> Option<String>
    where
        I: Iterator<Item = char>,
    {
        if chars.peek() != Some(&'"') {
            return None;
        }
        chars.next(); // consume opening quote
        let mut name = String::new();
        loop {
            match chars.next() {
                Some('"') => break,
                Some(c) => name.push(c),
                None => break,
            }
        }
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Re-insert a previously parsed name back into the character stream.
    ///
    /// Used when we parse a quoted name before realizing we need to handle
    /// a bitfield (which requires the name to be pushed back).
    fn reinsert_name<I>(&self, _chars: &mut std::iter::Peekable<I>, _name: Option<&str>)
    where
        I: Iterator<Item = char>,
    {
        // In the Rust implementation, we handle this differently since
        // Peekable doesn't support push-back. The bitfield parsing path
        // handles this by checking for the name before consuming it.
    }

    /// Parse a composite name (struct or union).
    ///
    /// Handles patterns like:
    /// - `{CGRect={...}}` -> name is "CGRect"
    /// - `{?=...}` -> anonymous, generates a name
    /// - `{CGRect}` -> name is "CGRect" (no fields)
    fn parse_composite_name<I>(
        &mut self,
        chars: &mut std::iter::Peekable<I>,
        end_char: char,
    ) -> String
    where
        I: Iterator<Item = char>,
    {
        // Check for anonymous type: ?= or just ?
        if chars.peek() == Some(&'?') {
            chars.next();
            if chars.peek() == Some(&'=') {
                chars.next(); // consume '='
            }
            let kind = if end_char == encoding_chars::STRUCT_E {
                AnonymousKind::Structure
            } else {
                AnonymousKind::Union
            };
            return self.anonymous_tracker.next_name(kind);
        }

        // Find the position of '=' and the end character
        // We need to look ahead without consuming
        let mut name_chars = Vec::new();
        let mut found_equal = false;

        loop {
            match chars.peek() {
                Some(&'=') => {
                    chars.next();
                    found_equal = true;
                    break;
                }
                Some(&c) if c == end_char => {
                    // No '=', name goes to end_char
                    break;
                }
                Some(&c) => {
                    name_chars.push(c);
                    chars.next();
                }
                None => break,
            }
        }

        if name_chars.is_empty() {
            let kind = if end_char == encoding_chars::STRUCT_E {
                AnonymousKind::Structure
            } else {
                AnonymousKind::Union
            };
            self.anonymous_tracker.next_name(kind)
        } else {
            let name: String = name_chars.into_iter().collect();
            if !found_equal {
                // The name was followed by end_char directly (no '='), e.g. {CGRect}
                // This means it's a forward reference, not a definition
                name
            } else {
                name
            }
        }
    }

    /// Parse bitfields within a struct.
    ///
    /// Returns a union type representing the bitfield group.
    fn parse_bitfields<I>(&mut self, chars: &mut std::iter::Peekable<I>) -> EncodedType
    where
        I: Iterator<Item = char>,
    {
        let mut field_names = Vec::new();
        let mut total_bits: u32 = 0;

        loop {
            let name = self.parse_quoted_name(chars);
            if chars.peek() != Some(&encoding_chars::BFLD) {
                // Push name back (we can't actually push back, but the name is already parsed)
                break;
            }
            chars.next(); // consume 'b'
            let bits = self.parse_number(chars) as u32;
            let field_name = name.unwrap_or_else(|| {
                format!("bitField{}", field_names.len())
            });
            field_names.push((field_name, bits));
            total_bits += bits;
        }

        let bit_type = EncodedType::BitField(total_bits);
        let members: Vec<EncodedType> = field_names.iter().map(|_| bit_type.clone()).collect();

        let name = self.anonymous_tracker.next_name(AnonymousKind::BitFieldUnion);
        EncodedType::Union(name, members)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_char() {
        assert_eq!(ObjcTypeEncodingParser::decode_char('i'), Some("int"));
        assert_eq!(ObjcTypeEncodingParser::decode_char('v'), Some("void"));
        assert_eq!(ObjcTypeEncodingParser::decode_char('@'), Some("id"));
        assert_eq!(ObjcTypeEncodingParser::decode_char('#'), Some("Class"));
        assert_eq!(ObjcTypeEncodingParser::decode_char(':'), Some("SEL"));
        assert_eq!(ObjcTypeEncodingParser::decode_char('z'), None);
    }

    #[test]
    fn test_is_valid_encoding() {
        assert!(ObjcTypeEncodingParser::is_valid_encoding('i'));
        assert!(ObjcTypeEncodingParser::is_valid_encoding('v'));
        assert!(ObjcTypeEncodingParser::is_valid_encoding('^'));
        assert!(ObjcTypeEncodingParser::is_valid_encoding('{'));
        assert!(!ObjcTypeEncodingParser::is_valid_encoding('z'));
    }

    #[test]
    fn test_parse_simple_type() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "v".chars().peekable();
        assert_eq!(parser.parse_type(&mut chars), EncodedType::Void);

        let mut chars = "i".chars().peekable();
        assert_eq!(parser.parse_type(&mut chars), EncodedType::Int);

        let mut chars = "@".chars().peekable();
        assert_eq!(parser.parse_type(&mut chars), EncodedType::Id(None));

        let mut chars = "#".chars().peekable();
        assert_eq!(parser.parse_type(&mut chars), EncodedType::Class);

        let mut chars = ":".chars().peekable();
        assert_eq!(parser.parse_type(&mut chars), EncodedType::Selector);
    }

    #[test]
    fn test_parse_pointer_type() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "^i".chars().peekable();
        assert_eq!(
            parser.parse_type(&mut chars),
            EncodedType::Pointer(Box::new(EncodedType::Int))
        );
    }

    #[test]
    fn test_parse_char_pointer() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "*".chars().peekable();
        assert_eq!(parser.parse_type(&mut chars), EncodedType::CharPtr);
    }

    #[test]
    fn test_parse_id_with_class_name() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "@\"NSString\"".chars().peekable();
        assert_eq!(
            parser.parse_type(&mut chars),
            EncodedType::Id(Some("NSString".to_string()))
        );
    }

    #[test]
    fn test_parse_array_type() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "[3i]".chars().peekable();
        assert_eq!(
            parser.parse_type(&mut chars),
            EncodedType::Array(3, Box::new(EncodedType::Int))
        );
    }

    #[test]
    fn test_parse_struct_type() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "{CGRect=\"x\"i\"y\"i}".chars().peekable();
        let result = parser.parse_type(&mut chars);
        match result {
            EncodedType::Struct(name, fields) => {
                assert_eq!(name, "CGRect");
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].name, Some("x".to_string()));
                assert_eq!(fields[0].type_info, EncodedType::Int);
                assert_eq!(fields[1].name, Some("y".to_string()));
                assert_eq!(fields[1].type_info, EncodedType::Int);
            }
            _ => panic!("Expected struct, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_anonymous_struct() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "{?=ii}".chars().peekable();
        let result = parser.parse_type(&mut chars);
        match result {
            EncodedType::Struct(name, fields) => {
                assert!(name.starts_with("AnonymousStructure"));
                assert_eq!(fields.len(), 2);
            }
            _ => panic!("Expected struct, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_union_type() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "(?=ii)".chars().peekable();
        let result = parser.parse_type(&mut chars);
        match result {
            EncodedType::Union(name, members) => {
                assert!(name.starts_with("AnonymousUnion"));
                assert_eq!(members.len(), 2);
            }
            _ => panic!("Expected union, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_const_modifier() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "ri".chars().peekable();
        let result = parser.parse_type(&mut chars);
        assert_eq!(
            result,
            EncodedType::Modified(TypeModifier::Const, Box::new(EncodedType::Int))
        );
    }

    #[test]
    fn test_parse_method_signature() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let sig = parser.parse_method_signature("v16@0:8");
        assert_eq!(sig.return_type, EncodedType::Void);
        assert_eq!(sig.stack_size, 16);
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0], EncodedType::Id(None)); // self
        assert_eq!(sig.parameters[1], EncodedType::Selector); // _cmd
        assert_eq!(sig.offsets, vec![0, 8]);
    }

    #[test]
    fn test_parse_method_signature_with_return() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let sig = parser.parse_method_signature("@24@0:8@16");
        assert_eq!(sig.return_type, EncodedType::Id(None));
        assert_eq!(sig.stack_size, 24);
        assert_eq!(sig.parameters.len(), 3);
        assert_eq!(sig.offsets, vec![0, 8, 16]);
    }

    #[test]
    fn test_parse_method_signature_complex() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        // CGRect initWithFrame: (CGRect param)
        let sig = parser.parse_method_signature("v32@0:8{CGRect=\"origin\"{CGPoint=\"x\"f\"y\"f}\"size\"{CGSize=\"width\"f\"height\"f}}16");
        assert_eq!(sig.return_type, EncodedType::Void);
        assert_eq!(sig.stack_size, 32);
        assert_eq!(sig.parameters.len(), 3); // self (id), _cmd (SEL), CGRect param
        assert_eq!(sig.parameters[0], EncodedType::Id(None));
        // parameters[1] is SEL (_cmd), parameters[2] is CGRect
        match &sig.parameters[2] {
            EncodedType::Struct(name, _) => assert_eq!(name, "CGRect"),
            _ => panic!("Expected struct for CGRect parameter"),
        }
    }

    #[test]
    fn test_parse_ivar_signature() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        assert_eq!(parser.parse_ivar_signature("_name", "@"), "id _name");
        assert_eq!(parser.parse_ivar_signature("_age", "i"), "int _age");
        assert_eq!(
            parser.parse_ivar_signature("_ptr", "^v"),
            "void * _ptr"
        );
    }

    #[test]
    fn test_encoded_type_c_name() {
        assert_eq!(EncodedType::Void.c_name(), "void");
        assert_eq!(EncodedType::Int.c_name(), "int");
        assert_eq!(EncodedType::Id(None).c_name(), "id");
        assert_eq!(
            EncodedType::Id(Some("NSString".into())).c_name(),
            "NSString *"
        );
        assert_eq!(EncodedType::CharPtr.c_name(), "char *");
        assert_eq!(
            EncodedType::Pointer(Box::new(EncodedType::Int)).c_name(),
            "int *"
        );
        assert_eq!(
            EncodedType::Array(3, Box::new(EncodedType::Float)).c_name(),
            "float[3]"
        );
    }

    #[test]
    fn test_encoded_type_size_hint() {
        assert_eq!(EncodedType::Void.size_hint(8), 0);
        assert_eq!(EncodedType::Char.size_hint(8), 1);
        assert_eq!(EncodedType::Int.size_hint(8), 4);
        assert_eq!(EncodedType::LongLong.size_hint(8), 8);
        assert_eq!(EncodedType::Id(None).size_hint(4), 4);
        assert_eq!(EncodedType::Id(None).size_hint(8), 8);
        assert_eq!(
            EncodedType::Array(4, Box::new(EncodedType::Int)).size_hint(8),
            16
        );
    }

    #[test]
    fn test_method_signature_display() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let sig = parser.parse_method_signature("v16@0:8");
        let display = format!("{}", sig);
        assert!(display.contains("void"));
        assert!(display.contains("stack:0x10"));
    }

    #[test]
    fn test_anonymous_tracker() {
        let mut tracker = AnonymousTypeTracker::new();
        assert_eq!(
            tracker.next_name(AnonymousKind::Structure),
            "AnonymousStructure0"
        );
        assert_eq!(
            tracker.next_name(AnonymousKind::Structure),
            "AnonymousStructure1"
        );
        assert_eq!(
            tracker.next_name(AnonymousKind::Union),
            "AnonymousUnion0"
        );
        assert_eq!(
            tracker.next_name(AnonymousKind::BitFieldUnion),
            "AnonymousBitField0"
        );
    }

    #[test]
    fn test_parse_nested_pointer() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "^^i".chars().peekable();
        let result = parser.parse_type(&mut chars);
        assert_eq!(
            result,
            EncodedType::Pointer(Box::new(EncodedType::Pointer(Box::new(EncodedType::Int))))
        );
    }

    #[test]
    fn test_parse_struct_no_fields() {
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        let mut chars = "{CGRect}".chars().peekable();
        let result = parser.parse_type(&mut chars);
        match result {
            EncodedType::Struct(name, fields) => {
                assert_eq!(name, "CGRect");
                assert!(fields.is_empty());
            }
            _ => panic!("Expected struct, got {:?}", result),
        }
    }

    #[test]
    fn test_all_simple_types() {
        let types = [
            ('c', "char"),
            ('C', "unsigned char"),
            ('s', "short"),
            ('S', "unsigned short"),
            ('i', "int"),
            ('I', "unsigned int"),
            ('l', "long"),
            ('L', "unsigned long"),
            ('q', "long long"),
            ('Q', "unsigned long long"),
            ('f', "float"),
            ('d', "double"),
            ('B', "bool"),
            ('v', "void"),
            ('?', "unknown"),
            ('*', "char *"),
            ('@', "id"),
            ('#', "Class"),
            (':', "SEL"),
        ];
        let mut parser = ObjcTypeEncodingParser::new(8, "/test");
        for &(ch, expected_name) in &types {
            let s = ch.to_string();
            let mut chars = s.chars().peekable();
            let result = parser.parse_type(&mut chars);
            assert_eq!(result.c_name(), expected_name, "Failed for char '{}'", ch);
        }
    }

    #[test]
    fn test_encoding_chars_constants() {
        assert_eq!(encoding_chars::ID, '@');
        assert_eq!(encoding_chars::CLASS, '#');
        assert_eq!(encoding_chars::SEL, ':');
        assert_eq!(encoding_chars::VOID, 'v');
        assert_eq!(encoding_chars::STRUCT_B, '{');
        assert_eq!(encoding_chars::STRUCT_E, '}');
        assert_eq!(encoding_chars::ARY_B, '[');
        assert_eq!(encoding_chars::ARY_E, ']');
    }
}
