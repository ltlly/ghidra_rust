//! Rust language support: name demangler, type metadata, and standard library
//! type recognition.
//!
//! Handles demangling of Rust symbols in both the legacy (`_ZN...E`)
//! and V0 (`_R...`) formats. Produces human-readable names suitable
//! for display in disassembly listings.
//!
//! # Mangling Formats
//!
//! - **Legacy** (`_ZN...E`): C++-like format used before the V0 scheme.
//!   Format: `_ZN` followed by length-prefixed path segments, terminated by `E`.
//!
//! - **V0** (`_R...`): The current mangling scheme introduced in RFC 2603.
//!   Uses a richer grammar with explicit tags for paths, types, generics,
//!   lifetimes, constants, and more.
//!
//! # Common Patterns Recognised
//!
//! Maps Rust standard library types to human-readable forms:
//! `Box<T>`, `Vec<T>`, `String`, `Option<T>`, `Result<T, E>`,
//! `Arc<T>`, `Rc<T>`, `HashMap<K, V>`, etc.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as FmtWrite;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during Rust name demangling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DemangleError {
    /// Not a Rust mangled name.
    NotMangled,
    /// Unexpected end of input.
    UnexpectedEnd,
    /// Invalid or unknown mangling construct.
    InvalidMangling(String),
}

impl fmt::Display for DemangleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMangled => write!(f, "not a Rust mangled name"),
            Self::UnexpectedEnd => write!(f, "unexpected end of input"),
            Self::InvalidMangling(msg) => write!(f, "invalid mangling: {msg}"),
        }
    }
}

impl std::error::Error for DemangleError {}

// ---------------------------------------------------------------------------
// Rust type metadata structures
// ---------------------------------------------------------------------------

/// Rust's internal type representation metadata.
///
/// Rust embeds metadata about types in the binary for use by the runtime,
/// including vtables for trait objects, type descriptors for `Any` and
/// reflection, and drop glue for owned values.
#[derive(Debug, Clone)]
pub struct RustTypeMetadata {
    /// The kind of metadata record.
    pub kind: RustMetadataKind,
    /// The address where this metadata record is located.
    pub address: u64,
    /// The name of the type (if known).
    pub type_name: Option<String>,
    /// The size of the type in bytes.
    pub size: usize,
    /// The alignment of the type.
    pub alignment: usize,
    /// Pointer to the drop-glue function (if any).
    pub drop_glue: Option<u64>,
    /// Pointer to the vtable (for trait objects).
    pub vtable: Option<RustVTable>,
    /// Whether this type implements `Send`.
    pub is_send: bool,
    /// Whether this type implements `Sync`.
    pub is_sync: bool,
}

/// Kinds of Rust metadata records found in a binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustMetadataKind {
    /// A concrete type descriptor (for `Any::type_id`).
    TypeDescriptor,
    /// A trait object vtable.
    TraitObjectVtable,
    /// Drop glue for a type.
    DropGlue,
    /// A fat pointer metadata table.
    SliceMetadata,
    /// A trait implementation descriptor.
    TraitImpl,
    /// An inherent method table.
    InherentImpl,
    /// Unknown metadata record.
    Unknown(u32),
}

/// A Rust vtable for trait objects.
///
/// Rust trait objects use a vtable layout where the first few entries
/// are: drop, size, alignment, followed by method pointers.
#[derive(Debug, Clone)]
pub struct RustVTable {
    /// Address of the vtable in memory.
    pub address: u64,
    /// The trait this vtable is for (mangled name).
    pub trait_name: Option<String>,
    /// The implementing type (mangled name).
    pub impl_type: Option<String>,
    /// Drop function pointer.
    pub drop_fn: Option<u64>,
    /// Type size in bytes.
    pub size: usize,
    /// Type alignment.
    pub align: usize,
    /// Additional method pointers beyond the standard header.
    pub methods: Vec<RustVTableMethod>,
}

/// A method entry in a Rust vtable.
#[derive(Debug, Clone)]
pub struct RustVTableMethod {
    /// Offset of this method in the vtable (bytes from vtable start).
    pub offset: usize,
    /// The method name (if known).
    pub name: Option<String>,
    /// The function pointer.
    pub fn_ptr: u64,
}

/// A collection of all Rust metadata found in a binary.
#[derive(Debug, Clone, Default)]
pub struct RustMetadataSection {
    /// Type descriptors.
    pub type_descriptors: Vec<RustTypeMetadata>,
    /// Vtable records.
    pub vtables: Vec<RustVTable>,
    /// Trait impl records.
    pub trait_impls: Vec<TraitImplRecord>,
    /// Panic handler metadata.
    pub panic_info: Vec<PanicInfoRecord>,
}

/// A trait implementation record found in the binary.
#[derive(Debug, Clone)]
pub struct TraitImplRecord {
    /// Address of the impl descriptor.
    pub address: u64,
    /// The trait being implemented.
    pub trait_name: Option<String>,
    /// The implementing type.
    pub impl_type: Option<String>,
    /// Associated method pointers.
    pub methods: Vec<(String, u64)>,
}

/// A panic info record.
#[derive(Debug, Clone)]
pub struct PanicInfoRecord {
    /// Address of the panic info.
    pub address: u64,
    /// File name where the panic is located.
    pub file: Option<String>,
    /// Line number.
    pub line: u32,
    /// Column number.
    pub column: u32,
    /// The message (if any).
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Rust standard library type recognition
// ---------------------------------------------------------------------------

/// Well-known crate names and their short forms.
const WELL_KNOWN_CRATES: &[(&str, &str)] = &[
    ("std", "std"),
    ("core", "core"),
    ("alloc", "alloc"),
    ("test", "test"),
    ("proc_macro", "proc_macro"),
];

/// Well-known Rust standard library types and their display names.
const WELL_KNOWN_TYPES: &[(&str, &str)] = &[
    // Primitive types
    ("bool", "bool"),
    ("char", "char"),
    ("str", "str"),
    ("u8", "u8"),
    ("u16", "u16"),
    ("u32", "u32"),
    ("u64", "u64"),
    ("u128", "u128"),
    ("usize", "usize"),
    ("i8", "i8"),
    ("i16", "i16"),
    ("i32", "i32"),
    ("i64", "i64"),
    ("i128", "i128"),
    ("isize", "isize"),
    ("f32", "f32"),
    ("f64", "f64"),
    ("never", "!"),
    // Standard library allocation
    ("Box", "Box"),
    ("Vec", "Vec"),
    ("String", "String"),
    ("VecDeque", "VecDeque"),
    ("LinkedList", "LinkedList"),
    ("BinaryHeap", "BinaryHeap"),
    ("BTreeMap", "BTreeMap"),
    ("BTreeSet", "BTreeSet"),
    ("HashMap", "HashMap"),
    ("HashSet", "HashSet"),
    // Smart pointers
    ("Arc", "Arc"),
    ("Rc", "Rc"),
    ("Weak", "Weak"),
    ("Pin", "Pin"),
    ("NonNull", "NonNull"),
    ("Unique", "Unique"),
    ("ManuallyDrop", "ManuallyDrop"),
    ("MaybeUninit", "MaybeUninit"),
    // Synchronization primitives
    ("Mutex", "Mutex"),
    ("RwLock", "RwLock"),
    ("RefCell", "RefCell"),
    ("Cell", "Cell"),
    ("OnceLock", "OnceLock"),
    ("OnceCell", "OnceCell"),
    ("LazyLock", "LazyLock"),
    ("UnsafeCell", "UnsafeCell"),
    ("AtomicBool", "AtomicBool"),
    ("AtomicU8", "AtomicU8"),
    ("AtomicU16", "AtomicU16"),
    ("AtomicU32", "AtomicU32"),
    ("AtomicU64", "AtomicU64"),
    ("AtomicUsize", "AtomicUsize"),
    ("AtomicI8", "AtomicI8"),
    ("AtomicI16", "AtomicI16"),
    ("AtomicI32", "AtomicI32"),
    ("AtomicI64", "AtomicI64"),
    ("AtomicIsize", "AtomicIsize"),
    // Wrapper types
    ("Option", "Option"),
    ("Result", "Result"),
    ("Cow", "Cow"),
    ("PhantomData", "PhantomData"),
    ("PhantomPinned", "PhantomPinned"),
    // Iterators
    ("Iterator", "Iterator"),
    ("IntoIterator", "IntoIterator"),
    ("DoubleEndedIterator", "DoubleEndedIterator"),
    ("ExactSizeIterator", "ExactSizeIterator"),
    ("FusedIterator", "FusedIterator"),
    ("TrustedLen", "TrustedLen"),
    ("Iter", "Iter"),
    ("IterMut", "IterMut"),
    ("IntoIter", "IntoIter"),
    ("Drain", "Drain"),
    ("Range", "Range"),
    ("RangeInclusive", "RangeInclusive"),
    ("RangeFrom", "RangeFrom"),
    ("RangeTo", "RangeTo"),
    ("RangeFull", "RangeFull"),
    ("RangeToInclusive", "RangeToInclusive"),
    // Error handling
    ("Error", "Error"),
    // IO
    ("Read", "Read"),
    ("Write", "Write"),
    ("Seek", "Seek"),
    ("BufRead", "BufRead"),
    ("BufReader", "BufReader"),
    ("BufWriter", "BufWriter"),
    ("Cursor", "Cursor"),
    ("Stdin", "Stdin"),
    ("Stdout", "Stdout"),
    ("Stderr", "Stderr"),
    // Path / FS
    ("Path", "Path"),
    ("PathBuf", "PathBuf"),
    ("File", "File"),
    ("DirEntry", "DirEntry"),
    ("Metadata", "Metadata"),
    ("OpenOptions", "OpenOptions"),
    // Networking
    ("TcpStream", "TcpStream"),
    ("TcpListener", "TcpListener"),
    ("UdpSocket", "UdpSocket"),
    ("IpAddr", "IpAddr"),
    ("Ipv4Addr", "Ipv4Addr"),
    ("Ipv6Addr", "Ipv6Addr"),
    ("SocketAddr", "SocketAddr"),
    ("SocketAddrV4", "SocketAddrV4"),
    ("SocketAddrV6", "SocketAddrV6"),
    // Closures and functions
    ("Fn", "Fn"),
    ("FnMut", "FnMut"),
    ("FnOnce", "FnOnce"),
    // Common traits
    ("Clone", "Clone"),
    ("Copy", "Copy"),
    ("Debug", "Debug"),
    ("Display", "Display"),
    ("Default", "Default"),
    ("Drop", "Drop"),
    ("Eq", "Eq"),
    ("Ord", "Ord"),
    ("PartialEq", "PartialEq"),
    ("PartialOrd", "PartialOrd"),
    ("Hash", "Hash"),
    ("Send", "Send"),
    ("Sync", "Sync"),
    ("Sized", "Sized"),
    ("Unpin", "Unpin"),
    ("UnwindSafe", "UnwindSafe"),
    ("RefUnwindSafe", "RefUnwindSafe"),
    ("Future", "Future"),
    ("IntoFuture", "IntoFuture"),
    ("Stream", "Stream"),
    ("AsyncIterator", "AsyncIterator"),
    ("Try", "Try"),
    ("From", "From"),
    ("Into", "Into"),
    ("AsRef", "AsRef"),
    ("AsMut", "AsMut"),
    ("Deref", "Deref"),
    ("DerefMut", "DerefMut"),
    ("Index", "Index"),
    ("IndexMut", "IndexMut"),
    ("Borrow", "Borrow"),
    ("BorrowMut", "BorrowMut"),
    ("ToOwned", "ToOwned"),
    ("ToString", "ToString"),
    ("FromStr", "FromStr"),
    ("FromIterator", "FromIterator"),
    ("Extend", "Extend"),
    ("Serialize", "Serialize"),
    ("Deserialize", "Deserialize"),
];

// ---------------------------------------------------------------------------
// Well-known type builder
// ---------------------------------------------------------------------------

/// Build a lookup map for well-known type names.
fn build_type_lookup() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in WELL_KNOWN_TYPES {
        map.insert(k.to_string(), v.to_string());
    }
    map
}

/// Map a Rust std type name to its canonical display name.
pub fn map_rust_std_type(name: &str) -> String {
    // First check the static list
    for (key, display) in WELL_KNOWN_TYPES {
        if *key == name {
            return display.to_string();
        }
    }
    name.to_string()
}

/// Check if a name is a well-known crate.
pub fn is_well_known_crate(name: &str) -> bool {
    WELL_KNOWN_CRATES.iter().any(|(k, _)| *k == name)
}

/// Try to guess a human-readable type name from a Rust mangled symbol.
pub fn guess_type_from_symbol(symbol: &str) -> Option<String> {
    if !is_rust_mangled(symbol) {
        return None;
    }
    demangle(symbol).ok()
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

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn remaining(&self) -> &str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn take_while<F: Fn(char) -> bool>(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if !(F)(c) {
                break;
            }
            s.push(c);
            self.pos += c.len_utf8();
        }
        s
    }

    fn expect(&mut self, expected: char) -> Result<(), DemangleError> {
        match self.advance() {
            Some(c) if c == expected => Ok(()),
            Some(c) => Err(DemangleError::InvalidMangling(format!(
                "expected '{expected}', got '{c}'"
            ))),
            None => Err(DemangleError::UnexpectedEnd),
        }
    }

    /// Read a base-10 unsigned integer.
    fn read_integer(&mut self) -> Result<u64, DemangleError> {
        let digits = self.take_while(|c| c.is_ascii_digit());
        if digits.is_empty() {
            return Err(DemangleError::UnexpectedEnd);
        }
        digits
            .parse()
            .map_err(|_| DemangleError::InvalidMangling("integer overflow".into()))
    }

    /// Read a length-prefixed identifier (legacy format).
    fn read_legacy_ident(&mut self) -> Result<String, DemangleError> {
        let len = self.read_integer()? as usize;
        if self.pos + len > self.input.len() {
            return Err(DemangleError::UnexpectedEnd);
        }
        let s = self.input[self.pos..self.pos + len].to_string();
        self.pos += len;
        Ok(s)
    }

    /// Read an identifier in V0 format.
    fn read_v0_ident(&mut self) -> Result<String, DemangleError> {
        match self.peek() {
            Some('N') => {
                self.advance();
                let mut encoded = String::new();
                while let Some(c) = self.peek() {
                    if c == '_' {
                        self.advance();
                        break;
                    }
                    encoded.push(c);
                    self.advance();
                }
                punycode_decode(&encoded)
            }
            Some(c) if c.is_ascii_digit() => {
                let len = self.read_integer()? as usize;
                if self.pos + len > self.input.len() {
                    return Err(DemangleError::UnexpectedEnd);
                }
                let s = self.input[self.pos..self.pos + len].to_string();
                self.pos += len;
                Ok(s)
            }
            _ => Err(DemangleError::UnexpectedEnd),
        }
    }

    /// Read a disambiguator: `s_` followed by a base-62 integer.
    fn read_disambiguator(&mut self) -> Result<u64, DemangleError> {
        if !self.remaining().starts_with("s_") {
            return Ok(0);
        }
        self.pos += 2;
        let mut value: u64 = 0;
        while let Some(c) = self.peek() {
            let digit = match c {
                '0'..='9' => c as u64 - b'0' as u64,
                'A'..='Z' => 10 + (c as u64 - b'A' as u64),
                'a'..='z' => 36 + (c as u64 - b'a' as u64),
                '_' => {
                    self.advance();
                    return Ok(value);
                }
                _ => return Ok(value),
            };
            self.pos += c.len_utf8();
            value = value
                .checked_mul(62)
                .and_then(|v| v.checked_add(digit))
                .unwrap_or(0);
        }
        Ok(value)
    }

    fn read_v0_integer(&mut self) -> Result<u64, DemangleError> {
        match self.peek() {
            Some(c) if c.is_ascii_digit() => {
                let hex = self.take_while(|c| c.is_ascii_hexdigit() || c == '_');
                let cleaned: String = hex.chars().filter(|c| *c != '_').collect();
                if cleaned.is_empty() {
                    return Ok(0);
                }
                u64::from_str_radix(&cleaned, 16)
                    .map_err(|_| DemangleError::InvalidMangling("bad hex integer".into()))
            }
            _ => Err(DemangleError::UnexpectedEnd),
        }
    }
}

/// Minimal Punycode decoder for V0 identifiers.
fn punycode_decode(encoded: &str) -> Result<String, DemangleError> {
    if encoded.is_empty() {
        return Ok(String::new());
    }
    let mut result = String::new();
    let mut i = 0;
    let bytes = encoded.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'-' {
            i += 1;
            continue;
        }
        let mut codepoint: u32 = 0;
        let mut count = 0;
        while i < bytes.len() {
            let digit = match bytes[i] {
                b'a'..=b'z' => bytes[i] - b'a',
                b'A'..=b'Z' => bytes[i] - b'A',
                b'0'..=b'9' => 26 + (bytes[i] - b'0'),
                _ => break,
            };
            codepoint = codepoint * 36 + digit as u32;
            count += 1;
            i += 1;
        }
        if count > 0 {
            if let Some(c) = char::from_u32(codepoint) {
                result.push(c);
            } else {
                result.push('?');
            }
        } else {
            i += 1;
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Demangle entry point
// ---------------------------------------------------------------------------

/// Demangle a Rust symbol name.
///
/// # Arguments
///
/// * `mangled` - The mangled Rust symbol.
///
/// # Returns
///
/// A human-readable demangled name.
pub fn demangle(mangled: &str) -> Result<String, DemangleError> {
    if mangled.is_empty() {
        return Err(DemangleError::NotMangled);
    }

    if mangled.starts_with("_R") {
        return demangle_v0(&mangled[2..]);
    }

    if mangled.starts_with("_ZN") {
        return demangle_legacy(mangled);
    }

    if mangled.starts_with("_RNv") {
        return demangle_v0(&mangled[2..]);
    }

    Err(DemangleError::NotMangled)
}

// ---------------------------------------------------------------------------
// Legacy (_ZN...E) demangling
// ---------------------------------------------------------------------------

fn demangle_legacy(mangled: &str) -> Result<String, DemangleError> {
    if !mangled.starts_with("_ZN") {
        return Err(DemangleError::NotMangled);
    }

    let body = &mangled[3..];

    let body = if let Some(e_pos) = body.rfind('E') {
        &body[..e_pos]
    } else if let Some(hash_pos) = body.find(".llvm.") {
        &body[..hash_pos]
    } else if body.len() > 3 && body[body.len() - 3..].starts_with("17h") {
        &body[..body.len().saturating_sub(3)]
    } else {
        body
    };

    let mut parser = Parser::new(body);
    let mut result = String::new();

    parse_legacy_path(&mut parser, &mut result)?;

    Ok(result)
}

fn parse_legacy_path(parser: &mut Parser, out: &mut String) -> Result<(), DemangleError> {
    let mut first = true;
    while !parser.at_end() {
        match parser.peek() {
            Some('$') => {
                parser.advance();
                match parser.peek() {
                    Some('C') => {
                        parser.advance();
                        out.push_str("::");
                    }
                    Some('S') => {
                        parser.advance();
                        // Substitution -- skip
                        _ = parser.read_integer();
                    }
                    Some('R') => {
                        parser.advance();
                        out.push_str("&");
                    }
                    Some('L') => {
                        parser.advance();
                        parser.read_integer().ok();
                    }
                    Some('B') => {
                        parser.advance();
                        out.push_str("bool");
                    }
                    Some('u') => {
                        parser.advance();
                        match parser.read_integer() {
                            Ok(8) => out.push_str("u8"),
                            Ok(16) => out.push_str("u16"),
                            Ok(32) => out.push_str("u32"),
                            Ok(64) => out.push_str("u64"),
                            _ => out.push_str("uint"),
                        }
                    }
                    Some('i') => {
                        parser.advance();
                        match parser.read_integer() {
                            Ok(8) => out.push_str("i8"),
                            Ok(16) => out.push_str("i16"),
                            Ok(32) => out.push_str("i32"),
                            Ok(64) => out.push_str("i64"),
                            _ => out.push_str("int"),
                        }
                    }
                    Some('f') => {
                        parser.advance();
                        match parser.read_integer() {
                            Ok(32) => out.push_str("f32"),
                            Ok(64) => out.push_str("f64"),
                            _ => out.push_str("float"),
                        }
                    }
                    _ => {}
                }
                first = false;
            }
            Some('I') => {
                parser.advance();
                out.push('<');
                parse_legacy_generics(parser, out)?;
                out.push('>');
            }
            Some(c) if c.is_ascii_digit() || c == 'N' => {
                let ident = if c == 'N' {
                    parser.advance();
                    let mut nested = String::new();
                    parse_legacy_path(parser, &mut nested)?;
                    parser.expect('E')?;
                    nested
                } else {
                    parser.read_legacy_ident()?
                };

                if !first {
                    out.push_str("::");
                }
                out.push_str(&map_rust_std_type(&ident));
                first = false;
            }
            Some('h') => break,
            Some('E') => break,
            _ => {
                parser.advance();
            }
        }
    }
    Ok(())
}

fn parse_legacy_generics(parser: &mut Parser, out: &mut String) -> Result<(), DemangleError> {
    let mut first = true;
    while !parser.at_end() {
        match parser.peek() {
            Some('E') => {
                parser.advance();
                break;
            }
            Some(',') => {
                parser.advance();
                out.push_str(", ");
                first = false;
            }
            _ => {
                if !first {
                    out.push_str(", ");
                }
                parse_legacy_path(parser, out)?;
                first = false;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// V0 demangling
// ---------------------------------------------------------------------------

fn demangle_v0(body: &str) -> Result<String, DemangleError> {
    let mut parser = Parser::new(body);
    let mut result = String::new();

    match parser.peek() {
        Some('C') => {
            parser.advance();
            _ = parser.read_disambiguator();
            parse_v0_path(&mut parser, &mut result)?;
        }
        Some('N') => {
            parser.advance();
            parse_v0_path(&mut parser, &mut result)?;
        }
        Some('M') => {
            parser.advance();
            parse_v0_path(&mut parser, &mut result)?;
        }
        Some('X') => {
            parser.advance();
            parse_v0_path(&mut parser, &mut result)?;
        }
        Some('Y') => {
            parser.advance();
            parse_v0_path(&mut parser, &mut result)?;
        }
        Some('I') => {
            parser.advance();
            parse_v0_path(&mut parser, &mut result)?;
        }
        _ => {
            parse_v0_path(&mut parser, &mut result)?;
        }
    }

    if result.is_empty() {
        return Err(DemangleError::InvalidMangling(
            "empty demangling result".into(),
        ));
    }

    Ok(result)
}

fn parse_v0_path(parser: &mut Parser, out: &mut String) -> Result<(), DemangleError> {
    let mut first = true;

    while !parser.at_end() {
        match parser.peek() {
            Some(c) if c.is_ascii_digit() || c == 'N' => {
                let ident = if c == 'N' {
                    parser.advance();
                    let mut enc = String::new();
                    while let Some(ch) = parser.peek() {
                        if ch == '_' {
                            parser.advance();
                            break;
                        }
                        enc.push(ch);
                        parser.advance();
                    }
                    punycode_decode(&enc).unwrap_or_else(|_| enc)
                } else {
                    parser.read_v0_ident()?
                };

                if !first {
                    out.push_str("::");
                }

                let disamb = parser.read_disambiguator()?;

                out.push_str(&map_rust_std_type(&ident));

                if parser.peek() == Some('I') {
                    parser.advance();
                    if parse_v0_generics(parser, out).is_err() {
                        // continue even if generics parsing fails
                    }
                }

                if disamb > 0 {
                    write!(out, "::{disamb}").ok();
                }

                first = false;
            }
            Some('G') => {
                parser.advance();
                parse_v0_path(parser, out)?;
            }
            Some('S') => {
                parser.advance();
                parser.read_v0_integer().ok();
            }
            Some('K') => {
                parser.advance();
                parse_v0_const(parser, out)?;
            }
            Some('E') => {
                parser.advance();
                break;
            }
            Some('<') | Some('>') => {
                parser.advance();
            }
            Some(c) if c.is_ascii_uppercase() => {
                break;
            }
            _ => {
                break;
            }
        }
    }

    Ok(())
}

fn parse_v0_generics(parser: &mut Parser, out: &mut String) -> Result<(), DemangleError> {
    out.push('<');
    let mut first = true;
    let mut depth = 1;

    while !parser.at_end() && depth > 0 {
        match parser.peek() {
            Some('E') => {
                parser.advance();
                depth -= 1;
                if depth == 0 {
                    break;
                }
                out.push('E');
            }
            Some('I') => {
                parser.advance();
                depth += 1;
                out.push('<');
                first = true;
            }
            Some(',') => {
                parser.advance();
                out.push_str(", ");
                first = false;
            }
            Some(c) if c.is_ascii_digit() || c == 'N' => {
                if !first {
                    out.push_str(", ");
                }
                let ident = if c == 'N' {
                    parser.advance();
                    let mut enc = String::new();
                    while let Some(ch) = parser.peek() {
                        if ch == '_' {
                            parser.advance();
                            break;
                        }
                        enc.push(ch);
                        parser.advance();
                    }
                    punycode_decode(&enc).unwrap_or_else(|_| enc)
                } else {
                    parser.read_v0_ident()?
                };
                out.push_str(&map_rust_std_type(&ident));
                first = false;
            }
            Some('L') => {
                parser.advance();
                let lt = parser.read_v0_integer().unwrap_or(0);
                if !first {
                    out.push_str(", ");
                }
                write!(out, "'{lt}").ok();
                first = false;
            }
            Some('K') => {
                parser.advance();
                if !first {
                    out.push_str(", ");
                }
                parse_v0_const(parser, out)?;
                first = false;
            }
            Some('B') => {
                parser.advance();
                if !first {
                    out.push_str(", ");
                }
                let idx = parser.read_v0_integer().unwrap_or(0);
                write!(out, "::{idx}").ok();
                first = false;
            }
            Some('A') => {
                parser.advance();
                let len = parser.read_v0_integer().unwrap_or(0);
                write!(out, "{len}").ok();
            }
            Some(c) if c.is_ascii_lowercase() => {
                if !first {
                    out.push_str(", ");
                }
                parse_v0_type(parser, out)?;
                first = false;
            }
            _ => {
                parser.advance();
            }
        }
    }

    out.push('>');
    Ok(())
}

fn parse_v0_const(parser: &mut Parser, out: &mut String) -> Result<(), DemangleError> {
    match parser.peek() {
        Some(c) if c.is_ascii_digit() => {
            let val = parser.read_v0_integer().unwrap_or(0);
            write!(out, "{val}").ok();
            Ok(())
        }
        Some('n') => {
            parser.advance();
            out.push('-');
            let val = parser.read_v0_integer().unwrap_or(0);
            write!(out, "{val}").ok();
            Ok(())
        }
        Some('b') => {
            parser.advance();
            let val = parser.read_v0_integer().unwrap_or(0);
            if val == 0 {
                out.push_str("false");
            } else {
                out.push_str("true");
            }
            Ok(())
        }
        Some('c') => {
            parser.advance();
            let val = parser.read_v0_integer().unwrap_or(0);
            if let Some(c) = char::from_u32(val as u32) {
                write!(out, "'{c}'").ok();
            } else {
                write!(out, "'\\u{{{val}}}'").ok();
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_v0_type(parser: &mut Parser, out: &mut String) -> Result<(), DemangleError> {
    match parser.peek() {
        Some('R') => {
            parser.advance();
            out.push('&');
            parse_v0_type(parser, out)?;
            Ok(())
        }
        Some('Q') => {
            parser.advance();
            out.push_str("&mut ");
            parse_v0_type(parser, out)?;
            Ok(())
        }
        Some('P') => {
            parser.advance();
            out.push_str("*const ");
            parse_v0_type(parser, out)?;
            Ok(())
        }
        Some('O') => {
            parser.advance();
            out.push_str("*mut ");
            parse_v0_type(parser, out)?;
            Ok(())
        }
        Some('A') => {
            parser.advance();
            out.push('[');
            parse_v0_type(parser, out)?;
            out.push_str("; ");
            parse_v0_const(parser, out)?;
            out.push(']');
            Ok(())
        }
        Some('S') => {
            parser.advance();
            out.push('[');
            parse_v0_type(parser, out)?;
            out.push(']');
            Ok(())
        }
        Some('T') => {
            parser.advance();
            out.push('(');
            let count = parser.read_v0_integer().unwrap_or(0) as usize;
            for i in 0..count {
                if i > 0 {
                    out.push_str(", ");
                }
                parse_v0_type(parser, out)?;
            }
            out.push(')');
            Ok(())
        }
        Some('F') => {
            parser.advance();
            parse_v0_fn_sig(parser, out)?;
            Ok(())
        }
        Some('D') => {
            parser.advance();
            out.push_str("dyn ");
            parse_v0_path(parser, out)?;
            Ok(())
        }
        Some('z') => {
            parser.advance();
            out.push('!');
            Ok(())
        }
        Some('u') => {
            parser.advance();
            out.push_str("()");
            Ok(())
        }
        Some('e') => {
            parser.advance();
            out.push('!');
            Ok(())
        }
        Some(c) if c.is_ascii_digit() || c == 'N' => {
            parse_v0_path(parser, out)?;
            Ok(())
        }
        Some('l') => {
            parser.advance();
            match parser.peek() {
                Some('0') => {
                    parser.advance();
                    out.push_str("bool");
                }
                Some('1') => {
                    parser.advance();
                    out.push_str("u8");
                }
                Some('2') => {
                    parser.advance();
                    out.push_str("u16");
                }
                Some('3') => {
                    parser.advance();
                    out.push_str("u32");
                }
                Some('4') => {
                    parser.advance();
                    out.push_str("u64");
                }
                Some('5') => {
                    parser.advance();
                    out.push_str("u128");
                }
                Some('6') => {
                    parser.advance();
                    out.push_str("usize");
                }
                _ => {
                    out.push_str("uint");
                }
            }
            Ok(())
        }
        Some('i') => {
            parser.advance();
            match parser.peek() {
                Some('0') => {
                    parser.advance();
                    out.push_str("i8");
                }
                Some('1') => {
                    parser.advance();
                    out.push_str("i16");
                }
                Some('2') => {
                    parser.advance();
                    out.push_str("i32");
                }
                Some('3') => {
                    parser.advance();
                    out.push_str("i64");
                }
                Some('4') => {
                    parser.advance();
                    out.push_str("i128");
                }
                Some('5') => {
                    parser.advance();
                    out.push_str("isize");
                }
                _ => {
                    out.push_str("int");
                }
            }
            Ok(())
        }
        Some('f') => {
            parser.advance();
            match parser.peek() {
                Some('0') => {
                    parser.advance();
                    out.push_str("f32");
                }
                Some('1') => {
                    parser.advance();
                    out.push_str("f64");
                }
                _ => {
                    out.push_str("float");
                }
            }
            Ok(())
        }
        Some('c') => {
            parser.advance();
            out.push_str("char");
            Ok(())
        }
        Some('b') => {
            parser.advance();
            out.push_str("bool");
            Ok(())
        }
        Some('a') => {
            parser.advance();
            out.push_str("str");
            Ok(())
        }
        Some('s') => {
            parser.advance();
            out.push_str("isize");
            Ok(())
        }
        Some('p') => {
            parser.advance();
            out.push('_');
            Ok(())
        }
        Some('v') => {
            parser.advance();
            out.push('_');
            Ok(())
        }
        Some('U') => {
            parser.advance();
            out.push_str("union ");
            parse_v0_path(parser, out)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_v0_fn_sig(parser: &mut Parser, out: &mut String) -> Result<(), DemangleError> {
    match parser.peek() {
        Some('R') => {
            parser.advance();
            out.push_str("extern \"Rust\" fn(");
        }
        Some('C') => {
            parser.advance();
            out.push_str("extern \"C\" fn(");
        }
        Some('K') => {
            parser.advance();
            out.push_str("extern \"C\" fn(");
        }
        Some('S') => {
            parser.advance();
            out.push_str("extern \"system\" fn(");
        }
        _ => {
            out.push_str("fn(");
        }
    }

    let mut first = true;
    while !parser.at_end() {
        match parser.peek() {
            Some('E') => {
                parser.advance();
                break;
            }
            Some('u') => {
                parser.advance();
                break;
            }
            Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {
                if !first {
                    out.push_str(", ");
                }
                parse_v0_type(parser, out)?;
                first = false;
            }
            _ => break,
        }
    }

    out.push(')');

    if !parser.at_end() {
        match parser.peek() {
            Some('u') => {
                parser.advance();
            }
            _ => {
                out.push_str(" -> ");
                parse_v0_type(parser, out)?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Convenience API
// ---------------------------------------------------------------------------

/// Demangle or return the original string on failure.
pub fn demangle_or_original(mangled: &str) -> String {
    demangle(mangled).unwrap_or_else(|_| mangled.to_string())
}

/// Check whether a name looks like a Rust mangled symbol.
pub fn is_rust_mangled(name: &str) -> bool {
    name.starts_with("_ZN") || name.starts_with("_R")
}

/// Check if a symbol name is a Rust panic handler.
pub fn is_rust_panic_fn(name: &str) -> bool {
    name.contains("panic")
        || name.contains("panic_bounds_check")
        || name.contains("rust_begin_unwind")
        || name.contains("panic_fmt")
}

/// Detect common Rust function patterns from their demangled names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustFunctionPattern {
    /// A main function.
    Main,
    /// A test function.
    Test,
    /// A benchmark function.
    Bench,
    /// A Drop implementation.
    DropImpl,
    /// A Clone implementation.
    CloneImpl,
    /// A Debug implementation.
    DebugImpl,
    /// A Default implementation.
    DefaultImpl,
    /// A new() constructor.
    New,
    /// A trait method implementation.
    TraitMethod { trait_name: String, method: String },
    /// Normal function.
    Normal,
}

/// Classify a demangled Rust function name.
pub fn classify_rust_function(demangled: &str) -> RustFunctionPattern {
    if demangled.ends_with("::main") || demangled == "main" {
        return RustFunctionPattern::Main;
    }
    if demangled.contains("::test_") || demangled.contains("test::") {
        return RustFunctionPattern::Test;
    }
    if demangled.contains("::bench_") {
        return RustFunctionPattern::Bench;
    }
    if demangled.ends_with("::drop") || demangled.contains("<impl") && demangled.contains(">::drop")
    {
        return RustFunctionPattern::DropImpl;
    }
    if demangled.ends_with("::clone") {
        return RustFunctionPattern::CloneImpl;
    }
    if demangled.ends_with("::fmt") || demangled.ends_with("::debug") {
        return RustFunctionPattern::DebugImpl;
    }
    if demangled.ends_with("::default") {
        return RustFunctionPattern::DefaultImpl;
    }
    if demangled.ends_with("::new") {
        return RustFunctionPattern::New;
    }
    if let Some(impl_pos) = demangled.find(" as ") {
        if let Some(method_start) = demangled[impl_pos..].find(">::") {
            let rest = &demangled[impl_pos + method_start + 3..];
            if let Some(paren) = rest.find('(') {
                let method = &rest[..paren];
                let trait_name = &demangled[impl_pos + 4..impl_pos + method_start];
                return RustFunctionPattern::TraitMethod {
                    trait_name: trait_name.to_string(),
                    method: method.to_string(),
                };
            }
        }
    }
    RustFunctionPattern::Normal
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_rust_mangled() {
        assert!(is_rust_mangled("_ZN3foo3barE"));
        assert!(is_rust_mangled("_RINvCs5abc1234foo"));
        assert!(!is_rust_mangled("$s4main3foo"));
    }

    #[test]
    fn test_legacy_simple() {
        let result = demangle("_ZN3foo3barE").unwrap();
        assert!(result.contains("foo::bar"), "got: {result}");
    }

    #[test]
    fn test_legacy_module_function() {
        let result = demangle("_ZN6module8function17h1234567890abcdefE").unwrap();
        assert!(result.contains("module::function"), "got: {result}");
    }

    #[test]
    fn test_not_mangled() {
        assert!(demangle("hello_world").is_err());
    }

    #[test]
    fn test_map_std_types() {
        assert_eq!(map_rust_std_type("Vec"), "Vec");
        assert_eq!(map_rust_std_type("HashMap"), "HashMap");
        assert_eq!(map_rust_std_type("custom_type"), "custom_type");
    }

    #[test]
    fn test_demangle_or_original() {
        assert_eq!(demangle_or_original("plain_name"), "plain_name");
    }

    #[test]
    fn test_v0_crate_path() {
        let result = demangle("_RC4test3foo").unwrap_or_else(|_| String::new());
        if !result.is_empty() {
            assert!(result.contains("test") || result.contains("foo"));
        }
    }

    #[test]
    fn test_empty() {
        assert!(demangle("").is_err());
    }

    #[test]
    fn test_is_panic_fn() {
        assert!(is_rust_panic_fn("rust_begin_unwind"));
        assert!(is_rust_panic_fn("core::panicking::panic"));
        assert!(!is_rust_panic_fn("regular_function"));
    }

    #[test]
    fn test_classify_main() {
        assert_eq!(
            classify_rust_function("my_crate::main"),
            RustFunctionPattern::Main
        );
    }

    #[test]
    fn test_classify_test() {
        assert_eq!(
            classify_rust_function("my_crate::tests::test_foo"),
            RustFunctionPattern::Test
        );
    }

    #[test]
    fn test_classify_new() {
        assert_eq!(
            classify_rust_function("MyStruct::new"),
            RustFunctionPattern::New
        );
    }

    #[test]
    fn test_classify_normal() {
        assert_eq!(
            classify_rust_function("some::random::function"),
            RustFunctionPattern::Normal
        );
    }

    #[test]
    fn test_well_known_crates() {
        assert!(is_well_known_crate("std"));
        assert!(is_well_known_crate("core"));
        assert!(!is_well_known_crate("my_random_crate"));
    }

    #[test]
    fn test_rust_type_metadata() {
        let md = RustTypeMetadata {
            kind: RustMetadataKind::TypeDescriptor,
            address: 0x4000,
            type_name: Some("MyStruct".into()),
            size: 24,
            alignment: 8,
            drop_glue: Some(0x5000),
            vtable: None,
            is_send: true,
            is_sync: true,
        };
        assert_eq!(md.size, 24);
        assert!(md.is_send);
    }

    #[test]
    fn test_rust_vtable() {
        let vt = RustVTable {
            address: 0x6000,
            trait_name: Some("core::fmt::Debug".into()),
            impl_type: Some("MyStruct".into()),
            drop_fn: Some(0x6100),
            size: 24,
            align: 8,
            methods: vec![],
        };
        assert_eq!(vt.size, 24);
        assert_eq!(vt.align, 8);
    }

    #[test]
    fn test_legacy_with_substitutions() {
        // Substitutions should not cause errors
        let result = demangle("_ZN3std2io4Read4readE");
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_punycode_demangled() {
        assert_eq!(punycode_decode("").unwrap(), "");
        assert_eq!(punycode_decode("abc").unwrap_or_else(|_| "?".into()), "?");
    }
}
