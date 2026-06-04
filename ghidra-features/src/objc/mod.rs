//! Objective-C metadata parser for Mach-O binaries.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.objc` Java packages.
//! Provides parsing of Objective-C runtime metadata structures for both
//! Objc1 (legacy 32-bit) and Objc2 (modern 32/64-bit) formats.
//!
//! # Architecture
//!
//! - [`ObjcState`] -- shared parsing state (pointer size, address translation)
//! - [`ObjcUtils`] -- utility functions for creating symbols and namespaces
//! - [`ObjcMethodType`] -- instance vs. class method distinction
//! - [`Objc1`] -- legacy Objective-C 1.x metadata structures
//! - [`Objc2`] -- modern Objective-C 2.x metadata structures
//! - [`analyzer`] -- analysis passes for applying ObjC metadata to a program
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::objc::{ObjcState, ObjcUtils, ObjcMethodType};
//!
//! let state = ObjcState::new_64bit("ghidra/app/util/bin/format/objc/objc2");
//! assert_eq!(state.pointer_size(), 8);
//! assert!(!state.is_32bit());
//! ```

pub mod objc1;
pub mod objc2;
pub mod analyzer;

use std::collections::HashSet;
use std::fmt;

// ============================================================================
// ObjcState -- shared parsing state
// ============================================================================

/// Shared state for Objective-C metadata parsing.
///
/// Tracks the pointer size (32 or 64 bit) and the category path
/// for data type creation.
///
/// Corresponds to Java's `ObjcState`.
#[derive(Debug, Clone)]
pub struct ObjcState {
    /// Whether the binary is 32-bit.
    is_32bit: bool,
    /// The pointer size in bytes (4 or 8).
    pointer_size: usize,
    /// The category path for data type creation.
    category_path: String,
    /// Set of already-visited addresses to avoid infinite recursion.
    visited: HashSet<u64>,
}

impl ObjcState {
    /// Create a new state for a 32-bit binary.
    pub fn new_32bit(category_path: &str) -> Self {
        Self {
            is_32bit: true,
            pointer_size: 4,
            category_path: category_path.to_string(),
            visited: HashSet::new(),
        }
    }

    /// Create a new state for a 64-bit binary.
    pub fn new_64bit(category_path: &str) -> Self {
        Self {
            is_32bit: false,
            pointer_size: 8,
            category_path: category_path.to_string(),
            visited: HashSet::new(),
        }
    }

    /// Create a new state with explicit pointer size.
    pub fn new(pointer_size: usize, category_path: &str) -> Self {
        Self {
            is_32bit: pointer_size == 4,
            pointer_size,
            category_path: category_path.to_string(),
            visited: HashSet::new(),
        }
    }

    /// Whether the binary is 32-bit.
    pub fn is_32bit(&self) -> bool {
        self.is_32bit
    }

    /// The pointer size in bytes.
    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    /// The category path for data types.
    pub fn category_path(&self) -> &str {
        &self.category_path
    }

    /// Mark an address as visited. Returns `true` if it was already visited.
    pub fn mark_visited(&mut self, addr: u64) -> bool {
        !self.visited.insert(addr)
    }

    /// Check if an address has been visited.
    pub fn is_visited(&self, addr: u64) -> bool {
        self.visited.contains(&addr)
    }

    /// Clear the visited set.
    pub fn clear_visited(&mut self) {
        self.visited.clear();
    }

    /// Close/reset the state.
    pub fn close(&mut self) {
        self.visited.clear();
    }
}

// ============================================================================
// ObjcMethodType
// ============================================================================

/// Whether a method is an instance method or a class method.
///
/// Corresponds to Java's `ObjcMethodType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjcMethodType {
    /// An instance method (operates on an object instance).
    Instance,
    /// A class method (operates on the class itself).
    Class,
}

impl ObjcMethodType {
    /// Returns the string representation used in symbol names.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Instance => "+",
            Self::Class => "-",
        }
    }
}

impl fmt::Display for ObjcMethodType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// ObjcUtils
// ============================================================================

/// Utility functions for Objective-C metadata.
///
/// Corresponds to Java's `ObjcUtils`.
pub struct ObjcUtils;

impl ObjcUtils {
    /// The prefix for Objective-C class symbols.
    pub const OBJC_CLASS_SYMBOL_PREFIX: &'static str = "_OBJC_CLASS_$_";
    /// The prefix for Objective-C metaclass symbols.
    pub const OBJC_META_CLASS_SYMBOL_PREFIX: &'static str = "_OBJC_METACLASS_$_";
    /// The prefix for Objective-C category symbols.
    pub const OBJC_CATEGORY_SYMBOL_PREFIX: &'static str = "_OBJC_$_CATEGORY_";
    /// The namespace for Objective-C symbols.
    pub const NAMESPACE: &'static str = "objc";

    /// Strip Objective-C class prefixes from a name.
    ///
    /// Removes `_OBJC_CLASS_$_` or `_OBJC_METACLASS_$_` prefixes.
    ///
    /// Corresponds to Java's `ObjcUtils.stripClassPrefix`.
    pub fn strip_class_prefix(name: &str) -> &str {
        if let Some(rest) = name.strip_prefix(Self::OBJC_CLASS_SYMBOL_PREFIX) {
            rest
        } else if let Some(rest) = name.strip_prefix(Self::OBJC_META_CLASS_SYMBOL_PREFIX) {
            rest
        } else {
            name
        }
    }

    /// Create a qualified symbol name with namespace components.
    ///
    /// Corresponds to Java's `ObjcUtils.createNamespace` / symbol creation.
    pub fn qualified_name(namespace_parts: &[&str], name: &str) -> String {
        let mut parts: Vec<&str> = namespace_parts.to_vec();
        parts.push(name);
        parts.join("::")
    }

    /// Read a pointer-sized index from a byte slice at the given offset.
    ///
    /// Corresponds to Java's `ObjcUtils.readNextIndex`.
    pub fn read_index(data: &[u8], offset: usize, is_32bit: bool) -> Option<u64> {
        if is_32bit {
            if offset + 4 > data.len() {
                return None;
            }
            Some(u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as u64)
        } else {
            if offset + 8 > data.len() {
                return None;
            }
            Some(u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]))
        }
    }

    /// Read an ASCII string pointer from data at the given offset,
    /// then read the null-terminated string from the pointed-to address.
    ///
    /// This is a simplified version for testing; in production the
    /// program's memory would be used.
    pub fn read_string_at(data: &[u8], string_addr: usize) -> Option<String> {
        if string_addr >= data.len() {
            return None;
        }
        let end = data[string_addr..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(data.len() - string_addr);
        std::str::from_utf8(&data[string_addr..string_addr + end])
            .ok()
            .map(|s| s.to_string())
    }
}

// ============================================================================
// ObjcTypeMetadataStructure -- base for all ObjC structures
// ============================================================================

/// Base type for all Objective-C metadata structures.
///
/// Each structure knows its base address and the parsing state.
///
/// Corresponds to Java's `ObjcTypeMetadataStructure`.
#[derive(Debug, Clone)]
pub struct ObjcTypeMetadataStructure {
    /// The base address of this structure in the binary.
    pub base: u64,
    /// Whether the binary is 32-bit.
    pub is_32bit: bool,
    /// The pointer size.
    pub pointer_size: usize,
}

impl ObjcTypeMetadataStructure {
    /// Create a new metadata structure base.
    pub fn new(base: u64, is_32bit: bool) -> Self {
        Self {
            base,
            is_32bit,
            pointer_size: if is_32bit { 4 } else { 8 },
        }
    }

    /// The name of this structure type (for data type creation).
    pub fn name(&self) -> &str {
        "objc_type"
    }
}

// ============================================================================
// ObjcMethod -- abstract method representation
// ============================================================================

/// Represents an Objective-C method (instance or class).
///
/// Corresponds to Java's `ObjcMethod`.
#[derive(Debug, Clone)]
pub struct ObjcMethod {
    /// The method name (selector).
    pub name: String,
    /// The method type encoding string.
    pub types: String,
    /// The address of the method implementation.
    pub implementation: u64,
    /// Whether this is an instance or class method.
    pub method_type: ObjcMethodType,
    /// The base address of this method structure.
    pub base: u64,
}

impl ObjcMethod {
    /// Create a new ObjcMethod.
    pub fn new(
        name: String,
        types: String,
        implementation: u64,
        method_type: ObjcMethodType,
        base: u64,
    ) -> Self {
        Self {
            name,
            types,
            implementation,
            method_type,
            base,
        }
    }

    /// The method name (selector).
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// The type encoding string.
    pub fn get_types(&self) -> &str {
        &self.types
    }

    /// The implementation address.
    pub fn get_implementation(&self) -> u64 {
        self.implementation
    }

    /// Whether this is an instance or class method.
    pub fn method_type(&self) -> ObjcMethodType {
        self.method_type
    }

    /// The fully qualified method signature.
    pub fn signature(&self) -> String {
        format!("{}[{}]", self.method_type.as_str(), self.name)
    }
}

// ============================================================================
// ObjcMethodList -- list of methods
// ============================================================================

/// A list of Objective-C methods.
///
/// Corresponds to Java's `ObjcMethodList`.
#[derive(Debug, Clone)]
pub struct ObjcMethodList {
    /// The methods in this list.
    pub methods: Vec<ObjcMethod>,
    /// The base address of this method list structure.
    pub base: u64,
    /// The name of this structure type.
    pub name: String,
}

impl ObjcMethodList {
    /// Create a new method list.
    pub fn new(base: u64, name: &str) -> Self {
        Self {
            methods: Vec::new(),
            base,
            name: name.to_string(),
        }
    }

    /// Add a method to the list.
    pub fn add_method(&mut self, method: ObjcMethod) {
        self.methods.push(method);
    }

    /// Get the number of methods.
    pub fn count(&self) -> usize {
        self.methods.len()
    }

    /// Iterate over the methods.
    pub fn methods(&self) -> &[ObjcMethod] {
        &self.methods
    }

    /// Check if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

// ============================================================================
// AbstractObjcTypeMetadata -- base for Objc1TypeMetadata / Objc2TypeMetadata
// ============================================================================

/// Abstract base for Objective-C type metadata parsers.
///
/// Corresponds to Java's `AbstractObjcTypeMetadata`.
#[derive(Debug)]
pub struct AbstractObjcTypeMetadata {
    /// The parsing state.
    pub state: ObjcState,
    /// Log messages collected during parsing.
    pub log_messages: Vec<String>,
}

impl AbstractObjcTypeMetadata {
    /// Create a new type metadata parser.
    pub fn new(state: ObjcState) -> Self {
        Self {
            state,
            log_messages: Vec::new(),
        }
    }

    /// Log a message.
    pub fn log(&mut self, message: &str) {
        self.log_messages.push(message.to_string());
    }

    /// Log an error message.
    pub fn log_error(&mut self, message: &str, error: &str) {
        self.log_messages
            .push(format!("{}: {}", message, error));
    }

    /// Get collected log messages.
    pub fn log_messages(&self) -> &[String] {
        &self.log_messages
    }

    /// Close the underlying state.
    pub fn close(&mut self) {
        self.state.close();
    }
}

// ============================================================================
// ObjcSourceLanguage -- source language identification
// ============================================================================

/// Identifies Objective-C as a source language.
///
/// Corresponds to Java's `ObjcSourceLanguage` and `MachoObjcSourceLanguage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcSourceLanguage {
    /// The language identifier.
    pub id: String,
    /// Whether this is from a Mach-O binary.
    pub is_macho: bool,
}

impl ObjcSourceLanguage {
    /// The Objective-C language identifier.
    pub const OBJC_ID: &'static str = "Objective-C";

    /// Create a standard Objective-C source language.
    pub fn objc() -> Self {
        Self {
            id: Self::OBJC_ID.to_string(),
            is_macho: false,
        }
    }

    /// Create a Mach-O specific Objective-C source language.
    pub fn macho_objc() -> Self {
        Self {
            id: Self::OBJC_ID.to_string(),
            is_macho: true,
        }
    }

    /// The language identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
}

// ============================================================================
// ObjcMethodTypeEncoding -- type encoding parser
// ============================================================================

/// Parses Objective-C type encoding strings.
///
/// Objective-C encodes parameter and return types in a compact string format.
/// This parser decodes those strings into human-readable forms.
///
/// Corresponds to Java's `Objc1TypeEncodings`.
pub struct ObjcTypeEncoding;

impl ObjcTypeEncoding {
    /// Decode a single type encoding character.
    ///
    /// Returns the C type name for the given encoding character.
    ///
    /// Corresponds to Java's `Objc1TypeEncodings` constants.
    pub fn decode(encoding: char) -> Option<&'static str> {
        match encoding {
            'c' => Some("char"),
            'i' => Some("int"),
            's' => Some("short"),
            'l' => Some("long"),
            'q' => Some("long long"),
            'C' => Some("unsigned char"),
            'I' => Some("unsigned int"),
            'S' => Some("unsigned short"),
            'L' => Some("unsigned long"),
            'Q' => Some("unsigned long long"),
            'f' => Some("float"),
            'd' => Some("double"),
            'B' => Some("bool"),
            'v' => Some("void"),
            '*' => Some("char *"),
            '@' => Some("id"),
            '#' => Some("Class"),
            ':' => Some("SEL"),
            '[' => Some("array"),
            '{' => Some("struct"),
            '(' => Some("union"),
            'b' => Some("bitfield"),
            '^' => Some("pointer"),
            '?' => Some("unknown"),
            'r' => Some("const"),
            'n' => Some("in"),
            'N' => Some("inout"),
            'o' => Some("out"),
            'O' => Some("bycopy"),
            'R' => Some("byref"),
            'V' => Some("oneway"),
            'j' => Some("_Complex"),
            _ => None,
        }
    }

    /// Decode a full type encoding string into a human-readable form.
    ///
    /// This is a simplified decoder that handles common patterns.
    pub fn decode_string(encoding: &str) -> String {
        let mut result = String::new();
        let mut chars = encoding.chars().peekable();

        while let Some(ch) = chars.next() {
            if let Some(type_name) = Self::decode(ch) {
                if !result.is_empty() {
                    result.push(' ');
                }
                result.push_str(type_name);
            } else if ch.is_ascii_digit() {
                // Skip size/offset digits
                continue;
            } else {
                if !result.is_empty() {
                    result.push(' ');
                }
                result.push(ch);
            }
        }

        result
    }

    /// Check if a character is a valid type encoding.
    pub fn is_valid_encoding(ch: char) -> bool {
        Self::decode(ch).is_some() || ch.is_ascii_digit()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_objc_state_32bit() {
        let state = ObjcState::new_32bit("test/path");
        assert!(state.is_32bit());
        assert_eq!(state.pointer_size(), 4);
        assert_eq!(state.category_path(), "test/path");
    }

    #[test]
    fn test_objc_state_64bit() {
        let state = ObjcState::new_64bit("test/path");
        assert!(!state.is_32bit());
        assert_eq!(state.pointer_size(), 8);
    }

    #[test]
    fn test_objc_state_visited() {
        let mut state = ObjcState::new_64bit("test");
        assert!(!state.is_visited(0x1000));
        assert!(!state.mark_visited(0x1000));
        assert!(state.is_visited(0x1000));
        assert!(state.mark_visited(0x1000)); // already visited
        state.clear_visited();
        assert!(!state.is_visited(0x1000));
    }

    #[test]
    fn test_objc_method_type() {
        assert_eq!(ObjcMethodType::Instance.as_str(), "+");
        assert_eq!(ObjcMethodType::Class.as_str(), "-");
        assert_eq!(format!("{}", ObjcMethodType::Instance), "+");
    }

    #[test]
    fn test_strip_class_prefix() {
        assert_eq!(
            ObjcUtils::strip_class_prefix("_OBJC_CLASS_$_NSString"),
            "NSString"
        );
        assert_eq!(
            ObjcUtils::strip_class_prefix("_OBJC_METACLASS_$_NSString"),
            "NSString"
        );
        assert_eq!(
            ObjcUtils::strip_class_prefix("plain_name"),
            "plain_name"
        );
    }

    #[test]
    fn test_qualified_name() {
        assert_eq!(
            ObjcUtils::qualified_name(&["objc", "Categories"], "MyClass"),
            "objc::Categories::MyClass"
        );
    }

    #[test]
    fn test_read_index_32bit() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(ObjcUtils::read_index(&data, 0, true), Some(0x12345678));
    }

    #[test]
    fn test_read_index_64bit() {
        let data = [0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x00];
        assert_eq!(
            ObjcUtils::read_index(&data, 0, false),
            Some(0x00ABCDEF12345678)
        );
    }

    #[test]
    fn test_read_index_out_of_bounds() {
        let data = [0x01, 0x02];
        assert_eq!(ObjcUtils::read_index(&data, 0, true), None);
    }

    #[test]
    fn test_read_string_at() {
        let data = b"\x00\x00\x00\x00Hello, World!\x00";
        assert_eq!(
            ObjcUtils::read_string_at(data, 4),
            Some("Hello, World!".to_string())
        );
    }

    #[test]
    fn test_objc_method() {
        let method = ObjcMethod::new(
            "initWithFrame:".to_string(),
            "v16@0:4{CGRect={CGPoint=ff}{CGSize=ff}}8".to_string(),
            0x1000,
            ObjcMethodType::Instance,
            0x2000,
        );
        assert_eq!(method.get_name(), "initWithFrame:");
        assert_eq!(method.get_implementation(), 0x1000);
        assert_eq!(method.method_type(), ObjcMethodType::Instance);
        assert_eq!(method.signature(), "+[initWithFrame:]");
    }

    #[test]
    fn test_objc_method_list() {
        let mut list = ObjcMethodList::new(0x3000, "method_list_t");
        assert!(list.is_empty());

        list.add_method(ObjcMethod::new(
            "init".into(),
            "v8@0:4".into(),
            0x1000,
            ObjcMethodType::Instance,
            0x2000,
        ));
        list.add_method(ObjcMethod::new(
            "alloc".into(),
            "@4@0:4".into(),
            0x1040,
            ObjcMethodType::Class,
            0x2010,
        ));

        assert_eq!(list.count(), 2);
        assert!(!list.is_empty());
        assert_eq!(list.methods()[0].get_name(), "init");
        assert_eq!(list.methods()[1].get_name(), "alloc");
    }

    #[test]
    fn test_type_metadata_structure() {
        let s = ObjcTypeMetadataStructure::new(0x4000, true);
        assert_eq!(s.base, 0x4000);
        assert!(s.is_32bit);
        assert_eq!(s.pointer_size, 4);
    }

    #[test]
    fn test_abstract_type_metadata() {
        let state = ObjcState::new_64bit("test");
        let mut meta = AbstractObjcTypeMetadata::new(state);
        assert!(meta.log_messages().is_empty());

        meta.log("test message");
        meta.log_error("operation failed", "IO error");
        assert_eq!(meta.log_messages().len(), 2);
        assert!(meta.log_messages()[0].contains("test message"));
        assert!(meta.log_messages()[1].contains("operation failed"));
    }

    #[test]
    fn test_source_language() {
        let lang = ObjcSourceLanguage::objc();
        assert_eq!(lang.id(), "Objective-C");
        assert!(!lang.is_macho);

        let macho_lang = ObjcSourceLanguage::macho_objc();
        assert!(macho_lang.is_macho);
    }

    #[test]
    fn test_type_encoding_decode() {
        assert_eq!(ObjcTypeEncoding::decode('i'), Some("int"));
        assert_eq!(ObjcTypeEncoding::decode('v'), Some("void"));
        assert_eq!(ObjcTypeEncoding::decode('@'), Some("id"));
        assert_eq!(ObjcTypeEncoding::decode('#'), Some("Class"));
        assert_eq!(ObjcTypeEncoding::decode(':'), Some("SEL"));
        assert_eq!(ObjcTypeEncoding::decode('z'), None);
    }

    #[test]
    fn test_type_encoding_decode_string() {
        let decoded = ObjcTypeEncoding::decode_string("v16@0:8");
        assert!(decoded.contains("void"));
        assert!(decoded.contains("id"));
        assert!(decoded.contains("SEL"));
    }

    #[test]
    fn test_type_encoding_is_valid() {
        assert!(ObjcTypeEncoding::is_valid_encoding('i'));
        assert!(ObjcTypeEncoding::is_valid_encoding('v'));
        assert!(ObjcTypeEncoding::is_valid_encoding('4'));
        assert!(!ObjcTypeEncoding::is_valid_encoding('z'));
    }
}
