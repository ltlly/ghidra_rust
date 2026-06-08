//! Complete Objective-C 2.x protocol parsing with all fields.
//!
//! Ported from Ghidra's `Objc2Protocol` Java class (256 lines).
//!
//! The existing `objc2.rs` module has a simplified protocol parser that
//! only reads the name. This module provides the full implementation that
//! parses ALL protocol fields: isa, name, protocols list, instance methods,
//! class methods, optional instance methods, optional class methods,
//! instance properties, and unknown trailing fields.
//!
//! # Structure Layout (from `objc-runtime-new.h`)
//!
//! ```text
//! struct protocol_t {
//!     uintptr_t isa;              // always 0 for protocols
//!     const char *mangledName;
//!     protocol_list_t *protocols;
//!     method_list_t *instanceMethods;
//!     method_list_t *classMethods;
//!     method_list_t *optionalInstanceMethods;
//!     method_list_t *optionalClassMethods;
//!     property_list_t *instanceProperties;
//!     // 32-bit: 2x uint32_t unknown
//!     // 64-bit: 2x uint64_t unknown
//! };
//! ```

use super::ObjcState;

// ============================================================================
// Objc2ProtocolFull -- complete protocol parsing
// ============================================================================

/// A fully parsed Objective-C 2.x protocol definition.
///
/// This parses ALL fields from the protocol_t structure, including
/// sub-objects like method lists, property lists, and protocol lists.
///
/// Corresponds to Java's `Objc2Protocol` with all `read*` methods.
#[derive(Debug, Clone)]
pub struct Objc2ProtocolFull {
    /// ISA pointer (always 0 for protocols).
    pub isa: u64,
    /// The protocol name.
    pub name: String,
    /// Protocols this protocol conforms to.
    pub protocols: Option<Objc2ProtocolListRef>,
    /// Instance methods.
    pub instance_methods: Option<Objc2MethodListRef>,
    /// Class methods.
    pub class_methods: Option<Objc2MethodListRef>,
    /// Optional instance methods.
    pub optional_instance_methods: Option<Objc2MethodListRef>,
    /// Optional class methods.
    pub optional_class_methods: Option<Objc2MethodListRef>,
    /// Instance properties.
    pub instance_properties: Option<Objc2PropertyListRef>,
    /// Unknown trailing field 0.
    pub unknown0: u64,
    /// Unknown trailing field 1.
    pub unknown1: u64,
    /// The base address of this structure.
    pub base: u64,
    /// Whether this is a 32-bit structure.
    pub is_32bit: bool,
}

/// A reference to a method list (pointer + parsed data).
#[derive(Debug, Clone)]
pub struct Objc2MethodListRef {
    /// The address of the method list structure.
    pub address: u64,
    /// Parsed methods.
    pub methods: Vec<Objc2ProtocolMethod>,
    /// Whether these are instance or class methods.
    pub is_class_methods: bool,
}

/// A method within a protocol.
#[derive(Debug, Clone)]
pub struct Objc2ProtocolMethod {
    /// The method name (selector).
    pub name: String,
    /// The type encoding string.
    pub types: String,
    /// The implementation address (may be 0 for protocol methods).
    pub implementation: u64,
    /// Whether this is an instance or class method.
    pub is_class_method: bool,
}

/// A reference to a property list.
#[derive(Debug, Clone)]
pub struct Objc2PropertyListRef {
    /// The address of the property list structure.
    pub address: u64,
    /// Parsed properties.
    pub properties: Vec<Objc2ProtocolProperty>,
}

/// A property within a protocol.
#[derive(Debug, Clone)]
pub struct Objc2ProtocolProperty {
    /// The property name.
    pub name: String,
    /// The property attributes string.
    pub attributes: String,
}

/// A reference to a protocol list (sub-protocols).
#[derive(Debug, Clone)]
pub struct Objc2ProtocolListRef {
    /// The address of the protocol list structure.
    pub address: u64,
    /// Names of conforming protocols.
    pub protocol_names: Vec<String>,
}

impl Objc2ProtocolFull {
    /// Structure name constant.
    pub const NAME: &'static str = "protocol_t";

    /// Parse a complete protocol from a data buffer.
    ///
    /// This follows all pointers and parses sub-structures.
    pub fn parse(data: &[u8], offset: usize, state: &ObjcState) -> Option<Self> {
        let is_32bit = state.is_32bit();
        let ptr_size = state.pointer_size();

        if offset + 8 * ptr_size > data.len() {
            return None;
        }

        let mut pos = offset;

        // isa
        let isa = read_ptr(data, &mut pos, is_32bit);

        // name pointer
        let name_addr = read_ptr(data, &mut pos, is_32bit);
        let name = read_string_at(data, name_addr as usize)
            .unwrap_or_else(|| format!("protocol_{}", offset));

        // protocols pointer
        let protocols_ptr = read_ptr(data, &mut pos, is_32bit);
        let protocols = if protocols_ptr != 0 {
            parse_protocol_list(data, protocols_ptr as usize, is_32bit)
        } else {
            None
        };

        // instance methods pointer
        let inst_methods_ptr = read_ptr(data, &mut pos, is_32bit);
        let instance_methods = if inst_methods_ptr != 0 {
            parse_method_list(data, inst_methods_ptr as usize, is_32bit, false)
        } else {
            None
        };

        // class methods pointer
        let class_methods_ptr = read_ptr(data, &mut pos, is_32bit);
        let class_methods = if class_methods_ptr != 0 {
            parse_method_list(data, class_methods_ptr as usize, is_32bit, true)
        } else {
            None
        };

        // optional instance methods pointer
        let opt_inst_ptr = read_ptr(data, &mut pos, is_32bit);
        let optional_instance_methods = if opt_inst_ptr != 0 {
            parse_method_list(data, opt_inst_ptr as usize, is_32bit, false)
        } else {
            None
        };

        // optional class methods pointer
        let opt_class_ptr = read_ptr(data, &mut pos, is_32bit);
        let optional_class_methods = if opt_class_ptr != 0 {
            parse_method_list(data, opt_class_ptr as usize, is_32bit, true)
        } else {
            None
        };

        // instance properties pointer
        let props_ptr = read_ptr(data, &mut pos, is_32bit);
        let instance_properties = if props_ptr != 0 {
            parse_property_list(data, props_ptr as usize, is_32bit)
        } else {
            None
        };

        // unknown trailing fields
        let unknown0 = read_ptr(data, &mut pos, is_32bit);
        let unknown1 = read_ptr(data, &mut pos, is_32bit);

        Some(Self {
            isa,
            name,
            protocols,
            instance_methods,
            class_methods,
            optional_instance_methods,
            optional_class_methods,
            instance_properties,
            unknown0,
            unknown1,
            base: offset as u64,
            is_32bit,
        })
    }

    /// Get the protocol name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the conforming protocol names.
    pub fn conforming_protocols(&self) -> Vec<&str> {
        self.protocols
            .as_ref()
            .map(|p| p.protocol_names.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get all instance method names.
    pub fn instance_method_names(&self) -> Vec<&str> {
        self.instance_methods
            .as_ref()
            .map(|ml| {
                ml.methods
                    .iter()
                    .filter(|m| !m.is_class_method)
                    .map(|m| m.name.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all class method names.
    pub fn class_method_names(&self) -> Vec<&str> {
        self.class_methods
            .as_ref()
            .map(|ml| {
                ml.methods
                    .iter()
                    .filter(|m| m.is_class_method)
                    .map(|m| m.name.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all optional instance method names.
    pub fn optional_instance_method_names(&self) -> Vec<&str> {
        self.optional_instance_methods
            .as_ref()
            .map(|ml| {
                ml.methods
                    .iter()
                    .filter(|m| !m.is_class_method)
                    .map(|m| m.name.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all optional class method names.
    pub fn optional_class_method_names(&self) -> Vec<&str> {
        self.optional_class_methods
            .as_ref()
            .map(|ml| {
                ml.methods
                    .iter()
                    .filter(|m| m.is_class_method)
                    .map(|m| m.name.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all property names.
    pub fn property_names(&self) -> Vec<&str> {
        self.instance_properties
            .as_ref()
            .map(|pl| pl.properties.iter().map(|p| p.name.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get the total number of methods (required + optional).
    pub fn total_method_count(&self) -> usize {
        let required = self
            .instance_methods
            .as_ref()
            .map(|m| m.methods.len())
            .unwrap_or(0)
            + self
                .class_methods
                .as_ref()
                .map(|m| m.methods.len())
                .unwrap_or(0);
        let optional = self
            .optional_instance_methods
            .as_ref()
            .map(|m| m.methods.len())
            .unwrap_or(0)
            + self
                .optional_class_methods
                .as_ref()
                .map(|m| m.methods.len())
                .unwrap_or(0);
        required + optional
    }

    /// Check if this protocol has any methods.
    pub fn has_methods(&self) -> bool {
        self.total_method_count() > 0
    }

    /// Check if this protocol has properties.
    pub fn has_properties(&self) -> bool {
        self.instance_properties
            .as_ref()
            .map_or(false, |p| !p.properties.is_empty())
    }

    /// Generate a summary string for this protocol.
    pub fn summary(&self) -> String {
        let mut parts = vec![format!("@protocol {}", self.name)];

        let conforming = self.conforming_protocols();
        if !conforming.is_empty() {
            parts.push(format!("<{}>", conforming.join(", ")));
        }

        parts.push(format!(
            " // {} methods, {} properties",
            self.total_method_count(),
            self.property_names().len()
        ));

        parts.join("")
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Read a pointer-sized value from data at the given position, advancing pos.
fn read_ptr(data: &[u8], pos: &mut usize, is_32bit: bool) -> u64 {
    let val = if is_32bit {
        if *pos + 4 > data.len() {
            return 0;
        }
        u32::from_le_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
        ]) as u64
    } else {
        if *pos + 8 > data.len() {
            return 0;
        }
        u64::from_le_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
            data[*pos + 4],
            data[*pos + 5],
            data[*pos + 6],
            data[*pos + 7],
        ])
    };
    *pos += if is_32bit { 4 } else { 8 };
    val
}

/// Read a null-terminated string from data at the given address.
fn read_string_at(data: &[u8], addr: usize) -> Option<String> {
    if addr >= data.len() {
        return None;
    }
    let end = data[addr..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - addr);
    std::str::from_utf8(&data[addr..addr + end])
        .ok()
        .map(|s| s.to_string())
}

/// Parse a method list at the given address.
fn parse_method_list(
    data: &[u8],
    offset: usize,
    is_32bit: bool,
    is_class: bool,
) -> Option<Objc2MethodListRef> {
    let ptr_size = if is_32bit { 4 } else { 8 };
    if offset + 8 > data.len() {
        return None;
    }

    let raw_entsize = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    let count = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);

    let entsize = raw_entsize & 0xFFFFFC; // mask off flag bits
    let entry_size = if entsize > 0 {
        entsize as usize
    } else {
        3 * ptr_size
    };

    let mut methods = Vec::new();
    let mut pos = offset + 8;

    for _ in 0..count {
        if let Some(method) = parse_method(data, pos, is_32bit, is_class) {
            methods.push(method);
        }
        pos += entry_size;
    }

    Some(Objc2MethodListRef {
        address: offset as u64,
        methods,
        is_class_methods: is_class,
    })
}

/// Parse a single method.
fn parse_method(
    data: &[u8],
    offset: usize,
    is_32bit: bool,
    is_class: bool,
) -> Option<Objc2ProtocolMethod> {
    let ptr_size = if is_32bit { 4 } else { 8 };
    if offset + 3 * ptr_size > data.len() {
        return None;
    }

    let mut pos = offset;
    let name_addr = read_ptr(data, &mut pos, is_32bit);
    let types_addr = read_ptr(data, &mut pos, is_32bit);
    let imp = read_ptr(data, &mut pos, is_32bit);

    let name = read_string_at(data, name_addr as usize)
        .unwrap_or_else(|| format!("method_{}", offset));
    let types = read_string_at(data, types_addr as usize).unwrap_or_default();

    Some(Objc2ProtocolMethod {
        name,
        types,
        implementation: imp,
        is_class_method: is_class,
    })
}

/// Parse a property list at the given address.
fn parse_property_list(
    data: &[u8],
    offset: usize,
    is_32bit: bool,
) -> Option<Objc2PropertyListRef> {
    let ptr_size = if is_32bit { 4 } else { 8 };
    if offset + 8 > data.len() {
        return None;
    }

    let entsize = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    let count = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);

    let entry_size = if entsize > 0 {
        entsize as usize
    } else {
        2 * ptr_size
    };

    let mut properties = Vec::new();
    let mut pos = offset + 8;

    for _ in 0..count {
        if let Some(prop) = parse_property(data, pos, is_32bit) {
            properties.push(prop);
        }
        pos += entry_size;
    }

    Some(Objc2PropertyListRef {
        address: offset as u64,
        properties,
    })
}

/// Parse a single property.
fn parse_property(
    data: &[u8],
    offset: usize,
    is_32bit: bool,
) -> Option<Objc2ProtocolProperty> {
    let ptr_size = if is_32bit { 4 } else { 8 };
    if offset + 2 * ptr_size > data.len() {
        return None;
    }

    let mut pos = offset;
    let name_addr = read_ptr(data, &mut pos, is_32bit);
    let attr_addr = read_ptr(data, &mut pos, is_32bit);

    let name = read_string_at(data, name_addr as usize)
        .unwrap_or_else(|| format!("prop_{}", offset));
    let attributes = read_string_at(data, attr_addr as usize).unwrap_or_default();

    Some(Objc2ProtocolProperty { name, attributes })
}

/// Parse a protocol list at the given address.
fn parse_protocol_list(
    data: &[u8],
    offset: usize,
    is_32bit: bool,
) -> Option<Objc2ProtocolListRef> {
    let ptr_size = if is_32bit { 4 } else { 8 };
    if offset + ptr_size > data.len() {
        return None;
    }

    let count = if is_32bit {
        u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64
    } else {
        u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ])
    };

    let mut protocol_names = Vec::new();
    let mut pos = offset + ptr_size;

    for _ in 0..count {
        let proto_addr = read_ptr(data, &mut pos, is_32bit);
        if proto_addr != 0 {
            // Each entry is a pointer to protocol_t; read the name field
            let name_ptr_pos = proto_addr as usize + ptr_size; // skip isa
            if let Some(name_addr) = read_ptr_safe(data, name_ptr_pos, is_32bit) {
                if let Some(name) = read_string_at(data, name_addr as usize) {
                    protocol_names.push(name);
                }
            }
        }
    }

    Some(Objc2ProtocolListRef {
        address: offset as u64,
        protocol_names,
    })
}

/// Read a pointer safely (returns None if out of bounds).
fn read_ptr_safe(data: &[u8], pos: usize, is_32bit: bool) -> Option<u64> {
    let size = if is_32bit { 4 } else { 8 };
    if pos + size > data.len() {
        return None;
    }
    Some(if is_32bit {
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as u64
    } else {
        u64::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ])
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_protocol() {
        let mut data = vec![0u8; 512];

        // Protocol name at offset 200
        let name = b"NSCoding\0";
        data[200..200 + name.len()].copy_from_slice(name);

        // protocol_t at offset 0 (32-bit)
        // isa = 0
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        // name ptr = 200
        data[4..8].copy_from_slice(&200u32.to_le_bytes());
        // protocols = 0 (no sub-protocols)
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        // instanceMethods = 0
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        // classMethods = 0
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        // optionalInstanceMethods = 0
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        // optionalClassMethods = 0
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        // instanceProperties = 0
        data[28..32].copy_from_slice(&0u32.to_le_bytes());
        // unknown0 = 0
        data[32..36].copy_from_slice(&0u32.to_le_bytes());
        // unknown1 = 0
        data[36..40].copy_from_slice(&0u32.to_le_bytes());

        let state = ObjcState::new_32bit("test");
        let proto = Objc2ProtocolFull::parse(&data, 0, &state);
        assert!(proto.is_some());
        let proto = proto.unwrap();
        assert_eq!(proto.get_name(), "NSCoding");
        assert_eq!(proto.isa, 0);
        assert!(proto.instance_methods.is_none());
        assert!(proto.class_methods.is_none());
        assert!(proto.optional_instance_methods.is_none());
        assert!(proto.optional_class_methods.is_none());
        assert!(proto.instance_properties.is_none());
        assert_eq!(proto.total_method_count(), 0);
        assert!(!proto.has_methods());
        assert!(!proto.has_properties());
    }

    #[test]
    fn test_parse_protocol_with_methods() {
        let mut data = vec![0u8; 1024];

        // Protocol name at offset 400
        let name = b"NSCoding\0";
        data[400..400 + name.len()].copy_from_slice(name);

        // Method name at offset 500
        let method_name = b"encodeWithCoder:\0";
        data[500..500 + method_name.len()].copy_from_slice(method_name);

        // Types at offset 520
        let types = b"v24@0:8@16\0";
        data[520..520 + types.len()].copy_from_slice(types);

        // method_list_t at offset 300
        data[300..304].copy_from_slice(&12u32.to_le_bytes()); // entsize = 12 (3*4)
        data[304..308].copy_from_slice(&1u32.to_le_bytes()); // count = 1
        // method at offset 308
        data[308..312].copy_from_slice(&500u32.to_le_bytes()); // name ptr
        data[312..316].copy_from_slice(&520u32.to_le_bytes()); // types ptr
        data[316..320].copy_from_slice(&0u32.to_le_bytes()); // imp = 0

        // protocol_t at offset 0 (32-bit)
        data[0..4].copy_from_slice(&0u32.to_le_bytes()); // isa
        data[4..8].copy_from_slice(&400u32.to_le_bytes()); // name ptr
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // protocols
        data[12..16].copy_from_slice(&300u32.to_le_bytes()); // instanceMethods
        data[16..20].copy_from_slice(&0u32.to_le_bytes()); // classMethods
        data[20..24].copy_from_slice(&0u32.to_le_bytes()); // optionalInstMethods
        data[24..28].copy_from_slice(&0u32.to_le_bytes()); // optionalClassMethods
        data[28..32].copy_from_slice(&0u32.to_le_bytes()); // instanceProperties
        data[32..36].copy_from_slice(&0u32.to_le_bytes()); // unknown0
        data[36..40].copy_from_slice(&0u32.to_le_bytes()); // unknown1

        let state = ObjcState::new_32bit("test");
        let proto = Objc2ProtocolFull::parse(&data, 0, &state).unwrap();
        assert_eq!(proto.get_name(), "NSCoding");
        assert!(proto.has_methods());
        assert_eq!(proto.total_method_count(), 1);
        assert_eq!(proto.instance_method_names(), vec!["encodeWithCoder:"]);
        assert!(proto.class_method_names().is_empty());
    }

    #[test]
    fn test_parse_protocol_64bit() {
        let mut data = vec![0u8; 512];

        // Protocol name at offset 300
        let name = b"NSObject\0";
        data[300..300 + name.len()].copy_from_slice(name);

        // protocol_t at offset 0 (64-bit)
        let mut pos = 0;
        // isa = 0
        data[pos..pos + 8].copy_from_slice(&0u64.to_le_bytes());
        pos += 8;
        // name ptr = 300
        data[pos..pos + 8].copy_from_slice(&300u64.to_le_bytes());
        pos += 8;
        // remaining fields = 0
        for _ in 0..6 {
            data[pos..pos + 8].copy_from_slice(&0u64.to_le_bytes());
            pos += 8;
        }
        // unknown0, unknown1 = 0
        data[pos..pos + 8].copy_from_slice(&0u64.to_le_bytes());
        pos += 8;
        data[pos..pos + 8].copy_from_slice(&0u64.to_le_bytes());

        let state = ObjcState::new_64bit("test");
        let proto = Objc2ProtocolFull::parse(&data, 0, &state).unwrap();
        assert_eq!(proto.get_name(), "NSObject");
        assert!(proto.is_32bit == false);
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0u8; 4];
        let state = ObjcState::new_32bit("test");
        assert!(Objc2ProtocolFull::parse(&data, 0, &state).is_none());
    }

    #[test]
    fn test_protocol_summary() {
        let proto = Objc2ProtocolFull {
            isa: 0,
            name: "NSCoding".into(),
            protocols: None,
            instance_methods: Some(Objc2MethodListRef {
                address: 0,
                methods: vec![Objc2ProtocolMethod {
                    name: "encodeWithCoder:".into(),
                    types: "v24@0:8@16".into(),
                    implementation: 0,
                    is_class_method: false,
                }],
                is_class_methods: false,
            }),
            class_methods: None,
            optional_instance_methods: None,
            optional_class_methods: None,
            instance_properties: None,
            unknown0: 0,
            unknown1: 0,
            base: 0,
            is_32bit: true,
        };
        let summary = proto.summary();
        assert!(summary.contains("NSCoding"));
        assert!(summary.contains("1 methods"));
    }

    #[test]
    fn test_read_string_at() {
        let data = b"\x00\x00Hello\0World\0";
        assert_eq!(read_string_at(data, 2), Some("Hello".to_string()));
        assert_eq!(read_string_at(data, 8), Some("World".to_string()));
        assert_eq!(read_string_at(data, 0), Some("".to_string()));
        assert_eq!(read_string_at(data, 100), None);
    }

    #[test]
    fn test_read_ptr() {
        let data = [0x78u8, 0x56, 0x34, 0x12];
        let mut pos = 0;
        assert_eq!(read_ptr(&data, &mut pos, true), 0x12345678);
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_method_list_ref_is_class() {
        let ml = Objc2MethodListRef {
            address: 0,
            methods: vec![],
            is_class_methods: true,
        };
        assert!(ml.is_class_methods);
    }

    #[test]
    fn test_property_names() {
        let proto = Objc2ProtocolFull {
            isa: 0,
            name: "Test".into(),
            protocols: None,
            instance_methods: None,
            class_methods: None,
            optional_instance_methods: None,
            optional_class_methods: None,
            instance_properties: Some(Objc2PropertyListRef {
                address: 0,
                properties: vec![
                    Objc2ProtocolProperty {
                        name: "frame".into(),
                        attributes: "T{CGRect},N".into(),
                    },
                    Objc2ProtocolProperty {
                        name: "bounds".into(),
                        attributes: "T{CGRect},N".into(),
                    },
                ],
            }),
            unknown0: 0,
            unknown1: 0,
            base: 0,
            is_32bit: true,
        };
        assert!(proto.has_properties());
        assert_eq!(proto.property_names(), vec!["frame", "bounds"]);
    }
}
