//! Objective-C 2.x (modern) metadata structures.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.objc.objc2` Java package.
//! These structures represent the modern Objective-C runtime metadata format
//! used in Mach-O binaries, supporting both 32-bit and 64-bit.
//!
//! # Structures
//!
//! - [`Objc2Constants`] -- section names and constants
//! - [`Objc2ImageInfo`] -- image info flags
//! - [`Objc2Class`] -- a class definition (with ro_data pointer)
//! - [`Objc2ClassRW`] -- class read-write data
//! - [`Objc2Category`] -- a category definition
//! - [`Objc2Method`] -- a method
//! - [`Objc2MethodList`] -- a list of methods
//! - [`Objc2Property`] -- a property
//! - [`Objc2PropertyList`] -- a list of properties
//! - [`Objc2Protocol`] -- a protocol definition
//! - [`Objc2ProtocolList`] -- a list of protocols
//! - [`Objc2InstanceVariable`] -- an instance variable
//! - [`Objc2InstanceVariableList`] -- a list of instance variables
//! - [`Objc2Cache`] -- a method cache
//! - [`Objc2Implementation`] -- an implementation reference
//! - [`Objc2MessageReference`] -- a message reference (for swift)
//! - [`Objc2TypeMetadata`] -- the top-level metadata parser

use super::{ObjcMethod, ObjcMethodType, ObjcState};

// ============================================================================
// Objc2Constants
// ============================================================================

/// Constants and section names for Objective-C 2.x metadata.
///
/// Corresponds to Java's `Objc2Constants`.
pub struct Objc2Constants;

impl Objc2Constants {
    /// Category path for ObjC2 data types.
    pub const CATEGORY_PATH: &'static str = "ghidra/app/util/bin/format/objc/objc2";

    /// The Objective-C segment name (modern).
    pub const OBJC_SEGMENT: &'static str = "__DATA_CONST";

    // Section names for ObjC2 metadata
    /// Class list section.
    pub const SECTION_CLASS_LIST: &'static str = "__objc_classlist";
    /// Non-lazy class list.
    pub const SECTION_NON_LAZY_CLASS_LIST: &'static str = "__objc_nlclslist";
    /// Category list section.
    pub const SECTION_CATEGORY_LIST: &'static str = "__objc_catlist";
    /// Non-lazy category list.
    pub const SECTION_NON_LAZY_CATEGORY_LIST: &'static str = "__objc_nlcatlist";
    /// Protocol list section.
    pub const SECTION_PROTOCOL_LIST: &'static str = "__objc_protolist";
    /// Image info section.
    pub const SECTION_IMAGE_INFO: &'static str = "__objc_imageinfo";
    /// Message references (Swift).
    pub const SECTION_MESSAGE_REFS: &'static str = "__objc_methrefs";
    /// Class references.
    pub const SECTION_CLASS_REFS: &'static str = "__objc_classrefs";
    /// Super references.
    pub const SECTION_SUPER_REFS: &'static str = "__objc_superrefs";

    /// Get all ObjC2 section names.
    pub fn section_names() -> Vec<&'static str> {
        vec![
            Self::SECTION_CLASS_LIST,
            Self::SECTION_NON_LAZY_CLASS_LIST,
            Self::SECTION_CATEGORY_LIST,
            Self::SECTION_NON_LAZY_CATEGORY_LIST,
            Self::SECTION_PROTOCOL_LIST,
            Self::SECTION_IMAGE_INFO,
            Self::SECTION_MESSAGE_REFS,
            Self::SECTION_CLASS_REFS,
            Self::SECTION_SUPER_REFS,
        ]
    }

    /// Check if a section name is a valid ObjC2 section.
    pub fn is_objc2_section(name: &str) -> bool {
        Self::section_names().contains(&name)
    }

    // Class info flags (from objc-runtime-new.h)
    /// Class is a metaclass.
    pub const RO_META: u32 = 1 << 0;
    /// Class is a root class.
    pub const RO_ROOT: u32 = 1 << 1;
    /// Class has a C++ constructor/destructor.
    pub const RO_HAS_CXX_STRUCTORS: u32 = 1 << 2;
    /// Hidden visibility.
    pub const RO_HIDDEN: u32 = 1 << 4;
    /// Exception support.
    pub const RO_EXCEPTION: u32 = 1 << 6;
    /// Bundle class.
    pub const RO_FROM_BUNDLE: u32 = 1 << 7;
    /// Class is lazy (non-fragile).
    pub const RO_IS_ARC: u32 = 1 << 8;
    /// Class has a swift refcount.
    pub const RO_HAS_SWIFT_RAW_RC: u32 = 1 << 20;
}

// ============================================================================
// Objc2ImageInfo
// ============================================================================

/// Image info for an Objective-C 2.x binary.
///
/// The structure in the binary is:
/// ```text
/// struct objc_image_info {
///     uint32_t version;
///     uint32_t flags;
/// };
/// ```
///
/// Corresponds to Java's `Objc2ImageInfo`.
#[derive(Debug, Clone)]
pub struct Objc2ImageInfo {
    /// The Objective-C version.
    pub version: u32,
    /// The image flags.
    pub flags: u32,
    /// Base address.
    pub base: u64,
}

impl Objc2ImageInfo {
    /// Structure name.
    pub const NAME: &'static str = "objc_image_info";

    /// Parse an image info from a data buffer.
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + 8 > data.len() {
            return None;
        }
        let version = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let flags = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        Some(Self {
            version,
            flags,
            base: offset as u64,
        })
    }

    /// Whether the image uses garbage collection.
    pub fn has_gc(&self) -> bool {
        self.flags & 0x1 != 0
    }

    /// Whether the image is compiled for ARC.
    pub fn is_arc(&self) -> bool {
        self.flags & 0x2 != 0
    }

    /// Whether the image uses Swift.
    pub fn has_swift(&self) -> bool {
        self.version >= 1
    }
}

// ============================================================================
// Objc2Cache
// ============================================================================

/// The method cache for an Objective-C 2.x class.
///
/// Corresponds to Java's `Objc2Cache`. In practice, this is a typedef
/// to the appropriate pointer-size word.
///
/// Corresponds to Java's `Objc2Cache`.
#[derive(Debug, Clone)]
pub struct Objc2Cache {
    /// Cache data (pointer-sized).
    pub data: u64,
    /// Whether this is a 32-bit cache.
    pub is_32bit: bool,
    /// Base address.
    pub base: u64,
}

impl Objc2Cache {
    /// Parse a cache entry from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        let size = if is_32bit { 4 } else { 8 };
        if offset + size > data.len() {
            return None;
        }
        let cache_data = if is_32bit {
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
        Some(Self {
            data: cache_data,
            is_32bit,
            base: offset as u64,
        })
    }
}

// ============================================================================
// Objc2InstanceVariable
// ============================================================================

/// An Objective-C 2.x instance variable (ivar).
///
/// The structure in the binary is:
/// ```text
/// struct ivar_t {
///     int32_t *offset;    // pointer to ivar offset
///     char    *name;
///     char    *type;
///     uint32_t alignment;
///     uint32_t size;
/// };
/// ```
///
/// Corresponds to Java's `Objc2InstanceVariable`.
#[derive(Debug, Clone)]
pub struct Objc2InstanceVariable {
    /// Pointer to the ivar offset variable.
    pub offset_ptr: u64,
    /// The ivar name.
    pub name: String,
    /// The type encoding.
    pub type_encoding: String,
    /// Alignment in bytes (log2 encoded).
    pub alignment: u32,
    /// Size in bytes.
    pub size: u32,
    /// Base address.
    pub base: u64,
}

impl Objc2InstanceVariable {
    /// Parse an ivar from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + 4 * ptr_size > data.len() {
            return None;
        }

        let mut pos = offset;

        // offset pointer
        let offset_ptr = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as u64;
            pos += 4;
            v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]);
            pos += 8;
            v
        };

        // name pointer
        let name_addr = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]) as usize;
            pos += 8;
            v
        };

        // type pointer
        let type_addr = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]) as usize;
            pos += 8;
            v
        };

        if pos + 8 > data.len() {
            return None;
        }

        let alignment = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        let size = u32::from_le_bytes([data[pos+4], data[pos+5], data[pos+6], data[pos+7]]);

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("ivar_{}", offset));
        let type_encoding = super::ObjcUtils::read_string_at(data, type_addr)
            .unwrap_or_default();

        Some(Self {
            offset_ptr,
            name,
            type_encoding,
            alignment,
            size,
            base: offset as u64,
        })
    }

    /// Get the ivar name.
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// Objc2InstanceVariableList
// ============================================================================

/// A list of Objective-C 2.x instance variables.
///
/// The structure is:
/// ```text
/// struct ivar_list_t {
///     uint32_t entsize;
///     uint32_t count;
///     ivar_t   first; // followed by count-1 more
/// };
/// ```
///
/// Corresponds to Java's `Objc2InstanceVariableList`.
#[derive(Debug, Clone)]
pub struct Objc2InstanceVariableList {
    /// Entry size (for forward compatibility).
    pub entsize: u32,
    /// Number of ivars.
    pub count: u32,
    /// The ivars.
    pub ivars: Vec<Objc2InstanceVariable>,
    /// Base address.
    pub base: u64,
}

impl Objc2InstanceVariableList {
    /// Structure name.
    pub const NAME: &'static str = "ivar_list_t";

    /// Parse an ivar list from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
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

        let mut ivars = Vec::new();
        let entry_size = if entsize > 0 { entsize as usize } else { if is_32bit { 20 } else { 40 } };
        let mut pos = offset + 8;

        for _ in 0..count {
            if let Some(ivar) = Objc2InstanceVariable::parse(data, pos, is_32bit) {
                ivars.push(ivar);
            }
            pos += entry_size;
        }

        Some(Self {
            entsize,
            count,
            ivars,
            base: offset as u64,
        })
    }

    /// Get the ivars.
    pub fn ivars(&self) -> &[Objc2InstanceVariable] {
        &self.ivars
    }
}

// ============================================================================
// Objc2Method
// ============================================================================

/// An Objective-C 2.x method.
///
/// The structure in the binary is:
/// ```text
/// struct method_t {
///     SEL    name;     // pointer to selector name
///     char  *types;    // pointer to type encoding
///     IMP    imp;      // pointer to implementation
/// };
/// ```
///
/// Corresponds to Java's `Objc2Method`.
#[derive(Debug, Clone)]
pub struct Objc2Method {
    /// The base ObjcMethod fields.
    pub method: ObjcMethod,
}

impl Objc2Method {
    /// Parse a method from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool, method_type: ObjcMethodType) -> Option<Self> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + 3 * ptr_size > data.len() {
            return None;
        }

        let mut pos = offset;

        // name (selector pointer)
        let name_addr = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]) as usize;
            pos += 8;
            v
        };

        // types pointer
        let types_addr = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]) as usize;
            pos += 8;
            v
        };

        // implementation pointer
        let imp = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as u64;
            pos += 4;
            v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]);
            pos += 8;
            v
        };

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("method_{}", offset));
        let types = super::ObjcUtils::read_string_at(data, types_addr)
            .unwrap_or_default();
        let _ = pos;

        Some(Self {
            method: ObjcMethod::new(name, types, imp, method_type, offset as u64),
        })
    }

    /// Get the method name.
    pub fn get_name(&self) -> &str {
        &self.method.name
    }

    /// Get the implementation address.
    pub fn get_implementation(&self) -> u64 {
        self.method.implementation
    }

    /// Get the method type.
    pub fn method_type(&self) -> ObjcMethodType {
        self.method.method_type
    }
}

// ============================================================================
// Objc2MethodList
// ============================================================================

/// A list of Objective-C 2.x methods.
///
/// The structure is:
/// ```text
/// struct method_list_t {
///     uint32_t entsize;   // low 2 bits used for flags
///     uint32_t count;
///     method_t first;     // followed by count-1 more
/// };
/// ```
///
/// Corresponds to Java's `Objc2MethodList`.
#[derive(Debug, Clone)]
pub struct Objc2MethodList {
    /// Entry size (with flag bits masked off).
    pub entsize: u32,
    /// Number of methods.
    pub count: u32,
    /// Whether the methods are relative (compact) pointers.
    pub is_relative: bool,
    /// The methods.
    pub methods: Vec<Objc2Method>,
    /// Base address.
    pub base: u64,
}

impl Objc2MethodList {
    /// Structure name.
    pub const NAME: &'static str = "method_list_t";

    /// Parse a method list from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool, method_type: ObjcMethodType) -> Option<Self> {
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

        // Low 2 bits of entsize are flags
        let is_relative = raw_entsize & 0x80000000 != 0;
        let entsize = raw_entsize & 0xFFFFFC; // mask off flag bits

        let entry_size = if entsize > 0 {
            entsize as usize
        } else {
            if is_32bit { 12 } else { 24 }
        };

        let mut methods = Vec::new();
        let mut pos = offset + 8;

        for _ in 0..count {
            if let Some(method) = Objc2Method::parse(data, pos, is_32bit, method_type) {
                methods.push(method);
            }
            pos += entry_size;
        }

        Some(Self {
            entsize,
            count,
            is_relative,
            methods,
            base: offset as u64,
        })
    }

    /// Get the methods.
    pub fn methods(&self) -> &[Objc2Method] {
        &self.methods
    }

    /// Get the count.
    pub fn count(&self) -> usize {
        self.methods.len()
    }
}

// ============================================================================
// Objc2Property
// ============================================================================

/// An Objective-C 2.x property.
///
/// The structure in the binary is:
/// ```text
/// struct property_t {
///     char *name;
///     char *attributes;
/// };
/// ```
///
/// Corresponds to Java's `Objc2Property`.
#[derive(Debug, Clone)]
pub struct Objc2Property {
    /// The property name.
    pub name: String,
    /// The property attributes string.
    pub attributes: String,
    /// Base address.
    pub base: u64,
}

impl Objc2Property {
    /// Parse a property from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + 2 * ptr_size > data.len() {
            return None;
        }

        let mut pos = offset;

        let name_addr = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]) as usize;
            pos += 8;
            v
        };

        let attr_addr = if is_32bit {
            u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize
        } else {
            u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]) as usize
        };

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("prop_{}", offset));
        let attributes = super::ObjcUtils::read_string_at(data, attr_addr)
            .unwrap_or_default();

        Some(Self {
            name,
            attributes,
            base: offset as u64,
        })
    }

    /// Get the property name.
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// Objc2PropertyList
// ============================================================================

/// A list of Objective-C 2.x properties.
///
/// Corresponds to Java's `Objc2PropertyList`.
#[derive(Debug, Clone)]
pub struct Objc2PropertyList {
    /// Entry size.
    pub entsize: u32,
    /// Number of properties.
    pub count: u32,
    /// The properties.
    pub properties: Vec<Objc2Property>,
    /// Base address.
    pub base: u64,
}

impl Objc2PropertyList {
    /// Structure name.
    pub const NAME: &'static str = "property_list_t";

    /// Parse a property list from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        if offset + 8 > data.len() {
            return None;
        }

        let entsize = u32::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
        ]);
        let count = u32::from_le_bytes([
            data[offset+4], data[offset+5], data[offset+6], data[offset+7],
        ]);

        let entry_size = if entsize > 0 {
            entsize as usize
        } else {
            if is_32bit { 8 } else { 16 }
        };

        let mut properties = Vec::new();
        let mut pos = offset + 8;

        for _ in 0..count {
            if let Some(prop) = Objc2Property::parse(data, pos, is_32bit) {
                properties.push(prop);
            }
            pos += entry_size;
        }

        Some(Self {
            entsize,
            count,
            properties,
            base: offset as u64,
        })
    }

    /// Get the properties.
    pub fn properties(&self) -> &[Objc2Property] {
        &self.properties
    }
}

// ============================================================================
// Objc2Protocol
// ============================================================================

/// An Objective-C 2.x protocol definition.
///
/// The structure in the binary is complex (contains pointers to methods,
/// properties, and other protocols). We parse the name and flags at minimum.
///
/// Corresponds to Java's `Objc2Protocol`.
#[derive(Debug, Clone)]
pub struct Objc2Protocol {
    /// The protocol name.
    pub name: String,
    /// Protocols this protocol conforms to.
    pub protocols: Vec<String>,
    /// Instance methods.
    pub instance_methods: Option<Objc2MethodList>,
    /// Class methods.
    pub class_methods: Option<Objc2MethodList>,
    /// Optional instance methods.
    pub optional_instance_methods: Option<Objc2MethodList>,
    /// Optional class methods.
    pub optional_class_methods: Option<Objc2MethodList>,
    /// Instance properties.
    pub instance_properties: Option<Objc2PropertyList>,
    /// Base address.
    pub base: u64,
}

impl Objc2Protocol {
    /// Structure name.
    pub const NAME: &'static str = "protocol_t";

    /// Parse a protocol from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + ptr_size > data.len() {
            return None;
        }

        let mut pos = offset;

        // isa pointer (usually 0 for protocols)
        pos += ptr_size;

        // name pointer
        let name_addr = if is_32bit {
            if pos + 4 > data.len() { return None; }
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            v
        } else {
            if pos + 8 > data.len() { return None; }
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]) as usize;
            pos += 8;
            v
        };

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("protocol_{}", offset));
        let _ = pos;

        // Skip: protocols pointer, instanceMethods, classMethods,
        //        optionalInstanceMethods, optionalClassMethods,
        //        instanceProperties (6 pointers)
        // We just read the name for now; full parsing would chase all pointers.

        Some(Self {
            name,
            protocols: Vec::new(),
            instance_methods: None,
            class_methods: None,
            optional_instance_methods: None,
            optional_class_methods: None,
            instance_properties: None,
            base: offset as u64,
        })
    }

    /// Get the protocol name.
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// Objc2ProtocolList
// ============================================================================

/// A list of Objective-C 2.x protocols.
///
/// Corresponds to Java's `Objc2ProtocolList`.
#[derive(Debug, Clone)]
pub struct Objc2ProtocolList {
    /// Number of protocols.
    pub count: u64,
    /// The protocols.
    pub protocols: Vec<Objc2Protocol>,
    /// Base address.
    pub base: u64,
}

impl Objc2ProtocolList {
    /// Structure name.
    pub const NAME: &'static str = "protocol_list_t";

    /// Parse a protocol list from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + ptr_size > data.len() {
            return None;
        }

        let count = if is_32bit {
            u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
            ]) as u64
        } else {
            u64::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
                data[offset+4], data[offset+5], data[offset+6], data[offset+7],
            ])
        };

        let mut protocols = Vec::new();
        let mut pos = offset + ptr_size;

        for _ in 0..count {
            // Each entry is a pointer to a protocol_t
            let proto_addr = if is_32bit {
                if pos + 4 > data.len() { break; }
                let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
                pos += 4;
                v
            } else {
                if pos + 8 > data.len() { break; }
                let v = u64::from_le_bytes([
                    data[pos], data[pos+1], data[pos+2], data[pos+3],
                    data[pos+4], data[pos+5], data[pos+6], data[pos+7],
                ]) as usize;
                pos += 8;
                v
            };

            if let Some(proto) = Objc2Protocol::parse(data, proto_addr, is_32bit) {
                protocols.push(proto);
            }
        }

        Some(Self {
            count,
            protocols,
            base: offset as u64,
        })
    }

    /// Get the protocols.
    pub fn protocols(&self) -> &[Objc2Protocol] {
        &self.protocols
    }
}

// ============================================================================
// Objc2ClassRW / Objc2Class
// ============================================================================

/// Read-write class data (pointed to by the class structure).
///
/// Corresponds to Java's `Objc2ClassRW`.
#[derive(Debug, Clone)]
pub struct Objc2ClassRW {
    /// Flags.
    pub flags: u32,
    /// The class name (from ro_data).
    pub name: String,
    /// Base address.
    pub base: u64,
}

impl Objc2ClassRW {
    /// Parse class RW data from a buffer.
    pub fn parse(data: &[u8], offset: usize, _is_32bit: bool) -> Option<Self> {
        if offset + 4 > data.len() {
            return None;
        }
        let flags = u32::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
        ]);
        Some(Self {
            flags,
            name: String::new(),
            base: offset as u64,
        })
    }
}

/// An Objective-C 2.x class definition.
///
/// The class structure points to `class_ro_t` which contains the actual name,
/// methods, properties, etc. This struct represents the top-level class pointer.
///
/// Corresponds to Java's `Objc2Class`.
#[derive(Debug, Clone)]
pub struct Objc2Class {
    /// Pointer to the metaclass.
    pub isa: u64,
    /// Pointer to the superclass.
    pub super_class: u64,
    /// Pointer to the method cache.
    pub cache: Objc2Cache,
    /// Pointer to the class_rw_t (vtable / data).
    pub data: u64,
    /// The class name (resolved from ro_data).
    pub name: String,
    /// Instance methods.
    pub instance_methods: Option<Objc2MethodList>,
    /// Class methods.
    pub class_methods: Option<Objc2MethodList>,
    /// Instance variables.
    pub instance_variables: Option<Objc2InstanceVariableList>,
    /// Protocols.
    pub protocols: Option<Objc2ProtocolList>,
    /// Instance properties.
    pub instance_properties: Option<Objc2PropertyList>,
    /// Base address.
    pub base: u64,
    /// Whether this is a metaclass.
    pub is_meta: bool,
}

impl Objc2Class {
    /// Structure name.
    pub const NAME: &'static str = "class_t";

    /// Parse a class pointer from a data buffer.
    ///
    /// The class list section contains pointers to class_t structures.
    pub fn parse_pointer(data: &[u8], offset: usize, is_32bit: bool) -> Option<u64> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + ptr_size > data.len() {
            return None;
        }
        if is_32bit {
            Some(u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
            ]) as u64)
        } else {
            Some(u64::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
                data[offset+4], data[offset+5], data[offset+6], data[offset+7],
            ]))
        }
    }

    /// Parse a class structure from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + 4 * ptr_size > data.len() {
            return None;
        }

        let mut pos = offset;

        // isa
        let isa = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as u64;
            pos += 4; v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]);
            pos += 8; v
        };

        // superclass
        let super_class = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as u64;
            pos += 4; v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]);
            pos += 8; v
        };

        // cache (2 pointer-sized words)
        let cache = Objc2Cache::parse(data, pos, is_32bit)
            .unwrap_or(Objc2Cache { data: 0, is_32bit, base: pos as u64 });
        pos += 2 * ptr_size;

        // data pointer (class_rw_t *)
        let data_ptr = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as u64;
            pos += 4; v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]);
            pos += 8; v
        };
        let _ = pos;

        Some(Self {
            isa,
            super_class,
            cache,
            data: data_ptr,
            name: format!("class_{}", offset),
            instance_methods: None,
            class_methods: None,
            instance_variables: None,
            protocols: None,
            instance_properties: None,
            base: offset as u64,
            is_meta: false,
        })
    }

    /// Get the class name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Set the class name.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Whether this is a metaclass.
    pub fn is_meta_class(&self) -> bool {
        self.is_meta
    }
}

// ============================================================================
// Objc2Category
// ============================================================================

/// An Objective-C 2.x category definition.
///
/// The structure in the binary is:
/// ```text
/// struct category_t {
///     char *name;
///     class_t *cls;
///     method_list_t *instanceMethods;
///     method_list_t *classMethods;
///     protocol_list_t *protocols;
///     property_list_t *instanceProperties;
///     // fields below only exist in newer ABIs
///     property_list_t *_classProperties;
/// };
/// ```
///
/// Corresponds to Java's `Objc2Category`.
#[derive(Debug, Clone)]
pub struct Objc2Category {
    /// The category name.
    pub name: String,
    /// The class this category extends (pointer).
    pub class_ptr: u64,
    /// Instance methods.
    pub instance_methods: Option<Objc2MethodList>,
    /// Class methods.
    pub class_methods: Option<Objc2MethodList>,
    /// Protocols.
    pub protocols: Option<Objc2ProtocolList>,
    /// Instance properties.
    pub instance_properties: Option<Objc2PropertyList>,
    /// Base address.
    pub base: u64,
}

impl Objc2Category {
    /// Structure name.
    pub const NAME: &'static str = "category_t";

    /// Parse a category pointer from a data buffer.
    pub fn parse_pointer(data: &[u8], offset: usize, is_32bit: bool) -> Option<u64> {
        Objc2Class::parse_pointer(data, offset, is_32bit)
    }

    /// Parse a category from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + 6 * ptr_size > data.len() {
            return None;
        }

        let mut pos = offset;

        // name pointer
        let name_addr = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4; v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]) as usize;
            pos += 8; v
        };

        // class pointer
        let class_ptr = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as u64;
            pos += 4; v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]);
            pos += 8; v
        };
        let _ = pos;

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("category_{}", offset));

        Some(Self {
            name,
            class_ptr,
            instance_methods: None,
            class_methods: None,
            protocols: None,
            instance_properties: None,
            base: offset as u64,
        })
    }

    /// Get the category name.
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// Objc2Implementation
// ============================================================================

/// An Objective-C 2.x implementation reference.
///
/// Corresponds to Java's `Objc2Implementation`.
#[derive(Debug, Clone)]
pub struct Objc2Implementation {
    /// The function pointer.
    pub function_ptr: u64,
    /// Base address.
    pub base: u64,
}

impl Objc2Implementation {
    /// Parse an implementation from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + ptr_size > data.len() {
            return None;
        }
        let function_ptr = if is_32bit {
            u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
            ]) as u64
        } else {
            u64::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
                data[offset+4], data[offset+5], data[offset+6], data[offset+7],
            ])
        };
        Some(Self { function_ptr, base: offset as u64 })
    }
}

// ============================================================================
// Objc2MessageReference
// ============================================================================

/// An Objective-C 2.x message reference (used in Swift).
///
/// The structure in the binary is:
/// ```text
/// struct message_ref {
///     IMP implementation;
///     SEL selector;
/// };
/// ```
///
/// Corresponds to Java's `Objc2MessageReference`.
#[derive(Debug, Clone)]
pub struct Objc2MessageReference {
    /// The implementation address.
    pub implementation: u64,
    /// The selector name.
    pub selector: String,
    /// Base address.
    pub base: u64,
}

impl Objc2MessageReference {
    /// Structure name.
    pub const NAME: &'static str = "message_ref";

    /// Size of a message ref (2 * pointer_size).
    pub fn sizeof(pointer_size: usize) -> usize {
        2 * pointer_size
    }

    /// Parse a message reference from a data buffer.
    pub fn parse(data: &[u8], offset: usize, is_32bit: bool) -> Option<Self> {
        let ptr_size = if is_32bit { 4 } else { 8 };
        if offset + 2 * ptr_size > data.len() {
            return None;
        }

        let mut pos = offset;

        let implementation = if is_32bit {
            let v = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as u64;
            pos += 4; v
        } else {
            let v = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]);
            pos += 8; v
        };

        // selector (pointer to selector string)
        let sel_addr = if is_32bit {
            u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize
        } else {
            u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]) as usize
        };

        let selector = super::ObjcUtils::read_string_at(data, sel_addr)
            .unwrap_or_else(|| format!("sel_{}", offset));

        Some(Self {
            implementation,
            selector,
            base: offset as u64,
        })
    }
}

// ============================================================================
// Objc2TypeMetadata
// ============================================================================

/// Top-level parser for Objective-C 2.x type metadata.
///
/// Parses all ObjC2 metadata from a Mach-O binary.
///
/// Corresponds to Java's `Objc2TypeMetadata`.
#[derive(Debug)]
pub struct Objc2TypeMetadata {
    /// The parsing state.
    pub state: ObjcState,
    /// All addresses that were referenced.
    pub refs: Vec<u64>,
    /// Image info entries.
    pub image_infos: Vec<Objc2ImageInfo>,
    /// Categories.
    pub categories: Vec<Objc2Category>,
    /// Classes.
    pub classes: Vec<Objc2Class>,
    /// Protocols.
    pub protocols: Vec<Objc2Protocol>,
    /// Message references.
    pub message_refs: Vec<Objc2MessageReference>,
    /// Log messages.
    pub log_messages: Vec<String>,
}

impl Objc2TypeMetadata {
    /// Create a new ObjC2 type metadata parser.
    pub fn new(is_32bit: bool) -> Self {
        let state = ObjcState::new(if is_32bit { 4 } else { 8 }, Objc2Constants::CATEGORY_PATH);
        Self {
            state,
            refs: Vec::new(),
            image_infos: Vec::new(),
            categories: Vec::new(),
            classes: Vec::new(),
            protocols: Vec::new(),
            message_refs: Vec::new(),
            log_messages: Vec::new(),
        }
    }

    /// Get all classes.
    pub fn classes(&self) -> &[Objc2Class] {
        &self.classes
    }

    /// Get all categories.
    pub fn categories(&self) -> &[Objc2Category] {
        &self.categories
    }

    /// Get all protocols.
    pub fn protocols(&self) -> &[Objc2Protocol] {
        &self.protocols
    }

    /// Get all message references.
    pub fn message_refs(&self) -> &[Objc2MessageReference] {
        &self.message_refs
    }

    /// Get all image info entries.
    pub fn image_infos(&self) -> &[Objc2ImageInfo] {
        &self.image_infos
    }

    /// Get referenced addresses.
    pub fn refs(&self) -> &[u64] {
        &self.refs
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_objc2_constants() {
        assert_eq!(Objc2Constants::CATEGORY_PATH, "ghidra/app/util/bin/format/objc/objc2");
        assert!(Objc2Constants::section_names().len() >= 8);
        assert!(Objc2Constants::is_objc2_section("__objc_classlist"));
        assert!(!Objc2Constants::is_objc2_section("__text"));
        assert_eq!(Objc2Constants::RO_META, 1);
        assert_eq!(Objc2Constants::RO_IS_ARC, 1 << 8);
    }

    #[test]
    fn test_objc2_image_info() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // version
        data[4..8].copy_from_slice(&0x3u32.to_le_bytes()); // flags (GC + ARC)

        let info = Objc2ImageInfo::parse(&data, 0);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.version, 2);
        assert!(info.has_gc());
        assert!(info.is_arc());
        assert!(info.has_swift());
    }

    #[test]
    fn test_objc2_image_info_no_flags() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());

        let info = Objc2ImageInfo::parse(&data, 0).unwrap();
        assert!(!info.has_gc());
        assert!(!info.is_arc());
        assert!(!info.has_swift());
    }

    #[test]
    fn test_objc2_cache() {
        let data = [0x78u8, 0x56, 0x34, 0x12];
        let cache = Objc2Cache::parse(&data, 0, true);
        assert!(cache.is_some());
        assert_eq!(cache.unwrap().data, 0x12345678);
    }

    #[test]
    fn test_objc2_class_parse_64bit() {
        let mut data = vec![0u8; 256];

        // class_t at offset 0 (64-bit)
        let mut pos = 0;
        // isa = 0x100
        data[pos..pos+8].copy_from_slice(&0x100u64.to_le_bytes());
        pos += 8;
        // superclass = 0x200
        data[pos..pos+8].copy_from_slice(&0x200u64.to_le_bytes());
        pos += 8;
        // cache (16 bytes)
        data[pos..pos+16].copy_from_slice(&[0u8; 16]);
        pos += 16;
        // data = 0x300
        data[pos..pos+8].copy_from_slice(&0x300u64.to_le_bytes());

        let class = Objc2Class::parse(&data, 0, false);
        assert!(class.is_some());
        let class = class.unwrap();
        assert_eq!(class.isa, 0x100);
        assert_eq!(class.super_class, 0x200);
        assert_eq!(class.data, 0x300);
        assert!(!class.is_meta_class());
    }

    #[test]
    fn test_objc2_category_parse() {
        let mut data = vec![0u8; 256];

        // Category name at offset 200
        let name = b"MyCategory\0";
        data[200..200 + name.len()].copy_from_slice(name);

        // category_t at offset 0 (32-bit)
        data[0..4].copy_from_slice(&200u32.to_le_bytes()); // name ptr
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // class ptr
        // remaining pointers are 0

        let cat = Objc2Category::parse(&data, 0, true);
        assert!(cat.is_some());
        let cat = cat.unwrap();
        assert_eq!(cat.get_name(), "MyCategory");
    }

    #[test]
    fn test_objc2_method_parse() {
        let mut data = vec![0u8; 256];

        // Method name at offset 100
        let name = b"viewDidLoad\0";
        data[100..100 + name.len()].copy_from_slice(name);

        // Types at offset 120
        let types = b"v16@0:8\0";
        data[120..120 + types.len()].copy_from_slice(types);

        // method_t at offset 0 (32-bit)
        data[0..4].copy_from_slice(&100u32.to_le_bytes()); // name ptr
        data[4..8].copy_from_slice(&120u32.to_le_bytes()); // types ptr
        data[8..12].copy_from_slice(&0x5000u32.to_le_bytes()); // imp

        let method = Objc2Method::parse(&data, 0, true, ObjcMethodType::Instance);
        assert!(method.is_some());
        let method = method.unwrap();
        assert_eq!(method.get_name(), "viewDidLoad");
        assert_eq!(method.get_implementation(), 0x5000);
    }

    #[test]
    fn test_objc2_method_list_parse() {
        let mut data = vec![0u8; 512];

        // method_list_t at offset 0
        data[0..4].copy_from_slice(&12u32.to_le_bytes()); // entsize = 12 (3 * 4)
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // count = 1

        // Method at offset 8
        let name = b"init\0";
        data[200..200 + name.len()].copy_from_slice(name);
        data[8..12].copy_from_slice(&200u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // types = NULL
        data[16..20].copy_from_slice(&0x4000u32.to_le_bytes()); // imp

        let list = Objc2MethodList::parse(&data, 0, true, ObjcMethodType::Instance);
        assert!(list.is_some());
        let list = list.unwrap();
        assert_eq!(list.count(), 1);
        assert_eq!(list.methods()[0].get_name(), "init");
    }

    #[test]
    fn test_objc2_property_parse() {
        let mut data = vec![0u8; 256];

        // Property name at offset 100
        let name = b"frame\0";
        data[100..100 + name.len()].copy_from_slice(name);

        // Attributes at offset 120
        let attr = b"T{CGRect={CGPoint=ff}{CGSize=ff}},N,V_frame\0";
        data[120..120 + attr.len()].copy_from_slice(attr);

        // property_t at offset 0 (32-bit)
        data[0..4].copy_from_slice(&100u32.to_le_bytes());
        data[4..8].copy_from_slice(&120u32.to_le_bytes());

        let prop = Objc2Property::parse(&data, 0, true);
        assert!(prop.is_some());
        let prop = prop.unwrap();
        assert_eq!(prop.get_name(), "frame");
        assert!(prop.attributes.starts_with("T{CGRect"));
    }

    #[test]
    fn test_objc2_property_list_parse() {
        let mut data = vec![0u8; 256];

        // property_list_t at offset 0
        data[0..4].copy_from_slice(&8u32.to_le_bytes()); // entsize
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // count = 0

        let list = Objc2PropertyList::parse(&data, 0, true);
        assert!(list.is_some());
        assert_eq!(list.unwrap().properties().len(), 0);
    }

    #[test]
    fn test_objc2_protocol_parse() {
        let mut data = vec![0u8; 256];

        // Protocol name at offset 200
        let name = b"NSCoding\0";
        data[200..200 + name.len()].copy_from_slice(name);

        // protocol_t at offset 0 (32-bit)
        // isa = 0
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        // name ptr = 200
        data[4..8].copy_from_slice(&200u32.to_le_bytes());

        let proto = Objc2Protocol::parse(&data, 0, true);
        assert!(proto.is_some());
        assert_eq!(proto.unwrap().get_name(), "NSCoding");
    }

    #[test]
    fn test_objc2_message_ref() {
        let mut data = vec![0u8; 256];

        // selector string at offset 200
        let sel = b"alloc\0";
        data[200..200 + sel.len()].copy_from_slice(sel);

        // message_ref at offset 0 (32-bit)
        data[0..4].copy_from_slice(&0x6000u32.to_le_bytes()); // implementation
        data[4..8].copy_from_slice(&200u32.to_le_bytes()); // selector

        let msg_ref = Objc2MessageReference::parse(&data, 0, true);
        assert!(msg_ref.is_some());
        let msg_ref = msg_ref.unwrap();
        assert_eq!(msg_ref.implementation, 0x6000);
        assert_eq!(msg_ref.selector, "alloc");
        assert_eq!(Objc2MessageReference::sizeof(4), 8);
    }

    #[test]
    fn test_objc2_implementation() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&0x7000u32.to_le_bytes());

        let imp = Objc2Implementation::parse(&data, 0, true);
        assert!(imp.is_some());
        assert_eq!(imp.unwrap().function_ptr, 0x7000);
    }

    #[test]
    fn test_objc2_instance_variable() {
        let mut data = vec![0u8; 256];

        // ivar name at offset 200
        let name = b"_ivar\0";
        data[200..200 + name.len()].copy_from_slice(name);

        // type at offset 220
        let types = b"i\0";
        data[220..220 + types.len()].copy_from_slice(types);

        // ivar_t at offset 0 (32-bit)
        data[0..4].copy_from_slice(&0u32.to_le_bytes()); // offset ptr
        data[4..8].copy_from_slice(&200u32.to_le_bytes()); // name ptr
        data[8..12].copy_from_slice(&220u32.to_le_bytes()); // type ptr
        data[12..16].copy_from_slice(&2u32.to_le_bytes()); // alignment
        data[16..20].copy_from_slice(&4u32.to_le_bytes()); // size

        let ivar = Objc2InstanceVariable::parse(&data, 0, true);
        assert!(ivar.is_some());
        let ivar = ivar.unwrap();
        assert_eq!(ivar.get_name(), "_ivar");
        assert_eq!(ivar.alignment, 2);
        assert_eq!(ivar.size, 4);
    }

    #[test]
    fn test_objc2_instance_variable_list() {
        let mut data = vec![0u8; 64];

        // ivar_list_t at offset 0
        data[0..4].copy_from_slice(&20u32.to_le_bytes()); // entsize = 20
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // count = 0

        let list = Objc2InstanceVariableList::parse(&data, 0, true);
        assert!(list.is_some());
        assert_eq!(list.unwrap().ivars().len(), 0);
    }

    #[test]
    fn test_objc2_type_metadata() {
        let meta = Objc2TypeMetadata::new(true);
        assert!(meta.classes().is_empty());
        assert!(meta.categories().is_empty());
        assert!(meta.protocols().is_empty());
        assert!(meta.message_refs().is_empty());
        assert!(meta.image_infos().is_empty());
        assert!(meta.refs().is_empty());
    }

    #[test]
    fn test_objc2_parse_too_short() {
        let data = [0u8; 2];
        assert!(Objc2Class::parse(&data, 0, false).is_none());
        assert!(Objc2Category::parse(&data, 0, false).is_none());
        assert!(Objc2Method::parse(&data, 0, false, ObjcMethodType::Instance).is_none());
        assert!(Objc2ImageInfo::parse(&data, 0).is_none());
        assert!(Objc2Protocol::parse(&data, 0, false).is_none());
    }

    #[test]
    fn test_objc2_class_parse_pointer() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&0xABCDu32.to_le_bytes());
        assert_eq!(Objc2Class::parse_pointer(&data, 0, true), Some(0xABCD));
    }
}
