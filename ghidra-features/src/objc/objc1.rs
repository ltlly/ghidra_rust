//! Objective-C 1.x (legacy) metadata structures.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.objc.objc1` Java package.
//! These structures represent the older 32-bit-only Objective-C runtime metadata
//! format used in Mach-O binaries before the modern Objc2 runtime.
//!
//! # Structures
//!
//! - [`Objc1Constants`] -- section names and constants
//! - [`Objc1Module`] -- a module (image) containing class and category definitions
//! - [`Objc1SymbolTable`] -- the symbol table within a module
//! - [`Objc1Class`] -- a class definition
//! - [`Objc1Category`] -- a category definition
//! - [`Objc1Method`] -- a method within a class or category
//! - [`Objc1MethodList`] -- a list of methods
//! - [`Objc1InstanceVariable`] -- an instance variable (ivar)
//! - [`Objc1InstanceVariableList`] -- a list of instance variables
//! - [`Objc1Protocol`] -- a protocol definition
//! - [`Objc1ProtocolList`] -- a list of protocols
//! - [`Objc1ProtocolMethod`] -- a method in a protocol
//! - [`Objc1ProtocolMethodList`] -- a list of protocol methods
//! - [`Objc1MetaClass`] -- a metaclass definition
//! - [`Objc1TypeMetadata`] -- the top-level metadata parser

use super::{ObjcMethod, ObjcMethodList, ObjcMethodType, ObjcState, ObjcTypeMetadataStructure};

// ============================================================================
// Objc1Constants
// ============================================================================

/// Constants and section names for Objective-C 1.x metadata.
///
/// Corresponds to Java's `Objc1Constants`.
pub struct Objc1Constants;

impl Objc1Constants {
    /// The Objective-C namespace.
    pub const NAMESPACE: &'static str = "objc";

    // Section names for ObjC1 metadata
    /// Module info section.
    pub const SECTION_MODULE_INFO: &'static str = "__module_info";
    /// Symbol table section.
    pub const SECTION_SYMBOLS: &'static str = "__symbols";
    /// Category section.
    pub const SECTION_CATEGORY: &'static str = "__category";
    /// Class section.
    pub const SECTION_CLASS: &'static str = "__class";
    /// Instance variable section.
    pub const SECTION_INSTANCE_VARS: &'static str = "__instance_vars";
    /// Protocol section.
    pub const SECTION_PROTOCOL: &'static str = "__protocol";
    /// Method section.
    pub const SECTION_METHOD: &'static str = "__method";
    /// Class names section.
    pub const SECTION_CLASS_NAMES: &'static str = "__class_names";
    /// Meta class section.
    pub const SECTION_META_CLASS: &'static str = "__meta_class";
    /// Protocol method types section.
    pub const SECTION_CLS_METH: &'static str = "__cls_meth";
    /// Instance method types section.
    pub const SECTION_INST_METH: &'static str = "__inst_meth";

    // Absolute symbols
    /// Absolute symbol binding the runtime page (RTP) version of objc_msgSend.
    pub const OBJ_MSGSEND_RTP: u64 = 0xfffeff00;
    /// Absolute symbol binding the RTP version of objc_msgSend_Exit.
    pub const OBJ_MSGSEND_RTP_EXIT: u64 = 0xfffeff00 + 0x100;

    /// The Objective-C segment name.
    pub const OBJC_SEGMENT: &'static str = "__OBJC";

    /// Get all valid Objective-C section names.
    pub fn section_names() -> Vec<&'static str> {
        vec![
            Self::SECTION_MODULE_INFO,
            Self::SECTION_SYMBOLS,
            Self::SECTION_CATEGORY,
            Self::SECTION_CLASS,
            Self::SECTION_INSTANCE_VARS,
            Self::SECTION_PROTOCOL,
            Self::SECTION_METHOD,
            Self::SECTION_CLASS_NAMES,
            Self::SECTION_META_CLASS,
            Self::SECTION_CLS_METH,
            Self::SECTION_INST_METH,
        ]
    }

    /// Check if a section name is a valid ObjC1 section.
    pub fn is_objc_section(name: &str) -> bool {
        Self::section_names().contains(&name)
    }

    /// Check if a program likely contains Objective-C 1.x metadata.
    ///
    /// Checks for the presence of the `__OBJC` segment.
    pub fn is_objectivec(segment_names: &[String]) -> bool {
        segment_names
            .iter()
            .any(|s| s == Self::OBJC_SEGMENT || s == "__objc")
    }
}

// ============================================================================
// Objc1Module
// ============================================================================

/// An Objective-C 1.x module (image).
///
/// Each module contains a symbol table that in turn holds class and
/// category definitions.  Corresponds to Java's `Objc1Module`.
///
/// The structure in the binary is:
/// ```text
/// struct objc_module {
///     uint32_t version;
///     uint32_t size;
///     char    *name;      // pointer to module name
///     Symtab  *symtab;    // pointer to symbol table
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Objc1Module {
    /// Version of the module structure.
    pub version: u32,
    /// Size of the module structure.
    pub size: u32,
    /// The module (image) name.
    pub name: String,
    /// The symbol table within this module.
    pub symbol_table: Option<Box<Objc1SymbolTable>>,
    /// The base address of this structure.
    pub base: u64,
}

impl Objc1Module {
    /// Create a new module by parsing from a data buffer.
    ///
    /// `data` is the raw binary data, `offset` is the start of the module
    /// structure, and `state` provides pointer size info.
    pub fn parse(data: &[u8], offset: usize, state: &ObjcState) -> Option<Self> {
        if offset + 16 > data.len() {
            return None;
        }

        let version = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        // Read name pointer
        let name_addr = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]) as usize;

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("module_{}", offset));

        // Read symtab pointer
        let symtab_addr = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]) as usize;

        let symbol_table = Objc1SymbolTable::parse(data, symtab_addr, state)
            .map(Box::new);

        Some(Self {
            version,
            size,
            name,
            symbol_table,
            base: offset as u64,
        })
    }

    /// Get the module name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the symbol table.
    pub fn symbol_table(&self) -> Option<&Objc1SymbolTable> {
        self.symbol_table.as_deref()
    }
}

// ============================================================================
// Objc1SymbolTable
// ============================================================================

/// The Objective-C 1.x symbol table within a module.
///
/// Contains lists of classes and categories.
///
/// The structure in the binary is:
/// ```text
/// struct objc_symtab {
///     int32_t  sel_ref_cnt;
///     int32_t  refs;
///     int16_t  cls_def_cnt;
///     int16_t  cat_def_cnt;
///     // followed by cls_def_cnt class pointers and cat_def_cnt category pointers
/// };
/// ```
///
/// Corresponds to Java's `Objc1SymbolTable`.
#[derive(Debug, Clone)]
pub struct Objc1SymbolTable {
    /// The name of this structure type.
    pub name: String,
    /// Number of selector references.
    pub sel_ref_cnt: i32,
    /// Reference pointer.
    pub refs: i32,
    /// Number of class definitions.
    pub cls_def_cnt: i16,
    /// Number of category definitions.
    pub cat_def_cnt: i16,
    /// The class definitions.
    pub classes: Vec<Objc1Class>,
    /// The category definitions.
    pub categories: Vec<Objc1Category>,
    /// The base address.
    pub base: u64,
}

impl Objc1SymbolTable {
    /// Structure name constant.
    pub const NAME: &'static str = "objc_symtab";

    /// Parse a symbol table from a data buffer.
    pub fn parse(data: &[u8], offset: usize, state: &ObjcState) -> Option<Self> {
        if offset + 12 > data.len() {
            return None;
        }

        let sel_ref_cnt = i32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let refs = i32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let cls_def_cnt = i16::from_le_bytes([data[offset + 8], data[offset + 9]]);
        let cat_def_cnt = i16::from_le_bytes([data[offset + 10], data[offset + 11]]);

        let mut pos = offset + 12;
        let mut classes = Vec::new();
        let mut categories = Vec::new();

        // Parse class definitions
        for _ in 0..cls_def_cnt {
            if let Some(class_addr) = super::ObjcUtils::read_index(data, pos, true) {
                let class_addr_usize = class_addr as usize;
                if let Some(class) = Objc1Class::parse(data, class_addr_usize, state) {
                    classes.push(class);
                }
            }
            pos += 4;
        }

        // Parse category definitions
        for _ in 0..cat_def_cnt {
            if let Some(cat_addr) = super::ObjcUtils::read_index(data, pos, true) {
                let cat_addr_usize = cat_addr as usize;
                if let Some(category) = Objc1Category::parse(data, cat_addr_usize, state) {
                    categories.push(category);
                }
            }
            pos += 4;
        }

        Some(Self {
            name: Self::NAME.to_string(),
            sel_ref_cnt,
            refs,
            cls_def_cnt,
            cat_def_cnt,
            classes,
            categories,
            base: offset as u64,
        })
    }

    /// Get the classes.
    pub fn classes(&self) -> &[Objc1Class] {
        &self.classes
    }

    /// Get the categories.
    pub fn categories(&self) -> &[Objc1Category] {
        &self.categories
    }
}

// ============================================================================
// Objc1Class
// ============================================================================

/// An Objective-C 1.x class definition.
///
/// The structure in the binary is:
/// ```text
/// struct objc_class {
///     Class  *isa;         // pointer to metaclass
///     Class  *super_class; // pointer to superclass
///     char   *name;        // class name
///     long    version;
///     long    info;
///     long    instance_size;
///     struct objc_ivar_list *ivars;
///     struct objc_method_list *methods;
///     struct objc_cache *cache;
///     struct objc_protocol_list *protocols;
///     // ... (more fields for non-fragile ABI)
/// };
/// ```
///
/// Corresponds to Java's `Objc1Class`.
#[derive(Debug, Clone)]
pub struct Objc1Class {
    /// Address of the metaclass.
    pub isa: u64,
    /// Address of the superclass.
    pub super_class: u64,
    /// The class name.
    pub name: String,
    /// Version.
    pub version: i32,
    /// Info flags.
    pub info: i32,
    /// Instance size.
    pub instance_size: i32,
    /// Instance variable list.
    pub instance_variables: Vec<Objc1InstanceVariable>,
    /// Instance methods.
    pub instance_methods: ObjcMethodList,
    /// Class methods.
    pub class_methods: ObjcMethodList,
    /// Protocols.
    pub protocols: Vec<Objc1Protocol>,
    /// The base address.
    pub base: u64,
    /// Whether this is actually a metaclass.
    pub is_meta: bool,
}

impl Objc1Class {
    /// Parse a class from a data buffer.
    pub fn parse(data: &[u8], offset: usize, state: &ObjcState) -> Option<Self> {
        if offset + 24 > data.len() {
            return None;
        }

        let isa = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64;
        let super_class = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as u64;

        let name_addr = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]) as usize;

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("class_{}", offset));

        let version = i32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        let info = i32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]);
        let instance_size = i32::from_le_bytes([
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]);

        Some(Self {
            isa,
            super_class,
            name,
            version,
            info,
            instance_size,
            instance_variables: Vec::new(),
            instance_methods: ObjcMethodList::new(offset as u64, "inst_method_list"),
            class_methods: ObjcMethodList::new(offset as u64, "class_method_list"),
            protocols: Vec::new(),
            base: offset as u64,
            is_meta: false,
        })
    }

    /// Get the class name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Whether this is a metaclass.
    pub fn is_meta_class(&self) -> bool {
        self.is_meta
    }

    /// Get the superclass address.
    pub fn super_class(&self) -> u64 {
        self.super_class
    }

    /// Get the metaclass address.
    pub fn isa(&self) -> u64 {
        self.isa
    }
}

// ============================================================================
// Objc1Category
// ============================================================================

/// An Objective-C 1.x category definition.
///
/// The structure in the binary is:
/// ```text
/// struct objc_category {
///     char *category_name;
///     char *class_name;
///     struct objc_method_list *instance_methods;
///     struct objc_method_list *class_methods;
///     struct objc_protocol_list *protocols;
/// };
/// ```
///
/// Corresponds to Java's `Objc1Category`.
#[derive(Debug, Clone)]
pub struct Objc1Category {
    /// The category name.
    pub category_name: String,
    /// The class name this category extends.
    pub class_name: String,
    /// Instance methods added by the category.
    pub instance_methods: ObjcMethodList,
    /// Class methods added by the category.
    pub class_methods: ObjcMethodList,
    /// Protocols adopted by the category.
    pub protocols: Vec<Objc1Protocol>,
    /// The base address.
    pub base: u64,
}

impl Objc1Category {
    /// Parse a category from a data buffer.
    pub fn parse(data: &[u8], offset: usize, _state: &ObjcState) -> Option<Self> {
        if offset + 8 > data.len() {
            return None;
        }

        let cat_name_addr = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        let cls_name_addr = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;

        let category_name = super::ObjcUtils::read_string_at(data, cat_name_addr)
            .unwrap_or_else(|| format!("category_{}", offset));
        let class_name = super::ObjcUtils::read_string_at(data, cls_name_addr)
            .unwrap_or_default();

        Some(Self {
            category_name,
            class_name,
            instance_methods: ObjcMethodList::new(offset as u64, "inst_method_list"),
            class_methods: ObjcMethodList::new(offset as u64, "class_method_list"),
            protocols: Vec::new(),
            base: offset as u64,
        })
    }

    /// Get the category name.
    pub fn get_name(&self) -> &str {
        &self.category_name
    }

    /// Get the class name this category extends.
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// The fully qualified category name (ClassName + CategoryName).
    pub fn full_name(&self) -> String {
        format!("{}({})", self.class_name, self.category_name)
    }
}

// ============================================================================
// Objc1Method
// ============================================================================

/// An Objective-C 1.x method.
///
/// The structure in the binary is:
/// ```text
/// struct objc_method {
///     SEL     method_name;
///     char   *method_types;
///     IMP     method_imp;
/// };
/// ```
///
/// Corresponds to Java's `Objc1Method`.
#[derive(Debug, Clone)]
pub struct Objc1Method {
    /// The base ObjcMethod fields.
    pub method: ObjcMethod,
}

impl Objc1Method {
    /// Parse a method from a data buffer.
    pub fn parse(
        data: &[u8],
        offset: usize,
        method_type: ObjcMethodType,
    ) -> Option<Self> {
        if offset + 12 > data.len() {
            return None;
        }

        let name_addr = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        let types_addr = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;
        let imp = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]) as u64;

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("method_{}", offset));
        let types = super::ObjcUtils::read_string_at(data, types_addr)
            .unwrap_or_default();

        Some(Self {
            method: ObjcMethod::new(name, types, imp, method_type, offset as u64),
        })
    }

    /// Get the method name.
    pub fn get_name(&self) -> &str {
        &self.method.name
    }

    /// Get the type encoding.
    pub fn get_types(&self) -> &str {
        &self.method.types
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
// Objc1MethodList
// ============================================================================

/// A list of Objective-C 1.x methods.
///
/// Corresponds to Java's `Objc1MethodList`.
#[derive(Debug, Clone)]
pub struct Objc1MethodList {
    /// The methods.
    pub methods: Vec<Objc1Method>,
    /// The base address.
    pub base: u64,
    /// Whether the list is obsolete (legacy flag).
    pub is_obsolete: bool,
    /// Method count from the binary.
    pub method_count: i32,
}

impl Objc1MethodList {
    /// The structure name.
    pub const NAME: &'static str = "objc_method_list";

    /// Parse a method list from a data buffer.
    pub fn parse(
        data: &[u8],
        offset: usize,
        method_type: ObjcMethodType,
    ) -> Option<Self> {
        if offset + 8 > data.len() {
            return None;
        }

        // First word is "obsolete" pointer (skip)
        let _obsolete = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        let method_count = i32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        let mut methods = Vec::new();
        let mut pos = offset + 8;

        for _ in 0..method_count {
            if let Some(method) = Objc1Method::parse(data, pos, method_type) {
                methods.push(method);
            }
            pos += 12; // 3 pointers * 4 bytes each
        }

        Some(Self {
            methods,
            base: offset as u64,
            is_obsolete: _obsolete != 0,
            method_count,
        })
    }

    /// Get the methods.
    pub fn methods(&self) -> &[Objc1Method] {
        &self.methods
    }

    /// Get the method count.
    pub fn count(&self) -> usize {
        self.methods.len()
    }
}

// ============================================================================
// Objc1InstanceVariable
// ============================================================================

/// An Objective-C 1.x instance variable (ivar).
///
/// The structure in the binary is:
/// ```text
/// struct objc_ivar {
///     int32_t offset;
///     char   *name;
///     char   *type;
///     int32_t alignment;
///     int32_t size;
/// };
/// ```
///
/// Corresponds to Java's `Objc1InstanceVariable`.
#[derive(Debug, Clone)]
pub struct Objc1InstanceVariable {
    /// Offset of the ivar within the object.
    pub offset: i32,
    /// The ivar name.
    pub name: String,
    /// The type encoding.
    pub type_encoding: String,
    /// Alignment.
    pub alignment: i32,
    /// Size.
    pub size: i32,
    /// Base address.
    pub base: u64,
}

impl Objc1InstanceVariable {
    /// Parse an instance variable from a data buffer.
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + 20 > data.len() {
            return None;
        }

        let ivar_offset = i32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let name_addr = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;
        let type_addr = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]) as usize;
        let alignment = i32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        let size = i32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]);

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("ivar_{}", offset));
        let type_encoding = super::ObjcUtils::read_string_at(data, type_addr)
            .unwrap_or_default();

        Some(Self {
            offset: ivar_offset,
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
// Objc1InstanceVariableList
// ============================================================================

/// A list of Objective-C 1.x instance variables.
///
/// Corresponds to Java's `Objc1InstanceVariableList`.
#[derive(Debug, Clone)]
pub struct Objc1InstanceVariableList {
    /// Number of ivars.
    pub count: i32,
    /// The ivars.
    pub ivars: Vec<Objc1InstanceVariable>,
    /// Base address.
    pub base: u64,
}

impl Objc1InstanceVariableList {
    /// Parse an instance variable list from a data buffer.
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + 4 > data.len() {
            return None;
        }

        let count = i32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        let mut ivars = Vec::new();
        let mut pos = offset + 4;

        for _ in 0..count {
            if let Some(ivar) = Objc1InstanceVariable::parse(data, pos) {
                ivars.push(ivar);
            }
            pos += 20; // 5 fields * 4 bytes each
        }

        Some(Self {
            count,
            ivars,
            base: offset as u64,
        })
    }

    /// Get the ivars.
    pub fn ivars(&self) -> &[Objc1InstanceVariable] {
        &self.ivars
    }
}

// ============================================================================
// Objc1Protocol
// ============================================================================

/// An Objective-C 1.x protocol definition.
///
/// Corresponds to Java's `Objc1Protocol`.
#[derive(Debug, Clone)]
pub struct Objc1Protocol {
    /// The protocol name.
    pub name: String,
    /// Protocols this protocol conforms to.
    pub protocols: Vec<String>,
    /// Instance methods.
    pub instance_methods: ObjcMethodList,
    /// Class methods.
    pub class_methods: ObjcMethodList,
    /// Base address.
    pub base: u64,
}

impl Objc1Protocol {
    /// Parse a protocol from a data buffer.
    pub fn parse(data: &[u8], offset: usize, _state: &ObjcState) -> Option<Self> {
        if offset + 4 > data.len() {
            return None;
        }

        let name_addr = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;

        let name = super::ObjcUtils::read_string_at(data, name_addr)
            .unwrap_or_else(|| format!("protocol_{}", offset));

        Some(Self {
            name,
            protocols: Vec::new(),
            instance_methods: ObjcMethodList::new(offset as u64, "inst_method_list"),
            class_methods: ObjcMethodList::new(offset as u64, "class_method_list"),
            base: offset as u64,
        })
    }

    /// Get the protocol name.
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// Objc1ProtocolList
// ============================================================================

/// A list of Objective-C 1.x protocols.
///
/// Corresponds to Java's `Objc1ProtocolList`.
#[derive(Debug, Clone)]
pub struct Objc1ProtocolList {
    /// The protocols.
    pub protocols: Vec<Objc1Protocol>,
    /// Base address.
    pub base: u64,
}

impl Objc1ProtocolList {
    /// Create a new empty protocol list.
    pub fn new(base: u64) -> Self {
        Self {
            protocols: Vec::new(),
            base,
        }
    }

    /// Get the protocols.
    pub fn protocols(&self) -> &[Objc1Protocol] {
        &self.protocols
    }

    /// Get the count.
    pub fn count(&self) -> usize {
        self.protocols.len()
    }
}

// ============================================================================
// Objc1ProtocolMethod
// ============================================================================

/// A method declared in an Objective-C 1.x protocol.
///
/// Corresponds to Java's `Objc1ProtocolMethod`.
#[derive(Debug, Clone)]
pub struct Objc1ProtocolMethod {
    /// The method name.
    pub name: String,
    /// The type encoding.
    pub types: String,
    /// Whether this method is required (vs. optional).
    pub is_required: bool,
}

impl Objc1ProtocolMethod {
    /// Create a new protocol method.
    pub fn new(name: String, types: String, is_required: bool) -> Self {
        Self {
            name,
            types,
            is_required,
        }
    }
}

// ============================================================================
// Objc1ProtocolMethodList
// ============================================================================

/// A list of Objective-C 1.x protocol methods.
///
/// Corresponds to Java's `Objc1ProtocolMethodList`.
#[derive(Debug, Clone)]
pub struct Objc1ProtocolMethodList {
    /// The methods.
    pub methods: Vec<Objc1ProtocolMethod>,
    /// Base address.
    pub base: u64,
}

impl Objc1ProtocolMethodList {
    /// Create a new empty list.
    pub fn new(base: u64) -> Self {
        Self {
            methods: Vec::new(),
            base,
        }
    }

    /// Add a method.
    pub fn add(&mut self, method: Objc1ProtocolMethod) {
        self.methods.push(method);
    }

    /// Get the methods.
    pub fn methods(&self) -> &[Objc1ProtocolMethod] {
        &self.methods
    }
}

// ============================================================================
// Objc1MetaClass
// ============================================================================

/// An Objective-C 1.x metaclass.
///
/// A metaclass is a class's class object. It holds the class methods.
///
/// Corresponds to Java's `Objc1MetaClass`.
#[derive(Debug, Clone)]
pub struct Objc1MetaClass {
    /// The underlying class data.
    pub class: Objc1Class,
}

impl Objc1MetaClass {
    /// Create a metaclass from a parsed class.
    pub fn from_class(mut class: Objc1Class) -> Self {
        class.is_meta = true;
        Self { class }
    }

    /// Get the metaclass name.
    pub fn get_name(&self) -> &str {
        &self.class.name
    }
}

// ============================================================================
// Objc1TypeMetadata
// ============================================================================

/// Top-level parser for Objective-C 1.x type metadata.
///
/// Parses all ObjC1 metadata structures from a Mach-O binary's
/// `__OBJC` segment.
///
/// Corresponds to Java's `Objc1TypeMetadata`.
#[derive(Debug)]
pub struct Objc1TypeMetadata {
    /// The parsing state.
    pub state: ObjcState,
    /// Parsed modules.
    pub modules: Vec<Objc1Module>,
    /// All classes found.
    pub classes: Vec<Objc1Class>,
    /// All categories found.
    pub categories: Vec<Objc1Category>,
    /// All protocols found.
    pub protocols: Vec<Objc1Protocol>,
    /// Log messages.
    pub log_messages: Vec<String>,
}

impl Objc1TypeMetadata {
    /// Category path for ObjC1 data types.
    pub const CATEGORY_PATH: &'static str = "ghidra/app/util/bin/format/objc/objc1";

    /// Create a new ObjC1 type metadata parser.
    pub fn new(is_32bit: bool) -> Self {
        let state = ObjcState::new(if is_32bit { 4 } else { 8 }, Self::CATEGORY_PATH);
        Self {
            state,
            modules: Vec::new(),
            classes: Vec::new(),
            categories: Vec::new(),
            protocols: Vec::new(),
            log_messages: Vec::new(),
        }
    }

    /// Parse metadata from raw binary data.
    ///
    /// `data` should be the contents of the `__OBJC` segment.
    pub fn parse(&mut self, data: &[u8]) {
        // Parse all module_info structures found in the data
        let mut offset = 0;
        while offset + 16 <= data.len() {
            if let Some(module) = Objc1Module::parse(data, offset, &self.state) {
                // Collect classes and categories from the module's symbol table
                if let Some(ref symtab) = module.symbol_table {
                    for class in &symtab.classes {
                        self.classes.push(class.clone());
                    }
                    for cat in &symtab.categories {
                        self.categories.push(cat.clone());
                    }
                }
                self.modules.push(module);
            }
            offset += 16;
        }
    }

    /// Get parsed modules.
    pub fn modules(&self) -> &[Objc1Module] {
        &self.modules
    }

    /// Get all classes.
    pub fn classes(&self) -> &[Objc1Class] {
        &self.classes
    }

    /// Get all categories.
    pub fn categories(&self) -> &[Objc1Category] {
        &self.categories
    }

    /// Get all protocols.
    pub fn protocols(&self) -> &[Objc1Protocol] {
        &self.protocols
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_objc1_constants() {
        assert_eq!(Objc1Constants::NAMESPACE, "objc");
        assert_eq!(Objc1Constants::OBJ_MSGSEND_RTP, 0xfffeff00);
        assert!(Objc1Constants::section_names().len() > 5);
        assert!(Objc1Constants::is_objc_section("__module_info"));
        assert!(!Objc1Constants::is_objc_section("__text"));
    }

    #[test]
    fn test_objc1_is_objectivec() {
        let segments = vec!["__TEXT".to_string(), "__OBJC".to_string()];
        assert!(Objc1Constants::is_objectivec(&segments));

        let no_objc = vec!["__TEXT".to_string(), "__DATA".to_string()];
        assert!(!Objc1Constants::is_objectivec(&no_objc));
    }

    #[test]
    fn test_objc1_class_parse() {
        // Build a minimal ObjC1 class structure in a byte buffer
        let mut data = vec![0u8; 256];

        // Name string at offset 200
        let name = b"NSString\0";
        data[200..200 + name.len()].copy_from_slice(name);

        // Class at offset 0
        // isa = 0
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        // super_class = 0
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        // name pointer = 200
        data[8..12].copy_from_slice(&200u32.to_le_bytes());
        // version = 0
        data[12..16].copy_from_slice(&0i32.to_le_bytes());
        // info = 0
        data[16..20].copy_from_slice(&0i32.to_le_bytes());
        // instance_size = 8
        data[20..24].copy_from_slice(&8i32.to_le_bytes());

        let state = ObjcState::new_32bit("test");
        let class = Objc1Class::parse(&data, 0, &state);
        assert!(class.is_some());
        let class = class.unwrap();
        assert_eq!(class.get_name(), "NSString");
        assert_eq!(class.instance_size, 8);
        assert!(!class.is_meta_class());
    }

    #[test]
    fn test_objc1_category_parse() {
        let mut data = vec![0u8; 256];

        // Category name at offset 100
        let cat_name = b"MyCategory\0";
        data[100..100 + cat_name.len()].copy_from_slice(cat_name);

        // Class name at offset 120
        let cls_name = b"MyClass\0";
        data[120..120 + cls_name.len()].copy_from_slice(cls_name);

        // Category at offset 0
        data[0..4].copy_from_slice(&100u32.to_le_bytes()); // category_name pointer
        data[4..8].copy_from_slice(&120u32.to_le_bytes()); // class_name pointer

        let state = ObjcState::new_32bit("test");
        let cat = Objc1Category::parse(&data, 0, &state);
        assert!(cat.is_some());
        let cat = cat.unwrap();
        assert_eq!(cat.get_name(), "MyCategory");
        assert_eq!(cat.class_name(), "MyClass");
        assert_eq!(cat.full_name(), "MyClass(MyCategory)");
    }

    #[test]
    fn test_objc1_method_parse() {
        let mut data = vec![0u8; 256];

        // Method name at offset 100
        let name = b"initWithFrame:\0";
        data[100..100 + name.len()].copy_from_slice(name);

        // Types at offset 120
        let types = b"v16@0:8\0";
        data[120..120 + types.len()].copy_from_slice(types);

        // Method at offset 0
        data[0..4].copy_from_slice(&100u32.to_le_bytes()); // name pointer
        data[4..8].copy_from_slice(&120u32.to_le_bytes()); // types pointer
        data[8..12].copy_from_slice(&0x2000u32.to_le_bytes()); // implementation

        let method = Objc1Method::parse(&data, 0, ObjcMethodType::Instance);
        assert!(method.is_some());
        let method = method.unwrap();
        assert_eq!(method.get_name(), "initWithFrame:");
        assert_eq!(method.get_types(), "v16@0:8");
        assert_eq!(method.get_implementation(), 0x2000);
    }

    #[test]
    fn test_objc1_method_list_parse() {
        let mut data = vec![0u8; 512];

        // Method list at offset 0
        // obsolete = 0
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        // method_count = 2
        data[4..8].copy_from_slice(&2i32.to_le_bytes());

        // First method at offset 8: name at 200, types at 220, imp = 0x1000
        let name1 = b"init\0";
        data[200..200 + name1.len()].copy_from_slice(name1);
        let types1 = b"v8@0:4\0";
        data[220..220 + types1.len()].copy_from_slice(types1);
        data[8..12].copy_from_slice(&200u32.to_le_bytes());
        data[12..16].copy_from_slice(&220u32.to_le_bytes());
        data[16..20].copy_from_slice(&0x1000u32.to_le_bytes());

        // Second method at offset 20: name at 240, types at 260, imp = 0x1040
        let name2 = b"dealloc\0";
        data[240..240 + name2.len()].copy_from_slice(name2);
        let types2 = b"v8@0:4\0";
        data[260..260 + types2.len()].copy_from_slice(types2);
        data[20..24].copy_from_slice(&240u32.to_le_bytes());
        data[24..28].copy_from_slice(&260u32.to_le_bytes());
        data[28..32].copy_from_slice(&0x1040u32.to_le_bytes());

        let list = Objc1MethodList::parse(&data, 0, ObjcMethodType::Instance);
        assert!(list.is_some());
        let list = list.unwrap();
        assert_eq!(list.count(), 2);
        assert_eq!(list.methods()[0].get_name(), "init");
        assert_eq!(list.methods()[1].get_name(), "dealloc");
    }

    #[test]
    fn test_objc1_instance_variable() {
        let mut data = vec![0u8; 256];

        // ivar at offset 0
        data[0..4].copy_from_slice(&8u32.to_le_bytes()); // offset
        let name = b"_name\0";
        data[100..100 + name.len()].copy_from_slice(name);
        data[4..8].copy_from_slice(&100u32.to_le_bytes()); // name pointer
        let types = b"@\0";
        data[120..120 + types.len()].copy_from_slice(types);
        data[8..12].copy_from_slice(&120u32.to_le_bytes()); // type pointer
        data[12..16].copy_from_slice(&2u32.to_le_bytes()); // alignment
        data[16..20].copy_from_slice(&4u32.to_le_bytes()); // size

        let ivar = Objc1InstanceVariable::parse(&data, 0);
        assert!(ivar.is_some());
        let ivar = ivar.unwrap();
        assert_eq!(ivar.get_name(), "_name");
        assert_eq!(ivar.offset, 8);
        assert_eq!(ivar.size, 4);
    }

    #[test]
    fn test_objc1_symbol_table_parse() {
        let mut data = vec![0u8; 512];

        // Symbol table at offset 0
        data[0..4].copy_from_slice(&0i32.to_le_bytes()); // sel_ref_cnt
        data[4..8].copy_from_slice(&0i32.to_le_bytes()); // refs
        data[8..10].copy_from_slice(&0i16.to_le_bytes()); // cls_def_cnt = 0
        data[10..12].copy_from_slice(&0i16.to_le_bytes()); // cat_def_cnt = 0

        let state = ObjcState::new_32bit("test");
        let symtab = Objc1SymbolTable::parse(&data, 0, &state);
        assert!(symtab.is_some());
        let symtab = symtab.unwrap();
        assert_eq!(symtab.cls_def_cnt, 0);
        assert_eq!(symtab.cat_def_cnt, 0);
        assert!(symtab.classes().is_empty());
        assert!(symtab.categories().is_empty());
    }

    #[test]
    fn test_objc1_protocol() {
        let mut data = vec![0u8; 256];
        let name = b"NSCopying\0";
        data[100..100 + name.len()].copy_from_slice(name);
        data[0..4].copy_from_slice(&100u32.to_le_bytes());

        let state = ObjcState::new_32bit("test");
        let proto = Objc1Protocol::parse(&data, 0, &state);
        assert!(proto.is_some());
        assert_eq!(proto.unwrap().get_name(), "NSCopying");
    }

    #[test]
    fn test_objc1_meta_class() {
        let mut data = vec![0u8; 64];
        let name = b"NSString\0";
        data[40..40 + name.len()].copy_from_slice(name);
        data[8..12].copy_from_slice(&40u32.to_le_bytes()); // name pointer
        data[20..24].copy_from_slice(&8i32.to_le_bytes()); // instance_size

        let state = ObjcState::new_32bit("test");
        let class = Objc1Class::parse(&data, 0, &state).unwrap();
        let meta = Objc1MetaClass::from_class(class);
        assert_eq!(meta.get_name(), "NSString");
        assert!(meta.class.is_meta);
    }

    #[test]
    fn test_objc1_type_metadata() {
        let mut meta = Objc1TypeMetadata::new(true);
        assert!(meta.modules().is_empty());
        assert!(meta.classes().is_empty());
        assert!(meta.categories().is_empty());
        // Parse empty data
        meta.parse(&[]);
        assert!(meta.modules().is_empty());
    }

    #[test]
    fn test_objc1_parse_too_short() {
        let data = [0u8; 4];
        assert!(Objc1Class::parse(&data, 0, &ObjcState::new_32bit("t")).is_none());
        assert!(Objc1Category::parse(&data, 0, &ObjcState::new_32bit("t")).is_none());
        assert!(Objc1Method::parse(&data, 0, ObjcMethodType::Instance).is_none());
        assert!(Objc1Module::parse(&data, 0, &ObjcState::new_32bit("t")).is_none());
    }
}
