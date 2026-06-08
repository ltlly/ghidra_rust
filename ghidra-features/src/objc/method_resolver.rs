//! Objective-C method resolution and metadata application.
//!
//! Ported from Ghidra's `ObjcUtils.createMethods`, `ObjcUtils.fixupReferences`,
//! and `Objc2TypeMetadata.applyTo` Java methods.
//!
//! This module provides the logic for:
//! - Resolving method addresses from ObjC metadata
//! - Applying method signatures to function listings
//! - Creating symbols and namespaces for ObjC classes, categories, and protocols
//! - Fixing up THUMB references in ARM binaries
//! - Setting memory blocks as read-only

use std::collections::{HashMap, HashSet};

// ============================================================================
// MethodResolutionState -- tracks method resolution progress
// ============================================================================

/// State for Objective-C method resolution.
///
/// Corresponds to the state tracked by `ObjcUtils.createMethods` and related methods.
#[derive(Debug)]
pub struct MethodResolutionState {
    /// Map of method addresses to their metadata.
    pub method_map: HashMap<u64, ResolvedMethod>,
    /// Addresses that have been processed (applied to the program).
    pub applied_addresses: HashSet<u64>,
    /// THUMB code locations (ARM-specific).
    pub thumb_code_locations: HashSet<u64>,
    /// Map of class indices to class metadata.
    pub class_index_map: HashMap<u64, ClassInfo>,
    /// Map of ivar addresses to ivar metadata.
    pub variable_map: HashMap<u64, ResolvedInstanceVariable>,
    /// Whether to process ObjC1 metadata.
    pub process_objc1: bool,
    /// Whether to process ObjC2 metadata.
    pub process_objc2: bool,
    /// Log messages collected during resolution.
    pub log_messages: Vec<String>,
}

/// A resolved Objective-C method with all metadata needed for symbol creation.
#[derive(Debug, Clone)]
pub struct ResolvedMethod {
    /// The method name (selector).
    pub name: String,
    /// The type encoding string.
    pub types: String,
    /// The implementation address.
    pub implementation: u64,
    /// Whether this is an instance or class method.
    pub is_class_method: bool,
    /// The class name this method belongs to.
    pub class_name: String,
    /// The method's fully qualified symbol name.
    pub symbol_name: String,
}

/// Information about an Objective-C class for symbol creation.
#[derive(Debug, Clone)]
pub struct ClassInfo {
    /// The class name.
    pub name: String,
    /// The address of the class structure.
    pub address: u64,
    /// The superclass name (if known).
    pub super_class_name: Option<String>,
    /// Whether this is a metaclass.
    pub is_meta: bool,
    /// Instance method selectors.
    pub instance_methods: Vec<String>,
    /// Class method selectors.
    pub class_methods: Vec<String>,
    /// Instance variable names.
    pub ivars: Vec<String>,
    /// Protocol names.
    pub protocols: Vec<String>,
}

/// A resolved instance variable.
#[derive(Debug, Clone)]
pub struct ResolvedInstanceVariable {
    /// The ivar name.
    pub name: String,
    /// The type encoding.
    pub type_encoding: String,
    /// The ivar size in bytes.
    pub size: u32,
    /// The ivar address.
    pub address: u64,
    /// The class name this ivar belongs to.
    pub class_name: String,
}

/// Metadata about a protocol for symbol creation.
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    /// The protocol name.
    pub name: String,
    /// The address of the protocol structure.
    pub address: u64,
    /// Protocols this protocol conforms to.
    pub conforms_to: Vec<String>,
    /// Instance method names.
    pub instance_methods: Vec<String>,
    /// Class method names.
    pub class_methods: Vec<String>,
    /// Optional instance method names.
    pub optional_instance_methods: Vec<String>,
    /// Optional class method names.
    pub optional_class_methods: Vec<String>,
}

/// Metadata about a category for symbol creation.
#[derive(Debug, Clone)]
pub struct CategoryInfo {
    /// The category name.
    pub name: String,
    /// The class name this category extends.
    pub class_name: String,
    /// The address of the category structure.
    pub address: u64,
    /// Instance method names.
    pub instance_methods: Vec<String>,
    /// Class method names.
    pub class_methods: Vec<String>,
    /// Protocol names.
    pub protocols: Vec<String>,
}

impl MethodResolutionState {
    /// Create a new empty method resolution state.
    pub fn new() -> Self {
        Self {
            method_map: HashMap::new(),
            applied_addresses: HashSet::new(),
            thumb_code_locations: HashSet::new(),
            class_index_map: HashMap::new(),
            variable_map: HashMap::new(),
            process_objc1: true,
            process_objc2: true,
            log_messages: Vec::new(),
        }
    }

    /// Add a method to the resolution state.
    pub fn add_method(&mut self, address: u64, method: ResolvedMethod) {
        self.method_map.insert(address, method);
    }

    /// Add a class to the resolution state.
    pub fn add_class(&mut self, index: u64, class: ClassInfo) {
        self.class_index_map.insert(index, class);
    }

    /// Add an instance variable to the resolution state.
    pub fn add_variable(&mut self, address: u64, variable: ResolvedInstanceVariable) {
        self.variable_map.insert(address, variable);
    }

    /// Mark an address as THUMB code.
    pub fn mark_thumb(&mut self, address: u64) {
        self.thumb_code_locations.insert(address);
    }

    /// Check if an address is THUMB code.
    pub fn is_thumb(&self, address: u64) -> bool {
        self.thumb_code_locations.contains(&address)
    }

    /// Log a message.
    pub fn log(&mut self, message: &str) {
        self.log_messages.push(message.to_string());
    }

    /// Get the number of methods to process.
    pub fn method_count(&self) -> usize {
        self.method_map.len()
    }

    /// Get the number of classes.
    pub fn class_count(&self) -> usize {
        self.class_index_map.len()
    }

    /// Get the number of instance variables.
    pub fn variable_count(&self) -> usize {
        self.variable_map.len()
    }

    /// Close/clear the state.
    pub fn close(&mut self) {
        self.applied_addresses.clear();
        self.thumb_code_locations.clear();
    }
}

impl Default for MethodResolutionState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MethodResolver -- applies ObjC metadata
// ============================================================================

/// Resolves and applies Objective-C metadata to a program.
///
/// This encapsulates the logic from `ObjcUtils.createMethods`,
/// `ObjcUtils.fixupReferences`, and `Objc2TypeMetadata.applyTo`.
pub struct MethodResolver;

impl MethodResolver {
    /// The prefix for Objective-C class symbols.
    pub const OBJC_CLASS_SYMBOL_PREFIX: &'static str = "_OBJC_CLASS_$_";
    /// The prefix for Objective-C metaclass symbols.
    pub const OBJC_META_CLASS_SYMBOL_PREFIX: &'static str = "_OBJC_METACLASS_$_";
    /// The prefix for Objective-C category symbols.
    pub const OBJC_CATEGORY_SYMBOL_PREFIX: &'static str = "_OBJC_$_CATEGORY_";
    /// The Objective-C namespace.
    pub const NAMESPACE: &'static str = "objc";

    /// Check if a symbol name is a known `objc_msgSend` variant.
    ///
    /// Corresponds to Java's `ObjcMessageAnalyzer.is_msg_send` logic.
    pub fn is_msg_send(symbol_name: &str) -> bool {
        const VARIANTS: &[&str] = &[
            "_objc_msgSend",
            "_objc_msgSend_stret",
            "_objc_msgSendSuper",
            "_objc_msgSendSuper_stret",
            "_objc_msgSendSuper2",
            "_objc_msgSendSuper2_stret",
            "_objc_msgSend_fixup",
            "_objc_msgSend_uncached",
            "_objc_msg_lookup",
            "_objc_msg_lookup_super",
        ];
        VARIANTS.iter().any(|&v| {
            symbol_name == v
                || symbol_name.ends_with(v)
                || symbol_name == &v[1..] // without leading underscore
        })
    }

    /// Strip Objective-C class prefixes from a name.
    ///
    /// Removes `_OBJC_CLASS_$_` or `_OBJC_METACLASS_$_` prefixes.
    pub fn strip_class_prefix(name: &str) -> &str {
        if let Some(rest) = name.strip_prefix(Self::OBJC_CLASS_SYMBOL_PREFIX) {
            rest
        } else if let Some(rest) = name.strip_prefix(Self::OBJC_META_CLASS_SYMBOL_PREFIX) {
            rest
        } else {
            name
        }
    }

    /// Format a class name for display (with metaclass indicator).
    pub fn format_class_name(name: &str, is_meta: bool) -> String {
        if is_meta {
            format!("+{}", name)
        } else {
            name.to_string()
        }
    }

    /// Format a method for display.
    pub fn format_method(is_class_method: bool, class_name: &str, selector: &str) -> String {
        let prefix = if is_class_method { "-" } else { "+" };
        format!("{}[{} {}]", prefix, class_name, selector)
    }

    /// Create the namespace path for a protocol.
    pub fn protocol_namespace_path(protocol_name: &str) -> String {
        format!("{}::Protocols::{}", Self::NAMESPACE, protocol_name)
    }

    /// Create the namespace path for a category.
    pub fn category_namespace_path(category_name: &str) -> String {
        format!("{}::Categories::{}", Self::NAMESPACE, category_name)
    }

    /// Create the namespace path for a class.
    pub fn class_namespace_path(class_name: &str) -> String {
        format!("{}::{}", Self::NAMESPACE, class_name)
    }

    /// Build the symbol name for a class.
    pub fn class_symbol_name(class_name: &str) -> String {
        format!("{}{}", Self::OBJC_CLASS_SYMBOL_PREFIX, class_name)
    }

    /// Build the symbol name for a metaclass.
    pub fn metaclass_symbol_name(class_name: &str) -> String {
        format!("{}{}", Self::OBJC_META_CLASS_SYMBOL_PREFIX, class_name)
    }

    /// Build the symbol name for a category.
    pub fn category_symbol_name(class_name: &str, category_name: &str) -> String {
        format!(
            "{}{}_{}",
            Self::OBJC_CATEGORY_SYMBOL_PREFIX, class_name, category_name
        )
    }

    /// Compute the THUMB-adjusted address for ARM binaries.
    ///
    /// THUMB code has bit 0 set; this returns the actual code address.
    pub fn thumb_adjusted_address(address: u64, is_thumb: bool) -> u64 {
        if is_thumb && address % 2 != 0 {
            address - 1
        } else {
            address
        }
    }

    /// Check if an address is in an executable section (for THUMB detection on ARM).
    ///
    /// In a real implementation, this would check the program's memory blocks.
    pub fn is_likely_thumb(address: u64, processor: &str) -> bool {
        if processor != "ARM" {
            return false;
        }
        // THUMB code typically has bit 0 set in function pointers
        address % 2 != 0
    }

    /// Generate a list of ObjC2 section names that should be set read-only.
    pub fn readonly_sections() -> Vec<&'static str> {
        vec![
            "__objc_data",
            "__objc_classrefs",
            "__objc_msgrefs",
            "__objc_selrefs",
            "__objc_superrefs",
            "__objc_protorefs",
        ]
    }

    /// Generate a list of all ObjC2 section names.
    pub fn all_objc2_sections() -> Vec<&'static str> {
        vec![
            "__objc_catlist",
            "__objc_classlist",
            "__objc_classrefs",
            "__objc_const",
            "__objc_data",
            "__objc_imageinfo",
            "__objc_msgrefs",
            "__objc_nlclslist",
            "__objc_nlcatlist",
            "__objc_protolist",
            "__objc_protorefs",
            "__objc_selrefs",
            "__objc_stubs",
            "__objc_superrefs",
        ]
    }

    /// Check if a section name is an ObjC2 section.
    pub fn is_objc2_section(name: &str) -> bool {
        name.starts_with("__objc_") || name == "__data"
    }

    /// Check if a section name is an ObjC1 section.
    pub fn is_objc1_section(name: &str) -> bool {
        matches!(
            name,
            "__module_info"
                | "__symbols"
                | "__category"
                | "__class"
                | "__instance_vars"
                | "__protocol"
                | "__method"
                | "__class_names"
                | "__meta_class"
                | "__cls_meth"
                | "__inst_meth"
        )
    }

    /// Check if a segment name is ObjC-related.
    pub fn is_objc_segment(segment_name: &str) -> bool {
        matches!(
            segment_name,
            "__OBJC" | "__objc" | "__DATA" | "__DATA_CONST" | "__DATA_DIRTY"
        )
    }

    /// Check if a program is likely an Objective-C program based on section names.
    pub fn is_objc_program(section_names: &[&str]) -> bool {
        section_names
            .iter()
            .any(|s| s.starts_with("__objc_") || *s == "__OBJC" || *s == "__objc")
    }
}

// ============================================================================
// ReferenceFixup -- reference management utilities
// ============================================================================

/// Information about a reference that needs fixing.
#[derive(Debug, Clone)]
pub struct ReferenceFixup {
    /// The source address of the reference.
    pub from_address: u64,
    /// The target address of the reference.
    pub to_address: u64,
    /// Whether the target is THUMB code.
    pub is_thumb: bool,
    /// The reference type.
    pub ref_type: ReferenceType,
}

/// Types of references that can be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceType {
    /// A data pointer reference.
    Data,
    /// A code reference (call/jump).
    Code,
    /// A read reference.
    Read,
}

/// Utility for fixing up references in ObjC metadata sections.
pub struct ReferenceFixupUtils;

impl ReferenceFixupUtils {
    /// Determine if a reference should be deleted (points to NULL).
    pub fn should_delete_null(to_address: u64) -> bool {
        to_address == 0
    }

    /// Determine if a reference needs THUMB adjustment.
    ///
    /// THUMB references need to be adjusted so they don't point to offcut addresses.
    pub fn needs_thumb_fixup(to_address: u64, is_thumb: bool) -> bool {
        is_thumb && to_address % 2 != 0
    }

    /// Compute the fixed-up target address.
    pub fn fixup_address(to_address: u64, is_thumb: bool) -> u64 {
        if is_thumb && to_address % 2 != 0 {
            to_address - 1
        } else {
            to_address
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_resolution_state_new() {
        let state = MethodResolutionState::new();
        assert!(state.method_map.is_empty());
        assert!(state.applied_addresses.is_empty());
        assert!(state.thumb_code_locations.is_empty());
        assert!(state.class_index_map.is_empty());
        assert!(state.variable_map.is_empty());
        assert!(state.process_objc1);
        assert!(state.process_objc2);
    }

    #[test]
    fn test_method_resolution_state_add_method() {
        let mut state = MethodResolutionState::new();
        state.add_method(
            0x1000,
            ResolvedMethod {
                name: "init".into(),
                types: "v16@0:8".into(),
                implementation: 0x2000,
                is_class_method: false,
                class_name: "NSObject".into(),
                symbol_name: "+[NSObject init]".into(),
            },
        );
        assert_eq!(state.method_count(), 1);
        assert!(state.method_map.contains_key(&0x1000));
    }

    #[test]
    fn test_method_resolution_state_thumb() {
        let mut state = MethodResolutionState::new();
        assert!(!state.is_thumb(0x1000));
        state.mark_thumb(0x1000);
        assert!(state.is_thumb(0x1000));
    }

    #[test]
    fn test_method_resolution_state_class() {
        let mut state = MethodResolutionState::new();
        state.add_class(
            0x3000,
            ClassInfo {
                name: "UIView".into(),
                address: 0x3000,
                super_class_name: Some("UIResponder".into()),
                is_meta: false,
                instance_methods: vec!["init".into(), "dealloc".into()],
                class_methods: vec!["alloc".into()],
                ivars: vec!["_frame".into()],
                protocols: vec!["NSCoding".into()],
            },
        );
        assert_eq!(state.class_count(), 1);
        let class = state.class_index_map.get(&0x3000).unwrap();
        assert_eq!(class.name, "UIView");
        assert_eq!(class.super_class_name, Some("UIResponder".into()));
    }

    #[test]
    fn test_is_msg_send() {
        assert!(MethodResolver::is_msg_send("_objc_msgSend"));
        assert!(MethodResolver::is_msg_send("_objc_msgSend_stret"));
        assert!(MethodResolver::is_msg_send("_objc_msgSendSuper"));
        assert!(MethodResolver::is_msg_send("_objc_msgSendSuper2"));
        assert!(MethodResolver::is_msg_send("objc_msgSend"));
        assert!(!MethodResolver::is_msg_send("_printf"));
        assert!(!MethodResolver::is_msg_send(""));
    }

    #[test]
    fn test_strip_class_prefix() {
        assert_eq!(
            MethodResolver::strip_class_prefix("_OBJC_CLASS_$_NSString"),
            "NSString"
        );
        assert_eq!(
            MethodResolver::strip_class_prefix("_OBJC_METACLASS_$_NSString"),
            "NSString"
        );
        assert_eq!(
            MethodResolver::strip_class_prefix("plain_name"),
            "plain_name"
        );
    }

    #[test]
    fn test_format_class_name() {
        assert_eq!(MethodResolver::format_class_name("UIView", false), "UIView");
        assert_eq!(MethodResolver::format_class_name("UIView", true), "+UIView");
    }

    #[test]
    fn test_format_method() {
        assert_eq!(
            MethodResolver::format_method(false, "UIView", "initWithFrame:"),
            "+[UIView initWithFrame:]"
        );
        assert_eq!(
            MethodResolver::format_method(true, "UIView", "alloc"),
            "-[UIView alloc]"
        );
    }

    #[test]
    fn test_namespace_paths() {
        assert_eq!(
            MethodResolver::protocol_namespace_path("NSCoding"),
            "objc::Protocols::NSCoding"
        );
        assert_eq!(
            MethodResolver::category_namespace_path("MyCategory"),
            "objc::Categories::MyCategory"
        );
        assert_eq!(
            MethodResolver::class_namespace_path("UIView"),
            "objc::UIView"
        );
    }

    #[test]
    fn test_symbol_names() {
        assert_eq!(
            MethodResolver::class_symbol_name("NSString"),
            "_OBJC_CLASS_$_NSString"
        );
        assert_eq!(
            MethodResolver::metaclass_symbol_name("NSString"),
            "_OBJC_METACLASS_$_NSString"
        );
        assert_eq!(
            MethodResolver::category_symbol_name("NSObject", "MyCategory"),
            "_OBJC_$_CATEGORY_NSObject_MyCategory"
        );
    }

    #[test]
    fn test_thumb_adjusted_address() {
        assert_eq!(MethodResolver::thumb_adjusted_address(0x1001, true), 0x1000);
        assert_eq!(MethodResolver::thumb_adjusted_address(0x1000, true), 0x1000);
        assert_eq!(MethodResolver::thumb_adjusted_address(0x1001, false), 0x1001);
    }

    #[test]
    fn test_is_likely_thumb() {
        assert!(MethodResolver::is_likely_thumb(0x1001, "ARM"));
        assert!(!MethodResolver::is_likely_thumb(0x1000, "ARM"));
        assert!(!MethodResolver::is_likely_thumb(0x1001, "AARCH64"));
    }

    #[test]
    fn test_readonly_sections() {
        let sections = MethodResolver::readonly_sections();
        assert!(sections.contains(&"__objc_data"));
        assert!(sections.contains(&"__objc_classrefs"));
        assert!(!sections.contains(&"__objc_classlist"));
    }

    #[test]
    fn test_all_objc2_sections() {
        let sections = MethodResolver::all_objc2_sections();
        assert!(sections.contains(&"__objc_classlist"));
        assert!(sections.contains(&"__objc_catlist"));
        assert!(sections.contains(&"__objc_protolist"));
        assert!(sections.len() >= 12);
    }

    #[test]
    fn test_is_objc2_section() {
        assert!(MethodResolver::is_objc2_section("__objc_classlist"));
        assert!(MethodResolver::is_objc2_section("__objc_const"));
        assert!(MethodResolver::is_objc2_section("__data"));
        assert!(!MethodResolver::is_objc2_section("__text"));
    }

    #[test]
    fn test_is_objc1_section() {
        assert!(MethodResolver::is_objc1_section("__module_info"));
        assert!(MethodResolver::is_objc1_section("__symbols"));
        assert!(MethodResolver::is_objc1_section("__class"));
        assert!(!MethodResolver::is_objc1_section("__text"));
    }

    #[test]
    fn test_is_objc_segment() {
        assert!(MethodResolver::is_objc_segment("__OBJC"));
        assert!(MethodResolver::is_objc_segment("__DATA_CONST"));
        assert!(!MethodResolver::is_objc_segment("__TEXT"));
    }

    #[test]
    fn test_is_objc_program() {
        assert!(MethodResolver::is_objc_program(&["__TEXT", "__objc_classlist"]));
        assert!(MethodResolver::is_objc_program(&["__OBJC", "__TEXT"]));
        assert!(!MethodResolver::is_objc_program(&["__TEXT", "__DATA"]));
    }

    #[test]
    fn test_reference_fixup_utils() {
        assert!(ReferenceFixupUtils::should_delete_null(0));
        assert!(!ReferenceFixupUtils::should_delete_null(0x1000));

        assert!(ReferenceFixupUtils::needs_thumb_fixup(0x1001, true));
        assert!(!ReferenceFixupUtils::needs_thumb_fixup(0x1000, true));
        assert!(!ReferenceFixupUtils::needs_thumb_fixup(0x1001, false));

        assert_eq!(ReferenceFixupUtils::fixup_address(0x1001, true), 0x1000);
        assert_eq!(ReferenceFixupUtils::fixup_address(0x1000, true), 0x1000);
        assert_eq!(ReferenceFixupUtils::fixup_address(0x1001, false), 0x1001);
    }

    #[test]
    fn test_resolved_method() {
        let method = ResolvedMethod {
            name: "initWithFrame:".into(),
            types: "v32@0:8{CGRect}16".into(),
            implementation: 0x5000,
            is_class_method: false,
            class_name: "UIView".into(),
            symbol_name: "+[UIView initWithFrame:]".into(),
        };
        assert_eq!(method.name, "initWithFrame:");
        assert_eq!(method.implementation, 0x5000);
        assert!(!method.is_class_method);
    }

    #[test]
    fn test_class_info() {
        let class = ClassInfo {
            name: "NSString".into(),
            address: 0x4000,
            super_class_name: Some("NSObject".into()),
            is_meta: false,
            instance_methods: vec!["init".into(), "length".into()],
            class_methods: vec!["stringWithFormat:".into()],
            ivars: vec!["_storage".into()],
            protocols: vec!["NSCopying".into(), "NSCoding".into()],
        };
        assert_eq!(class.name, "NSString");
        assert_eq!(class.instance_methods.len(), 2);
        assert_eq!(class.protocols.len(), 2);
    }

    #[test]
    fn test_protocol_info() {
        let proto = ProtocolInfo {
            name: "NSCoding".into(),
            address: 0x5000,
            conforms_to: vec!["NSObject".into()],
            instance_methods: vec!["encodeWithCoder:".into(), "initWithCoder:".into()],
            class_methods: vec![],
            optional_instance_methods: vec![],
            optional_class_methods: vec![],
        };
        assert_eq!(proto.name, "NSCoding");
        assert_eq!(proto.conforms_to.len(), 1);
        assert_eq!(proto.instance_methods.len(), 2);
    }

    #[test]
    fn test_category_info() {
        let cat = CategoryInfo {
            name: "MyCategory".into(),
            class_name: "NSObject".into(),
            address: 0x6000,
            instance_methods: vec!["myMethod".into()],
            class_methods: vec!["myClassMethod".into()],
            protocols: vec!["MyProtocol".into()],
        };
        assert_eq!(cat.name, "MyCategory");
        assert_eq!(cat.class_name, "NSObject");
    }
}
