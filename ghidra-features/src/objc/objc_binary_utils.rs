//! Objective-C binary scanning and utility functions.
//!
//! Ported from Ghidra's `ObjcUtils` Java class (430 lines) and
//! `Objc2Constants.isObjectiveC2` method.
//!
//! Provides utilities for:
//! - Detecting Objective-C programs by section/segment names
//! - THUMB code detection for ARM binaries
//! - Reference fixup for THUMB addresses
//! - Memory block management (read-only marking)
//! - Symbol name manipulation (prefix stripping, formatting)
//! - Section name validation for ObjC1 and ObjC2

/// Binary scanning and utility functions for Objective-C metadata.
///
/// Corresponds to Java's `ObjcUtils` static methods.
pub struct ObjcBinaryUtils;

impl ObjcBinaryUtils {
    /// The prefix for Objective-C 2.x sections.
    pub const OBJC2_PREFIX: &'static str = "__objc_";

    // -----------------------------------------------------------------------
    // Program detection
    // -----------------------------------------------------------------------

    /// Check if a program is likely an Objective-C 2.x program.
    ///
    /// Checks the executable format and memory block names.
    ///
    /// Corresponds to Java's `Objc2Constants.isObjectiveC2`.
    pub fn is_objectivec2(
        executable_format: Option<&str>,
        block_names: &[&str],
    ) -> bool {
        let is_macho = matches!(
            executable_format,
            Some("Mach-O") | Some("DYLD Cache") | Some("Extracted DYLD Component")
        );
        if !is_macho {
            return false;
        }
        block_names
            .iter()
            .any(|name| name.starts_with(Self::OBJC2_PREFIX))
    }

    /// Check if a program is likely an Objective-C 1.x program.
    ///
    /// Checks for the `__OBJC` segment.
    pub fn is_objectivec1(segment_names: &[&str]) -> bool {
        segment_names
            .iter()
            .any(|s| *s == "__OBJC" || *s == "__objc")
    }

    /// Check if a program is any kind of Objective-C program.
    pub fn is_objectivec(executable_format: Option<&str>, block_names: &[&str]) -> bool {
        Self::is_objectivec2(executable_format, block_names)
            || Self::is_objectivec1(block_names)
    }

    // -----------------------------------------------------------------------
    // THUMB code detection (ARM-specific)
    // -----------------------------------------------------------------------

    /// Check if an address is likely THUMB code on an ARM processor.
    ///
    /// THUMB code typically has bit 0 set in function pointers.
    ///
    /// Corresponds to Java's `ObjcUtils.isThumb(Program, Address)`.
    pub fn is_thumb(address: u64, processor: &str) -> bool {
        if !processor.eq_ignore_ascii_case("ARM") {
            return false;
        }
        address % 2 != 0
    }

    /// Get the actual code address by stripping the THUMB bit.
    ///
    /// THUMB code addresses have bit 0 set; the actual instruction
    /// address is at an even boundary.
    ///
    /// Corresponds to Java's THUMB address adjustment in `fixupReferences`.
    pub fn thumb_code_address(address: u64) -> u64 {
        if address % 2 != 0 {
            address - 1
        } else {
            address
        }
    }

    /// Check if an address needs THUMB fixup.
    pub fn needs_thumb_fixup(address: u64, is_thumb_code: bool) -> bool {
        is_thumb_code && address % 2 != 0
    }

    // -----------------------------------------------------------------------
    // Reference management
    // -----------------------------------------------------------------------

    /// Check if a reference should be deleted (points to NULL).
    ///
    /// Corresponds to Java's `fixupReferences` null check.
    pub fn should_delete_null_reference(to_address: u64) -> bool {
        to_address == 0
    }

    /// Compute the fixed-up reference target address.
    ///
    /// Handles THUMB adjustment for ARM binaries.
    ///
    /// Corresponds to Java's `fixupReferences` THUMB adjustment.
    pub fn fixup_reference_target(to_address: u64, is_thumb: bool) -> u64 {
        if is_thumb && to_address % 2 != 0 {
            to_address - 1
        } else {
            to_address
        }
    }

    // -----------------------------------------------------------------------
    // Symbol name manipulation
    // -----------------------------------------------------------------------

    /// The prefix for Objective-C class symbols.
    pub const OBJC_CLASS_SYMBOL_PREFIX: &'static str = "_OBJC_CLASS_$_";

    /// The prefix for Objective-C metaclass symbols.
    pub const OBJC_META_CLASS_SYMBOL_PREFIX: &'static str = "_OBJC_METACLASS_$_";

    /// The prefix for Objective-C category symbols.
    pub const OBJC_CATEGORY_SYMBOL_PREFIX: &'static str = "_OBJC_$_CATEGORY_";

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

    /// Check if a name has an ObjC class prefix.
    pub fn has_class_prefix(name: &str) -> bool {
        name.starts_with(Self::OBJC_CLASS_SYMBOL_PREFIX)
            || name.starts_with(Self::OBJC_META_CLASS_SYMBOL_PREFIX)
    }

    // -----------------------------------------------------------------------
    // Section name utilities
    // -----------------------------------------------------------------------

    /// All valid ObjC1 section names.
    pub fn objc1_section_names() -> Vec<&'static str> {
        vec![
            "__module_info",
            "__symbols",
            "__category",
            "__class",
            "__instance_vars",
            "__protocol",
            "__method",
            "__class_names",
            "__meta_class",
            "__cls_meth",
            "__inst_meth",
        ]
    }

    /// All valid ObjC2 section names.
    pub fn objc2_section_names() -> Vec<&'static str> {
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

    /// Check if a section name is a valid ObjC1 section.
    pub fn is_objc1_section(name: &str) -> bool {
        Self::objc1_section_names().contains(&name)
    }

    /// Check if a section name is a valid ObjC2 section.
    pub fn is_objc2_section(name: &str) -> bool {
        name.starts_with(Self::OBJC2_PREFIX)
    }

    /// Check if a section name is any ObjC section.
    pub fn is_objc_section(name: &str) -> bool {
        Self::is_objc1_section(name) || Self::is_objc2_section(name)
    }

    /// Check if a segment name is ObjC-related.
    pub fn is_objc_segment(segment_name: &str) -> bool {
        matches!(
            segment_name,
            "__OBJC" | "__objc" | "__DATA" | "__DATA_CONST" | "__DATA_DIRTY"
        )
    }

    /// Get ObjC2 sections that should be marked read-only after analysis.
    pub fn readonly_objc2_sections() -> Vec<&'static str> {
        vec![
            "__objc_data",
            "__objc_classrefs",
            "__objc_msgrefs",
            "__objc_selrefs",
            "__objc_superrefs",
            "__objc_protorefs",
        ]
    }

    // -----------------------------------------------------------------------
    // Namespace utilities
    // -----------------------------------------------------------------------

    /// The base Objective-C namespace.
    pub const NAMESPACE: &'static str = "objc";

    /// Create a namespace path for a class.
    pub fn class_namespace(class_name: &str) -> String {
        format!("{}::{}", Self::NAMESPACE, class_name)
    }

    /// Create a namespace path for a protocol.
    pub fn protocol_namespace(protocol_name: &str) -> String {
        format!("{}::Protocols::{}", Self::NAMESPACE, protocol_name)
    }

    /// Create a namespace path for a category.
    pub fn category_namespace(category_name: &str) -> String {
        format!("{}::Categories::{}", Self::NAMESPACE, category_name)
    }

    /// Create a namespace path for a metaclass.
    pub fn metaclass_namespace(class_name: &str) -> String {
        format!("{}::MetaClasses::{}", Self::NAMESPACE, class_name)
    }

    // -----------------------------------------------------------------------
    // Display formatting
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Data reading utilities
    // -----------------------------------------------------------------------

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

    /// Read a null-terminated ASCII string from a byte slice.
    ///
    /// Corresponds to Java's `ObjcUtils.dereferenceAsciiString`.
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

    /// Dereference a string pointer: read the pointer at `offset`, then read the
    /// string at the pointed-to address.
    ///
    /// Corresponds to Java's `ObjcUtils.dereferenceAsciiString(BinaryReader, boolean)`.
    pub fn dereference_string(data: &[u8], offset: usize, is_32bit: bool) -> Option<String> {
        let string_addr = Self::read_index(data, offset, is_32bit)?;
        if string_addr == 0 {
            return None;
        }
        Self::read_string_at(data, string_addr as usize)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_objectivec2() {
        assert!(ObjcBinaryUtils::is_objectivec2(
            Some("Mach-O"),
            &["__TEXT", "__objc_classlist"]
        ));
        assert!(ObjcBinaryUtils::is_objectivec2(
            Some("DYLD Cache"),
            &["__objc_const"]
        ));
        assert!(!ObjcBinaryUtils::is_objectivec2(
            Some("ELF"),
            &["__objc_classlist"]
        ));
        assert!(!ObjcBinaryUtils::is_objectivec2(
            Some("Mach-O"),
            &["__TEXT", "__DATA"]
        ));
    }

    #[test]
    fn test_is_objectivec1() {
        assert!(ObjcBinaryUtils::is_objectivec1(&["__TEXT", "__OBJC"]));
        assert!(ObjcBinaryUtils::is_objectivec1(&["__objc"]));
        assert!(!ObjcBinaryUtils::is_objectivec1(&["__TEXT", "__DATA"]));
    }

    #[test]
    fn test_is_objectivec() {
        assert!(ObjcBinaryUtils::is_objectivec(
            Some("Mach-O"),
            &["__TEXT", "__objc_classlist"]
        ));
        assert!(ObjcBinaryUtils::is_objectivec(
            Some("Mach-O"),
            &["__OBJC", "__TEXT"]
        ));
        assert!(!ObjcBinaryUtils::is_objectivec(
            Some("ELF"),
            &["__TEXT", "__DATA"]
        ));
    }

    #[test]
    fn test_is_thumb() {
        assert!(ObjcBinaryUtils::is_thumb(0x1001, "ARM"));
        assert!(!ObjcBinaryUtils::is_thumb(0x1000, "ARM"));
        assert!(!ObjcBinaryUtils::is_thumb(0x1001, "AARCH64"));
        assert!(!ObjcBinaryUtils::is_thumb(0x1001, "x86"));
    }

    #[test]
    fn test_thumb_code_address() {
        assert_eq!(ObjcBinaryUtils::thumb_code_address(0x1001), 0x1000);
        assert_eq!(ObjcBinaryUtils::thumb_code_address(0x1000), 0x1000);
    }

    #[test]
    fn test_needs_thumb_fixup() {
        assert!(ObjcBinaryUtils::needs_thumb_fixup(0x1001, true));
        assert!(!ObjcBinaryUtils::needs_thumb_fixup(0x1000, true));
        assert!(!ObjcBinaryUtils::needs_thumb_fixup(0x1001, false));
    }

    #[test]
    fn test_reference_fixup() {
        assert!(ObjcBinaryUtils::should_delete_null_reference(0));
        assert!(!ObjcBinaryUtils::should_delete_null_reference(0x1000));

        assert_eq!(
            ObjcBinaryUtils::fixup_reference_target(0x1001, true),
            0x1000
        );
        assert_eq!(
            ObjcBinaryUtils::fixup_reference_target(0x1000, true),
            0x1000
        );
        assert_eq!(
            ObjcBinaryUtils::fixup_reference_target(0x1001, false),
            0x1001
        );
    }

    #[test]
    fn test_strip_class_prefix() {
        assert_eq!(
            ObjcBinaryUtils::strip_class_prefix("_OBJC_CLASS_$_NSString"),
            "NSString"
        );
        assert_eq!(
            ObjcBinaryUtils::strip_class_prefix("_OBJC_METACLASS_$_NSString"),
            "NSString"
        );
        assert_eq!(
            ObjcBinaryUtils::strip_class_prefix("plain_name"),
            "plain_name"
        );
    }

    #[test]
    fn test_class_symbol_name() {
        assert_eq!(
            ObjcBinaryUtils::class_symbol_name("NSString"),
            "_OBJC_CLASS_$_NSString"
        );
    }

    #[test]
    fn test_metaclass_symbol_name() {
        assert_eq!(
            ObjcBinaryUtils::metaclass_symbol_name("NSString"),
            "_OBJC_METACLASS_$_NSString"
        );
    }

    #[test]
    fn test_category_symbol_name() {
        assert_eq!(
            ObjcBinaryUtils::category_symbol_name("NSObject", "MyCategory"),
            "_OBJC_$_CATEGORY_NSObject_MyCategory"
        );
    }

    #[test]
    fn test_has_class_prefix() {
        assert!(ObjcBinaryUtils::has_class_prefix("_OBJC_CLASS_$_NSString"));
        assert!(ObjcBinaryUtils::has_class_prefix(
            "_OBJC_METACLASS_$_NSString"
        ));
        assert!(!ObjcBinaryUtils::has_class_prefix("NSString"));
    }

    #[test]
    fn test_objc1_section_names() {
        let names = ObjcBinaryUtils::objc1_section_names();
        assert!(names.contains(&"__module_info"));
        assert!(names.contains(&"__symbols"));
        assert!(names.contains(&"__class"));
        assert!(names.len() >= 10);
    }

    #[test]
    fn test_objc2_section_names() {
        let names = ObjcBinaryUtils::objc2_section_names();
        assert!(names.contains(&"__objc_classlist"));
        assert!(names.contains(&"__objc_catlist"));
        assert!(names.contains(&"__objc_protolist"));
        assert!(names.len() >= 12);
    }

    #[test]
    fn test_is_objc1_section() {
        assert!(ObjcBinaryUtils::is_objc1_section("__module_info"));
        assert!(ObjcBinaryUtils::is_objc1_section("__symbols"));
        assert!(!ObjcBinaryUtils::is_objc1_section("__objc_classlist"));
    }

    #[test]
    fn test_is_objc2_section() {
        assert!(ObjcBinaryUtils::is_objc2_section("__objc_classlist"));
        assert!(ObjcBinaryUtils::is_objc2_section("__objc_const"));
        assert!(!ObjcBinaryUtils::is_objc2_section("__module_info"));
    }

    #[test]
    fn test_is_objc_section() {
        assert!(ObjcBinaryUtils::is_objc_section("__module_info"));
        assert!(ObjcBinaryUtils::is_objc_section("__objc_classlist"));
        assert!(!ObjcBinaryUtils::is_objc_section("__text"));
    }

    #[test]
    fn test_is_objc_segment() {
        assert!(ObjcBinaryUtils::is_objc_segment("__OBJC"));
        assert!(ObjcBinaryUtils::is_objc_segment("__DATA_CONST"));
        assert!(!ObjcBinaryUtils::is_objc_segment("__TEXT"));
    }

    #[test]
    fn test_readonly_objc2_sections() {
        let sections = ObjcBinaryUtils::readonly_objc2_sections();
        assert!(sections.contains(&"__objc_data"));
        assert!(sections.contains(&"__objc_classrefs"));
        assert!(!sections.contains(&"__objc_classlist"));
    }

    #[test]
    fn test_namespace_paths() {
        assert_eq!(
            ObjcBinaryUtils::class_namespace("UIView"),
            "objc::UIView"
        );
        assert_eq!(
            ObjcBinaryUtils::protocol_namespace("NSCoding"),
            "objc::Protocols::NSCoding"
        );
        assert_eq!(
            ObjcBinaryUtils::category_namespace("MyCategory"),
            "objc::Categories::MyCategory"
        );
        assert_eq!(
            ObjcBinaryUtils::metaclass_namespace("UIView"),
            "objc::MetaClasses::UIView"
        );
    }

    #[test]
    fn test_format_class_name() {
        assert_eq!(
            ObjcBinaryUtils::format_class_name("UIView", false),
            "UIView"
        );
        assert_eq!(
            ObjcBinaryUtils::format_class_name("UIView", true),
            "+UIView"
        );
    }

    #[test]
    fn test_format_method() {
        assert_eq!(
            ObjcBinaryUtils::format_method(false, "UIView", "initWithFrame:"),
            "+[UIView initWithFrame:]"
        );
        assert_eq!(
            ObjcBinaryUtils::format_method(true, "UIView", "alloc"),
            "-[UIView alloc]"
        );
    }

    #[test]
    fn test_read_index_32bit() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(
            ObjcBinaryUtils::read_index(&data, 0, true),
            Some(0x12345678)
        );
    }

    #[test]
    fn test_read_index_64bit() {
        let data = [0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x00];
        assert_eq!(
            ObjcBinaryUtils::read_index(&data, 0, false),
            Some(0x00ABCDEF12345678)
        );
    }

    #[test]
    fn test_read_index_out_of_bounds() {
        let data = [0x01, 0x02];
        assert_eq!(ObjcBinaryUtils::read_index(&data, 0, true), None);
    }

    #[test]
    fn test_read_string_at() {
        let data = b"\x00\x00\x00\x00Hello, World!\x00";
        assert_eq!(
            ObjcBinaryUtils::read_string_at(data, 4),
            Some("Hello, World!".to_string())
        );
    }

    #[test]
    fn test_dereference_string() {
        let mut data = vec![0u8; 64];
        // String pointer at offset 0, pointing to offset 16
        data[0..4].copy_from_slice(&16u32.to_le_bytes());
        // String at offset 16
        let s = b"NSString\0";
        data[16..16 + s.len()].copy_from_slice(s);

        assert_eq!(
            ObjcBinaryUtils::dereference_string(&data, 0, true),
            Some("NSString".to_string())
        );
    }

    #[test]
    fn test_dereference_string_null() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            ObjcBinaryUtils::dereference_string(&data, 0, true),
            None
        );
    }
}
