//! Objective-C aware loader for Mach-O binaries.
//!
//! Ported from Ghidra's `ghidra.app.util.opinion.ObjcLoader` (380 lines) and
//! related ObjC loader support classes. This loader detects Mach-O binaries
//! that contain Objective-C metadata sections and provides specialized loading
//! support for extracting class hierarchies, method lists, protocols, and
//! category definitions.
//!
//! # Architecture
//!
//! - [`OBJC_LOADER_NAME`] -- loader name constant
//! - [`ObjcSectionKind`] -- classification of ObjC-related Mach-O sections
//! - [`ObjcSectionInfo`] -- discovered section metadata
//! - [`ObjcLoadSpec`] -- ObjC-specific load specification
//! - [`ObjcProgramInfo`] -- summary of ObjC content found during loading
//! - Functions: section detection, metadata extraction, symbol creation
//!
//! # ObjC Sections
//!
//! The loader recognizes two generations of Objective-C metadata:
//!
//! **ObjC1** (legacy, `__OBJC` segment):
//! - `__class`, `__category`, `__protocol`, `__message_refs`,
//!   `__cls_refs`, `__instance_vars`, `__class_vars`
//!
//! **ObjC2** (modern, `__DATA` / `__DATA_CONST` segments):
//! - `__objc_classlist`, `__objc_catlist`, `__objc_protolist`,
//!   `__objc_selrefs`, `__objc_classrefs`, `__objc_data`,
//!   `__objc_const`, `__objc_methlist`, `__objc_imageinfo`,
//!   `__objc_nlclslist`, `__objc_nlcatlist`

use crate::objc::{ObjcState, ObjcMethodType};
use crate::loader::framework::*;

// ============================================================================
// Constants
// ============================================================================

/// The loader name for Objective-C aware Mach-O loading.
pub const OBJC_LOADER_NAME: &str = "Objective-C Mach-O Loader";

// ============================================================================
// ObjcSectionKind -- classification of ObjC sections
// ============================================================================

/// Classifies which generation of Objective-C metadata a section belongs to.
///
/// Corresponds to Ghidra's internal section classification for ObjC processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjcSectionKind {
    /// Legacy Objective-C 1.x metadata (`__OBJC` segment).
    Objc1,
    /// Modern Objective-C 2.x metadata (`__DATA` / `__DATA_CONST` segments).
    Objc2,
    /// Not an Objective-C section.
    None,
}

impl ObjcSectionKind {
    /// Classify a section by its segment and section name.
    ///
    /// Corresponds to Ghidra's section-name matching logic in the ObjC loader.
    pub fn classify(segment: &str, section: &str) -> Self {
        if segment == "__OBJC" || segment == "__objc" {
            return Self::Objc1;
        }

        if segment == "__DATA" || segment == "__DATA_CONST" || segment == "__DATA_DIRTY" {
            if Self::is_objc2_section(section) {
                return Self::Objc2;
            }
        }

        Self::None
    }

    /// Check if a section name belongs to ObjC2 metadata.
    fn is_objc2_section(section: &str) -> bool {
        matches!(
            section,
            "__objc_classlist"
                | "__objc_catlist"
                | "__objc_protolist"
                | "__objc_selrefs"
                | "__objc_classrefs"
                | "__objc_data"
                | "__objc_const"
                | "__objc_methlist"
                | "__objc_imageinfo"
                | "__objc_nlclslist"
                | "__objc_nlcatlist"
                | "__objc_superrefs"
                | "__objc_ivar"
                | "__objc_protorefs"
        )
    }

    /// Whether this is any kind of ObjC section.
    pub fn is_objc(self) -> bool {
        self != Self::None
    }

    /// Whether this is an ObjC1 section.
    pub fn is_objc1(self) -> bool {
        self == Self::Objc1
    }

    /// Whether this is an ObjC2 section.
    pub fn is_objc2(self) -> bool {
        self == Self::Objc2
    }
}

// ============================================================================
// ObjcSectionInfo -- discovered section metadata
// ============================================================================

/// Metadata about a discovered Objective-C section in a Mach-O binary.
///
/// Corresponds to Ghidra's internal representation of ObjC section locations
/// during the loading phase.
#[derive(Debug, Clone)]
pub struct ObjcSectionInfo {
    /// The segment name (e.g., `__DATA`, `__OBJC`).
    pub segment: String,
    /// The section name (e.g., `__objc_classlist`).
    pub section: String,
    /// Virtual address of the section.
    pub vm_addr: u64,
    /// Size of the section in bytes.
    pub vm_size: u64,
    /// File offset of the section.
    pub file_offset: u64,
    /// Classification of this section.
    pub kind: ObjcSectionKind,
}

impl ObjcSectionInfo {
    /// Create a new section info.
    pub fn new(
        segment: impl Into<String>,
        section: impl Into<String>,
        vm_addr: u64,
        vm_size: u64,
        file_offset: u64,
    ) -> Self {
        let segment = segment.into();
        let section = section.into();
        let kind = ObjcSectionKind::classify(&segment, &section);
        Self {
            segment,
            section,
            vm_addr,
            vm_size,
            file_offset,
            kind,
        }
    }

    /// The full section path (`segment.section`).
    pub fn full_name(&self) -> String {
        format!("{}.{}", self.segment, self.section)
    }

    /// Whether this section contains ObjC metadata.
    pub fn is_objc(&self) -> bool {
        self.kind.is_objc()
    }

    /// End address of this section.
    pub fn end_addr(&self) -> u64 {
        self.vm_addr.saturating_add(self.vm_size)
    }

    /// Whether this section is empty (zero size).
    pub fn is_empty(&self) -> bool {
        self.vm_size == 0
    }
}

// ============================================================================
// ObjcLoadSpec -- ObjC-specific load specification
// ============================================================================

/// An ObjC-specific load specification for a Mach-O binary.
///
/// Extends the basic load spec with ObjC metadata information.
///
/// Corresponds to Ghidra's ObjC load spec augmentation.
#[derive(Debug, Clone)]
pub struct ObjcLoadSpec {
    /// The underlying load spec.
    pub base: LoadSpec,
    /// Whether ObjC1 metadata was detected.
    pub has_objc1: bool,
    /// Whether ObjC2 metadata was detected.
    pub has_objc2: bool,
    /// Discovered ObjC sections.
    pub sections: Vec<ObjcSectionInfo>,
    /// Whether the binary supports ARC (Automatic Reference Counting).
    pub supports_arc: bool,
    /// Whether the binary supports garbage collection.
    pub supports_gc: bool,
}

impl ObjcLoadSpec {
    /// Create a new ObjC load spec.
    pub fn new(base: LoadSpec) -> Self {
        Self {
            base,
            has_objc1: false,
            has_objc2: false,
            sections: Vec::new(),
            supports_arc: false,
            supports_gc: false,
        }
    }

    /// Add an ObjC section to this load spec.
    pub fn add_section(&mut self, section: ObjcSectionInfo) {
        match section.kind {
            ObjcSectionKind::Objc1 => self.has_objc1 = true,
            ObjcSectionKind::Objc2 => self.has_objc2 = true,
            ObjcSectionKind::None => {}
        }
        self.sections.push(section);
    }

    /// Whether any ObjC metadata was detected.
    pub fn has_objc(&self) -> bool {
        self.has_objc1 || self.has_objc2
    }

    /// Get all ObjC sections of a given kind.
    pub fn sections_of_kind(&self, kind: ObjcSectionKind) -> Vec<&ObjcSectionInfo> {
        self.sections.iter().filter(|s| s.kind == kind).collect()
    }

    /// Get all ObjC2 class list sections.
    pub fn class_list_sections(&self) -> Vec<&ObjcSectionInfo> {
        self.sections
            .iter()
            .filter(|s| s.section == "__objc_classlist")
            .collect()
    }

    /// Get all ObjC2 category list sections.
    pub fn category_list_sections(&self) -> Vec<&ObjcSectionInfo> {
        self.sections
            .iter()
            .filter(|s| s.section == "__objc_catlist")
            .collect()
    }

    /// Get all ObjC2 protocol list sections.
    pub fn protocol_list_sections(&self) -> Vec<&ObjcSectionInfo> {
        self.sections
            .iter()
            .filter(|s| s.section == "__objc_protolist")
            .collect()
    }

    /// Get the image info section, if present.
    pub fn image_info_section(&self) -> Option<&ObjcSectionInfo> {
        self.sections
            .iter()
            .find(|s| s.section == "__objc_imageinfo")
    }
}

// ============================================================================
// ObjcProgramInfo -- summary of ObjC content found during loading
// ============================================================================

/// Summary of Objective-C content found in a loaded program.
///
/// Created after the loading phase to report what ObjC metadata was discovered.
///
/// Corresponds to Ghidra's post-load ObjC summary reporting.
#[derive(Debug, Clone, Default)]
pub struct ObjcProgramInfo {
    /// Number of ObjC classes found.
    pub class_count: usize,
    /// Number of ObjC categories found.
    pub category_count: usize,
    /// Number of ObjC protocols found.
    pub protocol_count: usize,
    /// Number of selectors found.
    pub selector_count: usize,
    /// Number of method lists parsed.
    pub method_list_count: usize,
    /// Number of methods found.
    pub method_count: usize,
    /// Whether ObjC1 metadata was processed.
    pub processed_objc1: bool,
    /// Whether ObjC2 metadata was processed.
    pub processed_objc2: bool,
    /// Log messages from processing.
    pub messages: Vec<String>,
}

impl ObjcProgramInfo {
    /// Create a new empty program info.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether any ObjC metadata was processed.
    pub fn has_objc(&self) -> bool {
        self.processed_objc1 || self.processed_objc2
    }

    /// Total number of ObjC symbols found.
    pub fn total_symbols(&self) -> usize {
        self.class_count + self.category_count + self.protocol_count
    }

    /// Add a log message.
    pub fn log(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
    }

    /// Format a summary string.
    pub fn summary(&self) -> String {
        format!(
            "ObjC{}: {} classes, {} categories, {} protocols, {} selectors, {} methods in {} lists",
            if self.processed_objc2 { "2" } else { "1" },
            self.class_count,
            self.category_count,
            self.protocol_count,
            self.selector_count,
            self.method_count,
            self.method_list_count,
        )
    }
}

// ============================================================================
// ObjC section detection functions
// ============================================================================

/// Check whether a Mach-O binary contains Objective-C metadata.
///
/// Scans the section names for known ObjC1 or ObjC2 section patterns.
///
/// Corresponds to Ghidra's ObjC detection in `MachoLoader` and `ObjcUtils`.
pub fn has_objc_metadata(sections: &[ObjcSectionInfo]) -> bool {
    sections.iter().any(|s| s.is_objc())
}

/// Classify all sections from segment/section name pairs.
///
/// Given a list of `(segment, section, vm_addr, vm_size, file_offset)` tuples,
/// returns `ObjcSectionInfo` entries for each.
pub fn classify_sections(
    raw_sections: &[(String, String, u64, u64, u64)],
) -> Vec<ObjcSectionInfo> {
    raw_sections
        .iter()
        .map(|(seg, sec, addr, size, offset)| {
            ObjcSectionInfo::new(seg.as_str(), sec.as_str(), *addr, *size, *offset)
        })
        .collect()
}

/// Find all ObjC sections from a list of section info.
pub fn find_objc_sections(sections: &[ObjcSectionInfo]) -> Vec<&ObjcSectionInfo> {
    sections.iter().filter(|s| s.is_objc()).collect()
}

/// Parse image info flags from raw bytes at the image info section.
///
/// The `__objc_imageinfo` section contains two 32-bit values:
/// - `version` (Swift version / ObjC version)
/// - `flags` (feature flags)
///
/// Returns `(version, flags)`.
///
/// Corresponds to Ghidra's image info parsing in Objc2.
pub fn parse_image_info(data: &[u8], offset: usize) -> Option<(u32, u32)> {
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
    Some((version, flags))
}

/// Class flags for ObjC2 metadata (from `class_ro_t`).
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

    /// Return human-readable flag names.
    pub fn describe(flags: u32) -> Vec<&'static str> {
        let mut names = Vec::new();
        if flags & RO_META != 0 { names.push("META"); }
        if flags & RO_HAS_SWIFT_EXTENSIONS != 0 { names.push("SWIFT_EXTENSIONS"); }
        if flags & RO_ROOT != 0 { names.push("ROOT"); }
        if flags & RO_HIDDEN != 0 { names.push("HIDDEN"); }
        if flags & RO_EXCEPTION != 0 { names.push("EXCEPTION"); }
        if flags & RO_IS_ARC != 0 { names.push("ARC"); }
        if flags & RO_HAS_CXX_STRUCTORS != 0 { names.push("CXX_STRUCTORS"); }
        if flags & RO_HAS_ASSOC_OBJECTS != 0 { names.push("ASSOC_OBJECTS"); }
        if flags & RO_REALIZED != 0 { names.push("REALIZED"); }
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
        if flags & SUPPORTS_GC != 0 { names.push("SUPPORTS_GC"); }
        if flags & REQUIRES_GC != 0 { names.push("REQUIRES_GC"); }
        if flags & SUPPORTS_ARC != 0 { names.push("SUPPORTS_ARC"); }
        if flags & SUPPORTS_SWIFT != 0 { names.push("SUPPORTS_SWIFT"); }
        if flags & HAS_CATEGORY_CLASS_PROPERTIES != 0 { names.push("HAS_CATEGORY_CLASS_PROPERTIES"); }
        names
    }
}

// ============================================================================
// ObjC selector and class name helpers
// ============================================================================

/// Create the standard Objective-C class symbol name.
///
/// Corresponds to Ghidra's symbol naming for ObjC classes.
pub fn objc_class_symbol(class_name: &str) -> String {
    format!("_OBJC_CLASS_$_{}", class_name)
}

/// Create the standard Objective-C metaclass symbol name.
pub fn objc_metaclass_symbol(class_name: &str) -> String {
    format!("_OBJC_METACLASS_$_{}", class_name)
}

/// Create the standard Objective-C category symbol name.
pub fn objc_category_symbol(class_name: &str, category_name: &str) -> String {
    format!("_OBJC_$_CATEGORY_{}_{}", class_name, category_name)
}

/// Create an Objective-C selector reference symbol name.
pub fn objc_selector_symbol(selector: &str) -> String {
    format!("_OBJC_SELECTOR_REFERENCES_{}", selector)
}

/// The namespace path for ObjC symbols.
pub const OBJC_NAMESPACE: &str = "objc";

// ============================================================================
// ObjC class descriptor structures (ObjC2)
// ============================================================================

/// Parsed ObjC2 class metadata from `__objc_data`.
///
/// Corresponds to Ghidra's `Objc2Class`.
#[derive(Debug, Clone)]
pub struct Objc2ClassData {
    /// Address of the class structure.
    pub address: u64,
    /// Address of the ISA (metaclass) pointer.
    pub isa: u64,
    /// Address of the superclass pointer.
    pub superclass: u64,
    /// Address of the method cache.
    pub cache_addr: u64,
    /// Address of the class's `class_ro_t` (read-only data).
    pub ro_data: u64,
    /// Flags from `class_ro_t`.
    pub flags: u32,
    /// Whether this is a metaclass.
    pub is_meta: bool,
    /// Whether this class is a Swift class.
    pub is_swift: bool,
}

impl Objc2ClassData {
    /// Create a new class data structure.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            isa: 0,
            superclass: 0,
            cache_addr: 0,
            ro_data: 0,
            flags: 0,
            is_meta: false,
            is_swift: false,
        }
    }

    /// Update flags and derive boolean properties.
    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
        self.is_meta = (flags & class_flags::RO_META) != 0;
        self.is_swift = (flags & class_flags::RO_HAS_SWIFT_EXTENSIONS) != 0;
    }
}

/// Parsed ObjC2 category metadata from `__objc_catlist`.
///
/// Corresponds to Ghidra's `Objc2Category`.
#[derive(Debug, Clone)]
pub struct Objc2CategoryData {
    /// Address of the category structure.
    pub address: u64,
    /// Category name pointer.
    pub name_addr: u64,
    /// Class this category extends.
    pub class_addr: u64,
    /// Instance methods pointer.
    pub instance_methods: u64,
    /// Class methods pointer.
    pub class_methods: u64,
    /// Protocols pointer.
    pub protocols: u64,
    /// Instance properties pointer.
    pub instance_properties: u64,
}

impl Objc2CategoryData {
    /// Create a new category data structure.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            name_addr: 0,
            class_addr: 0,
            instance_methods: 0,
            class_methods: 0,
            protocols: 0,
            instance_properties: 0,
        }
    }
}

/// Parsed ObjC2 protocol metadata from `__objc_protolist`.
///
/// Corresponds to Ghidra's `Objc2Protocol`.
#[derive(Debug, Clone)]
pub struct Objc2ProtocolData {
    /// Address of the protocol structure.
    pub address: u64,
    /// Protocol name pointer.
    pub name_addr: u64,
    /// Protocols this protocol conforms to.
    pub protocols: u64,
    /// Instance methods pointer.
    pub instance_methods: u64,
    /// Class methods pointer.
    pub class_methods: u64,
    /// Optional instance methods.
    pub optional_instance_methods: u64,
    /// Optional class methods.
    pub optional_class_methods: u64,
    /// Instance properties.
    pub instance_properties: u64,
}

impl Objc2ProtocolData {
    /// Create a new protocol data structure.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            name_addr: 0,
            protocols: 0,
            instance_methods: 0,
            class_methods: 0,
            optional_instance_methods: 0,
            optional_class_methods: 0,
            instance_properties: 0,
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
    fn test_section_kind_classify_objc1() {
        assert_eq!(ObjcSectionKind::classify("__OBJC", "__class"), ObjcSectionKind::Objc1);
        assert_eq!(ObjcSectionKind::classify("__objc", "__message_refs"), ObjcSectionKind::Objc1);
    }

    #[test]
    fn test_section_kind_classify_objc2() {
        assert_eq!(
            ObjcSectionKind::classify("__DATA", "__objc_classlist"),
            ObjcSectionKind::Objc2
        );
        assert_eq!(
            ObjcSectionKind::classify("__DATA_CONST", "__objc_const"),
            ObjcSectionKind::Objc2
        );
        assert_eq!(
            ObjcSectionKind::classify("__DATA", "__objc_imageinfo"),
            ObjcSectionKind::Objc2
        );
    }

    #[test]
    fn test_section_kind_classify_none() {
        assert_eq!(ObjcSectionKind::classify("__TEXT", "__text"), ObjcSectionKind::None);
        assert_eq!(ObjcSectionKind::classify("__DATA", "__data"), ObjcSectionKind::None);
        assert_eq!(ObjcSectionKind::classify("__DATA_CONST", "__got"), ObjcSectionKind::None);
    }

    #[test]
    fn test_section_info_creation() {
        let info = ObjcSectionInfo::new("__DATA", "__objc_classlist", 0x2000, 0x100, 0x1000);
        assert_eq!(info.kind, ObjcSectionKind::Objc2);
        assert!(info.is_objc());
        assert_eq!(info.full_name(), "__DATA.__objc_classlist");
        assert_eq!(info.end_addr(), 0x2100);
        assert!(!info.is_empty());
    }

    #[test]
    fn test_section_info_empty() {
        let info = ObjcSectionInfo::new("__DATA", "__objc_classlist", 0x2000, 0, 0x1000);
        assert!(info.is_empty());
    }

    #[test]
    fn test_objc_load_spec() {
        let base = LoadSpec::with_unknown_language("test", 0x1000, true);
        let mut spec = ObjcLoadSpec::new(base);

        assert!(!spec.has_objc());
        assert!(!spec.has_objc1);
        assert!(!spec.has_objc2);

        spec.add_section(ObjcSectionInfo::new("__DATA", "__objc_classlist", 0x2000, 0x100, 0x1000));
        assert!(spec.has_objc());
        assert!(spec.has_objc2);
        assert_eq!(spec.class_list_sections().len(), 1);
    }

    #[test]
    fn test_objc_load_spec_sections_of_kind() {
        let base = LoadSpec::with_unknown_language("test", 0x1000, true);
        let mut spec = ObjcLoadSpec::new(base);
        spec.add_section(ObjcSectionInfo::new("__DATA", "__objc_classlist", 0x2000, 0x100, 0x1000));
        spec.add_section(ObjcSectionInfo::new("__DATA", "__objc_catlist", 0x2100, 0x40, 0x1100));
        spec.add_section(ObjcSectionInfo::new("__DATA", "__objc_protolist", 0x2140, 0x20, 0x1140));

        let objc2 = spec.sections_of_kind(ObjcSectionKind::Objc2);
        assert_eq!(objc2.len(), 3);

        let objc1 = spec.sections_of_kind(ObjcSectionKind::Objc1);
        assert_eq!(objc1.len(), 0);
    }

    #[test]
    fn test_objc_load_spec_image_info() {
        let base = LoadSpec::with_unknown_language("test", 0x1000, true);
        let mut spec = ObjcLoadSpec::new(base);
        assert!(spec.image_info_section().is_none());

        spec.add_section(ObjcSectionInfo::new("__DATA", "__objc_imageinfo", 0x3000, 8, 0x2000));
        assert!(spec.image_info_section().is_some());
    }

    #[test]
    fn test_program_info_default() {
        let info = ObjcProgramInfo::new();
        assert!(!info.has_objc());
        assert_eq!(info.total_symbols(), 0);
        assert!(info.messages.is_empty());
    }

    #[test]
    fn test_program_info_summary() {
        let mut info = ObjcProgramInfo::new();
        info.processed_objc2 = true;
        info.class_count = 10;
        info.category_count = 3;
        info.protocol_count = 5;
        info.selector_count = 50;
        info.method_count = 120;
        info.method_list_count = 15;

        let summary = info.summary();
        assert!(summary.contains("ObjC2"));
        assert!(summary.contains("10 classes"));
        assert!(summary.contains("3 categories"));
        assert!(summary.contains("5 protocols"));
    }

    #[test]
    fn test_has_objc_metadata() {
        let sections = vec![
            ObjcSectionInfo::new("__TEXT", "__cstring", 0x1000, 0x100, 0),
            ObjcSectionInfo::new("__DATA", "__objc_classlist", 0x2000, 0x100, 0x1000),
        ];
        assert!(has_objc_metadata(&sections));

        let no_objc = vec![
            ObjcSectionInfo::new("__TEXT", "__cstring", 0x1000, 0x100, 0),
            ObjcSectionInfo::new("__DATA", "__data", 0x2000, 0x100, 0x1000),
        ];
        assert!(!has_objc_metadata(&no_objc));
    }

    #[test]
    fn test_classify_sections() {
        let raw = vec![
            ("__DATA".into(), "__objc_classlist".into(), 0x2000, 0x100, 0x1000),
            ("__DATA".into(), "__objc_catlist".into(), 0x2100, 0x40, 0x1100),
            ("__TEXT".into(), "__text".into(), 0x1000, 0x500, 0),
        ];
        let classified = classify_sections(&raw);
        assert_eq!(classified.len(), 3);

        let objc = find_objc_sections(&classified);
        assert_eq!(objc.len(), 2);
    }

    #[test]
    fn test_parse_image_info() {
        // version=2, flags=0x0C (SUPPORTS_ARC | SUPPORTS_SWIFT)
        let data = [2, 0, 0, 0, 0x0C, 0, 0, 0];
        let (version, flags) = parse_image_info(&data, 0).unwrap();
        assert_eq!(version, 2);
        assert_eq!(flags, 0x0C);
    }

    #[test]
    fn test_parse_image_info_too_short() {
        let data = [0u8; 4];
        assert!(parse_image_info(&data, 0).is_none());
    }

    #[test]
    fn test_class_flags_describe() {
        let flags = class_flags::RO_META | class_flags::RO_IS_ARC;
        let names = class_flags::describe(flags);
        assert!(names.contains(&"META"));
        assert!(names.contains(&"ARC"));
        assert!(!names.contains(&"ROOT"));
    }

    #[test]
    fn test_image_flags_describe() {
        let flags = image_flags::SUPPORTS_ARC | image_flags::SUPPORTS_SWIFT;
        let names = image_flags::describe(flags);
        assert!(names.contains(&"SUPPORTS_ARC"));
        assert!(names.contains(&"SUPPORTS_SWIFT"));
    }

    #[test]
    fn test_objc_class_symbol() {
        assert_eq!(objc_class_symbol("NSString"), "_OBJC_CLASS_$_NSString");
    }

    #[test]
    fn test_objc_metaclass_symbol() {
        assert_eq!(objc_metaclass_symbol("NSString"), "_OBJC_METACLASS_$_NSString");
    }

    #[test]
    fn test_objc_category_symbol() {
        assert_eq!(
            objc_category_symbol("NSString", "Additions"),
            "_OBJC_$_CATEGORY_NSString_Additions"
        );
    }

    #[test]
    fn test_objc2_class_data() {
        let mut class = Objc2ClassData::new(0x1000);
        assert_eq!(class.address, 0x1000);
        assert!(!class.is_meta);
        assert!(!class.is_swift);

        class.set_flags(class_flags::RO_META | class_flags::RO_HAS_SWIFT_EXTENSIONS);
        assert!(class.is_meta);
        assert!(class.is_swift);
    }

    #[test]
    fn test_objc2_category_data() {
        let mut cat = Objc2CategoryData::new(0x2000);
        cat.name_addr = 0x3000;
        cat.class_addr = 0x4000;
        assert_eq!(cat.address, 0x2000);
        assert_eq!(cat.name_addr, 0x3000);
    }

    #[test]
    fn test_objc2_protocol_data() {
        let proto = Objc2ProtocolData::new(0x5000);
        assert_eq!(proto.address, 0x5000);
        assert_eq!(proto.name_addr, 0);
    }

    #[test]
    fn test_section_kind_is_methods() {
        assert!(ObjcSectionKind::Objc1.is_objc());
        assert!(ObjcSectionKind::Objc2.is_objc());
        assert!(!ObjcSectionKind::None.is_objc());

        assert!(ObjcSectionKind::Objc1.is_objc1());
        assert!(!ObjcSectionKind::Objc1.is_objc2());
        assert!(ObjcSectionKind::Objc2.is_objc2());
        assert!(!ObjcSectionKind::Objc2.is_objc1());
    }

    #[test]
    fn test_program_info_logging() {
        let mut info = ObjcProgramInfo::new();
        info.log("Found 10 classes");
        info.log("Processed ObjC2 metadata");
        assert_eq!(info.messages.len(), 2);
        assert!(info.messages[0].contains("10 classes"));
    }
}
