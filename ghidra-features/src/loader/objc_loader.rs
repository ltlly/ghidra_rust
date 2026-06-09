//! Objective-C aware loader for Mach-O binaries.
//!
//! Ported from Ghidra's `ghidra.app.util.opinion.ObjcLoader` Java class.
//!
//! This loader is a specialized Mach-O loader that detects and processes
//! Objective-C runtime metadata embedded in Mach-O binaries. It wraps the
//! standard Mach-O loading with ObjC-specific analysis:
//!
//! - Detects `__OBJC` (ObjC1) and `__objc_*` (ObjC2) sections
//! - Reads image info flags (ARC, Swift, GC support)
//! - Creates ObjC-specific load specs with enhanced language detection
//! - Provides ObjC metadata extraction during the load phase
//!
//! # Relationship to macho_loader
//!
//! This loader runs at a higher priority than the generic `macho_loader` when
//! ObjC metadata is detected. The generic Mach-O loader handles the low-level
//! parsing (headers, segments, sections); this loader adds ObjC-specific
//! intelligence on top.
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::loader::objc_loader::*;
//!
//! let data = vec![0u8; 32]; // placeholder
//! let sections = vec![
//!     ("__DATA".to_string(), "__objc_classlist".to_string(), 0x2000, 0x100, 0x1000),
//! ];
//! let detected = detect_objc_in_macho(&sections);
//! assert!(detected.is_some());
//! ```

use super::framework::*;
use super::macho_loader;

// ============================================================================
// Constants
// ============================================================================

/// The loader name for the Objective-C aware Mach-O loader.
///
/// Corresponds to Ghidra's ObjcLoader name.
pub const OBJC_LOADER_NAME: &str = "Mach-O Objective-C Loader";

/// Priority boost for Mach-O files containing ObjC metadata.
///
/// When ObjC metadata is detected, this loader takes precedence over the
/// generic Mach-O loader.
const OBJC_PRIORITY_BOOST: bool = true;

/// The minimum number of bytes required for image info (two u32 values).
const IMAGE_INFO_SIZE: usize = 8;

// ============================================================================
// ObjcDetected -- result of ObjC detection in a Mach-O
// ============================================================================

/// Result of detecting Objective-C metadata in a Mach-O binary.
///
/// Corresponds to Ghidra's ObjC detection results used to augment
/// the standard Mach-O load spec.
#[derive(Debug, Clone)]
pub struct ObjcDetected {
    /// Whether ObjC1 metadata (`__OBJC` segment) was found.
    pub has_objc1: bool,
    /// Whether ObjC2 metadata (`__objc_*` sections) was found.
    pub has_objc2: bool,
    /// The CPU type from the Mach-O header.
    pub cpu_type: i32,
    /// Whether this is a 64-bit binary.
    pub is_64bit: bool,
    /// ObjC image info version, if `__objc_imageinfo` was found.
    pub image_info_version: Option<u32>,
    /// ObjC image info flags, if `__objc_imageinfo` was found.
    pub image_info_flags: Option<u32>,
    /// Discovered ObjC section names.
    pub objc_sections: Vec<String>,
}

impl ObjcDetected {
    /// Whether any ObjC metadata was found.
    pub fn has_objc(&self) -> bool {
        self.has_objc1 || self.has_objc2
    }

    /// Whether the binary supports ARC.
    pub fn supports_arc(&self) -> bool {
        self.image_info_flags
            .map(|f| (f & IMAGE_FLAG_SUPPORTS_ARC) != 0)
            .unwrap_or(false)
    }

    /// Whether the binary supports Swift.
    pub fn supports_swift(&self) -> bool {
        self.image_info_flags
            .map(|f| (f & IMAGE_FLAG_SUPPORTS_SWIFT) != 0)
            .unwrap_or(false)
    }
}

/// Image info flag: ARC support.
const IMAGE_FLAG_SUPPORTS_ARC: u32 = 1 << 2;

/// Image info flag: Swift support.
const IMAGE_FLAG_SUPPORTS_SWIFT: u32 = 1 << 3;

// ============================================================================
// Section classification
// ============================================================================

/// Names of ObjC2 sections found in `__DATA` / `__DATA_CONST` segments.
const OBJC2_SECTIONS: &[&str] = &[
    "__objc_classlist",
    "__objc_catlist",
    "__objc_protolist",
    "__objc_selrefs",
    "__objc_classrefs",
    "__objc_data",
    "__objc_const",
    "__objc_methlist",
    "__objc_imageinfo",
    "__objc_nlclslist",
    "__objc_nlcatlist",
    "__objc_superrefs",
    "__objc_ivar",
    "__objc_protorefs",
];

/// Check if a section name is an ObjC2 section.
fn is_objc2_section(section: &str) -> bool {
    OBJC2_SECTIONS.contains(&section)
}

/// Check if a section belongs to ObjC1 (`__OBJC` segment).
fn is_objc1_segment(segment: &str) -> bool {
    segment == "__OBJC" || segment == "__objc"
}

// ============================================================================
// Detection functions
// ============================================================================

/// Detect Objective-C metadata in section information from a Mach-O binary.
///
/// Takes a list of `(segment, section, vm_addr, vm_size, file_offset)` tuples
/// (as would be extracted by the Mach-O header parser) and determines whether
/// ObjC metadata is present.
///
/// Returns `Some(ObjcDetected)` if ObjC metadata was found, `None` otherwise.
///
/// Corresponds to Ghidra's ObjC detection logic in `MachoLoader.getPreferred`.
pub fn detect_objc_in_macho(
    sections: &[(String, String, u64, u64, u64)],
) -> Option<ObjcDetected> {
    let mut has_objc1 = false;
    let mut has_objc2 = false;
    let mut objc_sections = Vec::new();

    for (segment, section, _addr, _size, _offset) in sections {
        if is_objc1_segment(segment) {
            has_objc1 = true;
            objc_sections.push(format!("{}.{}", segment, section));
        } else if (segment == "__DATA"
            || segment == "__DATA_CONST"
            || segment == "__DATA_DIRTY")
            && is_objc2_section(section)
        {
            has_objc2 = true;
            objc_sections.push(format!("{}.{}", segment, section));
        }
    }

    if !has_objc1 && !has_objc2 {
        return None;
    }

    Some(ObjcDetected {
        has_objc1,
        has_objc2,
        cpu_type: 0,  // filled in by caller from Mach-O header
        is_64bit: false, // filled in by caller
        image_info_version: None,
        image_info_flags: None,
        objc_sections,
    })
}

/// Detect ObjC metadata from raw Mach-O section data and fill in header info.
///
/// This is a convenience wrapper that also sets the CPU type and 64-bit flag
/// from the Mach-O header.
pub fn detect_objc_with_header(
    sections: &[(String, String, u64, u64, u64)],
    cpu_type: i32,
    is_64bit: bool,
) -> Option<ObjcDetected> {
    detect_objc_in_macho(sections).map(|mut detected| {
        detected.cpu_type = cpu_type;
        detected.is_64bit = is_64bit;
        detected
    })
}

/// Parse image info from raw bytes.
///
/// The `__objc_imageinfo` section contains two 32-bit values:
/// - version (ObjC/Swift ABI version)
/// - flags (feature flags)
///
/// Returns `(version, flags)` or `None` if the data is too short.
///
/// Corresponds to Ghidra's image info parsing.
pub fn parse_image_info(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < IMAGE_INFO_SIZE {
        return None;
    }
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    Some((version, flags))
}

// ============================================================================
// Load spec functions
// ============================================================================

/// Find ObjC-enhanced load specs for a Mach-O binary.
///
/// This function augments the standard Mach-O load specs with ObjC-specific
/// information when Objective-C metadata is detected.
///
/// Returns an empty vector if the data is not a Mach-O or contains no ObjC
/// metadata.
///
/// Corresponds to Ghidra's ObjcLoader preferred load spec logic.
pub fn find_objc_load_specs(
    data: &[u8],
    sections: &[(String, String, u64, u64, u64)],
) -> Vec<LoadSpec> {
    // First check if this is a Mach-O
    if !macho_loader::is_macho(data) {
        return Vec::new();
    }

    // Then check for ObjC metadata
    let detected = match detect_objc_in_macho(sections) {
        Some(d) => d,
        None => return Vec::new(),
    };

    // Parse header to get CPU type
    let mut detected = detected;
    if let Ok(header) = parse_macho_header_for_cpu(data) {
        detected.cpu_type = header.0;
        detected.is_64bit = header.1;
    }

    // Build a load spec using the Mach-O language mapping
    let machine = macho_cpu_name(detected.cpu_type);
    let image_base = if detected.is_64bit { 0x100000000 } else { 0x1000 };
    let results = QueryOpinionService::query("Mac OS X Mach-O", machine, None);

    let mut specs = Vec::new();
    for result in &results {
        let mut spec = LoadSpec::from_query_result(
            OBJC_LOADER_NAME,
            image_base,
            result,
        );
        // ObjC loaders are preferred when ObjC metadata is present
        spec.is_preferred = OBJC_PRIORITY_BOOST;
        specs.push(spec);
    }

    if specs.is_empty() {
        let mut spec = LoadSpec::with_unknown_language(
            OBJC_LOADER_NAME,
            image_base,
            true,
        );
        spec.is_preferred = OBJC_PRIORITY_BOOST;
        specs.push(spec);
    }

    specs
}

/// Check whether this loader should be preferred over the generic Mach-O loader.
///
/// Returns `true` if ObjC metadata is detected in the sections.
pub fn is_objc_preferred(
    data: &[u8],
    sections: &[(String, String, u64, u64, u64)],
) -> bool {
    macho_loader::is_macho(data) && detect_objc_in_macho(sections).is_some()
}

// ============================================================================
// Loader options
// ============================================================================

/// Option name: whether to apply ObjC metadata during loading.
pub const OPTION_APPLY_OBJC: &str = "Apply Objective-C Metadata";

/// Option name: whether to create ObjC namespaces.
pub const OPTION_CREATE_NAMESPACES: &str = "Create Objective-C Namespaces";

/// Option name: whether to resolve ObjC selectors.
pub const OPTION_RESOLVE_SELECTORS: &str = "Resolve Objective-C Selectors";

/// Default loader options for the ObjC loader.
pub fn default_objc_options() -> Vec<LoadOption> {
    vec![
        LoadOption::new_bool(OPTION_APPLY_OBJC, true),
        LoadOption::new_bool(OPTION_CREATE_NAMESPACES, true),
        LoadOption::new_bool(OPTION_RESOLVE_SELECTORS, true),
    ]
}

// ============================================================================
// Helper functions
// ============================================================================

/// Parse minimal Mach-O header to extract CPU type and bitness.
fn parse_macho_header_for_cpu(data: &[u8]) -> Result<(i32, bool), LoadError> {
    if data.len() < 8 {
        return Err(LoadError::MalformedInput("Too short for Mach-O".into()));
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    let (is_64, is_le) = match magic {
        macho::MH_MAGIC => (false, true),
        macho::MH_CIGAM => (false, false),
        macho::MH_MAGIC_64 => (true, true),
        macho::MH_CIGAM_64 => (true, false),
        _ => {
            let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            match magic_be {
                macho::MH_MAGIC => (false, false),
                macho::MH_CIGAM => (false, true),
                macho::MH_MAGIC_64 => (true, false),
                macho::MH_CIGAM_64 => (true, true),
                _ => return Err(LoadError::MalformedInput(format!("Bad Mach-O magic: 0x{:x}", magic))),
            }
        }
    };

    let cpu_type = if is_le {
        i32::from_le_bytes([data[4], data[5], data[6], data[7]])
    } else {
        i32::from_be_bytes([data[4], data[5], data[6], data[7]])
    };

    Ok((cpu_type, is_64))
}

/// Map Mach-O CPU type to a human-readable machine name.
fn macho_cpu_name(cpu_type: i32) -> &'static str {
    let base = cpu_type & 0x00FFFFFF;
    let is_64 = (cpu_type & macho::CPU_ARCH_ABI64) != 0;
    match base {
        macho::CPU_TYPE_X86 => {
            if is_64 { "x86_64" } else { "i386" }
        }
        macho::CPU_TYPE_ARM => {
            if is_64 { "arm64" } else { "ARM" }
        }
        macho::CPU_TYPE_POWERPC => {
            if is_64 { "ppc64" } else { "ppc" }
        }
        _ => "unknown",
    }
}

// Import macho constants from fileformats
use crate::fileformats::macho;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_objc2_sections() {
        let sections = vec![
            ("__TEXT".into(), "__cstring".into(), 0x1000, 0x100, 0),
            ("__DATA".into(), "__objc_classlist".into(), 0x2000, 0x100, 0x1000),
            ("__DATA".into(), "__objc_catlist".into(), 0x2100, 0x40, 0x1100),
            ("__DATA".into(), "__objc_protolist".into(), 0x2140, 0x20, 0x1140),
        ];
        let detected = detect_objc_in_macho(&sections).unwrap();
        assert!(detected.has_objc2);
        assert!(!detected.has_objc1);
        assert!(detected.has_objc());
        assert_eq!(detected.objc_sections.len(), 3);
    }

    #[test]
    fn test_detect_objc1_sections() {
        let sections = vec![
            ("__OBJC".into(), "__class".into(), 0x1000, 0x200, 0),
            ("__OBJC".into(), "__message_refs".into(), 0x1200, 0x100, 0x200),
        ];
        let detected = detect_objc_in_macho(&sections).unwrap();
        assert!(detected.has_objc1);
        assert!(!detected.has_objc2);
        assert!(detected.has_objc());
    }

    #[test]
    fn test_detect_no_objc() {
        let sections = vec![
            ("__TEXT".into(), "__text".into(), 0x1000, 0x500, 0),
            ("__DATA".into(), "__data".into(), 0x2000, 0x100, 0x1000),
        ];
        assert!(detect_objc_in_macho(&sections).is_none());
    }

    #[test]
    fn test_detect_empty_sections() {
        assert!(detect_objc_in_macho(&[]).is_none());
    }

    #[test]
    fn test_detect_mixed_objc1_objc2() {
        let sections = vec![
            ("__OBJC".into(), "__class".into(), 0x1000, 0x200, 0),
            ("__DATA".into(), "__objc_classlist".into(), 0x2000, 0x100, 0x1000),
        ];
        let detected = detect_objc_in_macho(&sections).unwrap();
        assert!(detected.has_objc1);
        assert!(detected.has_objc2);
    }

    #[test]
    fn test_detect_with_header() {
        let sections = vec![
            ("__DATA".into(), "__objc_classlist".into(), 0x2000, 0x100, 0x1000),
        ];
        let detected = detect_objc_with_header(&sections, macho::CPU_TYPE_ARM64, true).unwrap();
        assert_eq!(detected.cpu_type, macho::CPU_TYPE_ARM64);
        assert!(detected.is_64bit);
    }

    // -----------------------------------------------------------------------
    // Image info tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_image_info_valid() {
        // version=2, flags=0x0C (SUPPORTS_ARC | SUPPORTS_SWIFT)
        let data = [2, 0, 0, 0, 0x0C, 0, 0, 0];
        let (version, flags) = parse_image_info(&data).unwrap();
        assert_eq!(version, 2);
        assert_eq!(flags, 0x0C);
    }

    #[test]
    fn test_parse_image_info_too_short() {
        let data = [0u8; 4];
        assert!(parse_image_info(&data).is_none());
    }

    #[test]
    fn test_parse_image_info_empty() {
        assert!(parse_image_info(&[]).is_none());
    }

    // -----------------------------------------------------------------------
    // ObjcDetected property tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_detected_has_objc() {
        let d = ObjcDetected {
            has_objc1: false,
            has_objc2: true,
            cpu_type: macho::CPU_TYPE_X86_64,
            is_64bit: true,
            image_info_version: None,
            image_info_flags: None,
            objc_sections: vec!["__DATA.__objc_classlist".into()],
        };
        assert!(d.has_objc());
        assert!(!d.supports_arc());
        assert!(!d.supports_swift());
    }

    #[test]
    fn test_detected_supports_arc() {
        let d = ObjcDetected {
            has_objc1: false,
            has_objc2: true,
            cpu_type: macho::CPU_TYPE_ARM64,
            is_64bit: true,
            image_info_version: Some(2),
            image_info_flags: Some(IMAGE_FLAG_SUPPORTS_ARC),
            objc_sections: vec![],
        };
        assert!(d.supports_arc());
        assert!(!d.supports_swift());
    }

    #[test]
    fn test_detected_supports_swift() {
        let d = ObjcDetected {
            has_objc1: false,
            has_objc2: true,
            cpu_type: macho::CPU_TYPE_ARM64,
            is_64bit: true,
            image_info_version: Some(2),
            image_info_flags: Some(IMAGE_FLAG_SUPPORTS_ARC | IMAGE_FLAG_SUPPORTS_SWIFT),
            objc_sections: vec![],
        };
        assert!(d.supports_arc());
        assert!(d.supports_swift());
    }

    #[test]
    fn test_detected_no_objc() {
        let d = ObjcDetected {
            has_objc1: false,
            has_objc2: false,
            cpu_type: 0,
            is_64bit: false,
            image_info_version: None,
            image_info_flags: None,
            objc_sections: vec![],
        };
        assert!(!d.has_objc());
    }

    // -----------------------------------------------------------------------
    // Section classification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_objc2_section() {
        assert!(is_objc2_section("__objc_classlist"));
        assert!(is_objc2_section("__objc_catlist"));
        assert!(is_objc2_section("__objc_protolist"));
        assert!(is_objc2_section("__objc_selrefs"));
        assert!(is_objc2_section("__objc_imageinfo"));
        assert!(is_objc2_section("__objc_nlclslist"));
    }

    #[test]
    fn test_is_not_objc2_section() {
        assert!(!is_objc2_section("__data"));
        assert!(!is_objc2_section("__text"));
        assert!(!is_objc2_section("__cstring"));
        assert!(!is_objc2_section("__got"));
    }

    #[test]
    fn test_is_objc1_segment() {
        assert!(is_objc1_segment("__OBJC"));
        assert!(is_objc1_segment("__objc"));
        assert!(!is_objc1_segment("__DATA"));
        assert!(!is_objc1_segment("__TEXT"));
    }

    // -----------------------------------------------------------------------
    // Mach-O header parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_macho_header_le64() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&macho::CPU_TYPE_X86_64.to_le_bytes());

        let (cpu, is_64) = parse_macho_header_for_cpu(&data).unwrap();
        assert_eq!(cpu, macho::CPU_TYPE_X86_64);
        assert!(is_64);
    }

    #[test]
    fn test_parse_macho_header_le32() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&macho::MH_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&macho::CPU_TYPE_X86.to_le_bytes());

        let (cpu, is_64) = parse_macho_header_for_cpu(&data).unwrap();
        assert_eq!(cpu, macho::CPU_TYPE_X86);
        assert!(!is_64);
    }

    #[test]
    fn test_parse_macho_header_too_short() {
        let data = [0u8; 4];
        assert!(parse_macho_header_for_cpu(&data).is_err());
    }

    #[test]
    fn test_parse_macho_header_invalid_magic() {
        let data = [0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(parse_macho_header_for_cpu(&data).is_err());
    }

    // -----------------------------------------------------------------------
    // CPU name tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_macho_cpu_name() {
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_X86), "i386");
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_X86_64), "x86_64");
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_ARM), "ARM");
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_ARM64), "arm64");
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_POWERPC), "ppc");
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_POWERPC64), "ppc64");
        assert_eq!(macho_cpu_name(999), "unknown");
    }

    // -----------------------------------------------------------------------
    // Load spec tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_objc_load_specs_non_macho() {
        let data = [0x7f, b'E', b'L', b'F', 0, 0, 0, 0]; // ELF
        let sections = vec![
            ("__DATA".into(), "__objc_classlist".into(), 0x2000, 0x100, 0x1000),
        ];
        let specs = find_objc_load_specs(&data, &sections);
        assert!(specs.is_empty());
    }

    #[test]
    fn test_find_objc_load_specs_no_objc() {
        // Build minimal Mach-O header
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&macho::CPU_TYPE_X86_64.to_le_bytes());

        let sections = vec![
            ("__TEXT".into(), "__text".into(), 0x1000, 0x500, 0),
        ];
        let specs = find_objc_load_specs(&data, &sections);
        assert!(specs.is_empty());
    }

    #[test]
    fn test_find_objc_load_specs_with_objc() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&macho::CPU_TYPE_X86_64.to_le_bytes());

        let sections = vec![
            ("__DATA".into(), "__objc_classlist".into(), 0x2000, 0x100, 0x1000),
        ];
        let specs = find_objc_load_specs(&data, &sections);
        assert!(!specs.is_empty());
        assert!(specs[0].is_preferred);
    }

    // -----------------------------------------------------------------------
    // Preference tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_objc_preferred_macho_with_objc() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());

        let sections = vec![
            ("__DATA".into(), "__objc_classlist".into(), 0x2000, 0x100, 0x1000),
        ];
        assert!(is_objc_preferred(&data, &sections));
    }

    #[test]
    fn test_is_objc_preferred_macho_without_objc() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());

        let sections = vec![
            ("__TEXT".into(), "__text".into(), 0x1000, 0x500, 0),
        ];
        assert!(!is_objc_preferred(&data, &sections));
    }

    #[test]
    fn test_is_objc_preferred_not_macho() {
        let data = [0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        let sections = vec![
            ("__DATA".into(), "__objc_classlist".into(), 0x2000, 0x100, 0x1000),
        ];
        assert!(!is_objc_preferred(&data, &sections));
    }

    // -----------------------------------------------------------------------
    // Options tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_objc_options() {
        let options = default_objc_options();
        assert_eq!(options.len(), 3);
        assert!(options.iter().any(|o| o.name == OPTION_APPLY_OBJC));
        assert!(options.iter().any(|o| o.name == OPTION_CREATE_NAMESPACES));
        assert!(options.iter().any(|o| o.name == OPTION_RESOLVE_SELECTORS));
    }

    // -----------------------------------------------------------------------
    // Constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_loader_name() {
        assert_eq!(OBJC_LOADER_NAME, "Mach-O Objective-C Loader");
    }

    #[test]
    fn test_image_info_size() {
        assert_eq!(IMAGE_INFO_SIZE, 8);
    }
}
