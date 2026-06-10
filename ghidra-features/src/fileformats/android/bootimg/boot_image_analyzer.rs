//! Android boot image analyzer.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.bootimg.BootImageAnalyzer`.
//!
//! The boot image analyzer identifies `boot.img` and `vendor_boot.img` files
//! by their magic bytes and dispatches to the version-specific header parser.
//! In Ghidra, this analyzer creates data labels and fragments for each boot
//! image section (kernel, ramdisk, second stage, DTB); in this Rust port we
//! provide the detection and parsing logic.

use super::boot_image_header::{
    is_boot_image, is_vendor_boot_image, parse_boot_image_header, parse_vendor_boot_image_header,
    BootImageHeader, BootImageHeaderVersion, VendorBootImageHeader, VendorBootImageHeaderVersion,
    VendorBootImageHeaderV4, BOOT_MAGIC, VENDOR_BOOT_MAGIC,
};

// ═══════════════════════════════════════════════════════════════════════════════════
// BootImageAnalyzer
// ═══════════════════════════════════════════════════════════════════════════════════

/// Analyzer metadata for the Android boot image format.
///
/// In the Java source, `BootImageAnalyzer` extends `FileFormatAnalyzer` and
/// hooks into Ghidra's analysis pipeline. This Rust struct captures the
/// analyzer's identity and provides the core detection/parsing entry point.
#[derive(Debug, Clone)]
pub struct BootImageAnalyzer {
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether enabled by default.
    pub default_enablement: bool,
}

impl Default for BootImageAnalyzer {
    fn default() -> Self {
        Self {
            name: "Android Boot, Recovery, or Vendor Image Annotation".to_string(),
            description: "Annotates Android Boot, Recovery, or Vendor Image files.".to_string(),
            default_enablement: false,
        }
    }
}

impl BootImageAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the given data blob appears to be a boot image
    /// or vendor boot image.
    pub fn can_analyze(data: &[u8]) -> bool {
        is_boot_image(data) || is_vendor_boot_image(data)
    }

    /// Returns true if the data is a boot image with a supported version.
    pub fn is_supported_boot_image(data: &[u8]) -> bool {
        if !is_boot_image(data) {
            return false;
        }
        parse_boot_image_header(data).is_ok()
    }

    /// Returns true if the data is a vendor boot image with a supported version.
    pub fn is_supported_vendor_boot_image(data: &[u8]) -> bool {
        if !is_vendor_boot_image(data) {
            return false;
        }
        parse_vendor_boot_image_header(data).is_ok()
    }

    /// Attempt to parse the boot image header from the given data.
    ///
    /// Returns the version-specific header on success.
    pub fn analyze_boot_image(data: &[u8]) -> Result<BootImageHeaderVersion, String> {
        parse_boot_image_header(data)
    }

    /// Attempt to parse the vendor boot image header from the given data.
    ///
    /// Returns the version-specific header on success.
    pub fn analyze_vendor_boot_image(
        data: &[u8],
    ) -> Result<VendorBootImageHeaderVersion, String> {
        parse_vendor_boot_image_header(data)
    }

    /// Compute the list of fragment descriptors for a parsed boot image.
    ///
    /// Each fragment is `(name, start_offset, end_offset)` and can be used
    /// to annotate the binary.
    pub fn boot_image_fragments(header: &BootImageHeaderVersion) -> Vec<(&str, u64, u64)> {
        let mut fragments = Vec::new();
        match header {
            BootImageHeaderVersion::V0(h) => {
                fragments.push(("header", 0, h.page_size as u64));
                if h.kernel_size > 0 {
                    fragments.push((
                        super::boot_image_header::KERNEL,
                        h.kernel_offset(),
                        h.kernel_offset() + h.kernel_size as u64,
                    ));
                }
                if h.ramdisk_size > 0 {
                    fragments.push((
                        super::boot_image_header::RAMDISK,
                        h.ramdisk_offset(),
                        h.ramdisk_offset() + h.ramdisk_size as u64,
                    ));
                }
                if h.second_size > 0 {
                    fragments.push((
                        super::boot_image_header::SECOND_STAGE,
                        h.second_offset(),
                        h.second_offset() + h.second_size as u64,
                    ));
                }
            }
            BootImageHeaderVersion::V1(h) => {
                fragments.push(("header", 0, h.v0.page_size as u64));
                if h.v0.kernel_size > 0 {
                    fragments.push((
                        super::boot_image_header::KERNEL,
                        h.kernel_offset(),
                        h.kernel_offset() + h.v0.kernel_size as u64,
                    ));
                }
                if h.v0.ramdisk_size > 0 {
                    fragments.push((
                        super::boot_image_header::RAMDISK,
                        h.ramdisk_offset(),
                        h.ramdisk_offset() + h.v0.ramdisk_size as u64,
                    ));
                }
                if h.v0.second_size > 0 {
                    fragments.push((
                        super::boot_image_header::SECOND_STAGE,
                        h.second_offset(),
                        h.second_offset() + h.v0.second_size as u64,
                    ));
                }
            }
            BootImageHeaderVersion::V2(h) => {
                fragments.push(("header", 0, h.v1.v0.page_size as u64));
                if h.v1.v0.kernel_size > 0 {
                    fragments.push((
                        super::boot_image_header::KERNEL,
                        h.kernel_offset(),
                        h.kernel_offset() + h.v1.v0.kernel_size as u64,
                    ));
                }
                if h.v1.v0.ramdisk_size > 0 {
                    fragments.push((
                        super::boot_image_header::RAMDISK,
                        h.ramdisk_offset(),
                        h.ramdisk_offset() + h.v1.v0.ramdisk_size as u64,
                    ));
                }
                if h.v1.v0.second_size > 0 {
                    fragments.push((
                        super::boot_image_header::SECOND_STAGE,
                        h.second_offset(),
                        h.second_offset() + h.v1.v0.second_size as u64,
                    ));
                }
                if h.dtb_size > 0 {
                    let dtb_off = h.ramdisk_offset()
                        + h.v1.v0.ramdisk_size as u64;
                    let ps = h.v1.v0.page_size as u64;
                    let aligned = (dtb_off + ps - 1) / ps * ps;
                    fragments.push((
                        super::boot_image_header::DTB,
                        aligned,
                        aligned + h.dtb_size as u64,
                    ));
                }
            }
            BootImageHeaderVersion::V3(h) => {
                fragments.push(("header", 0, super::boot_image_header::V3_PAGE_SIZE as u64));
                if h.kernel_size > 0 {
                    fragments.push((
                        super::boot_image_header::KERNEL,
                        h.kernel_offset(),
                        h.kernel_offset() + h.kernel_size as u64,
                    ));
                }
                if h.ramdisk_size > 0 {
                    fragments.push((
                        super::boot_image_header::RAMDISK,
                        h.ramdisk_offset(),
                        h.ramdisk_offset() + h.ramdisk_size as u64,
                    ));
                }
            }
            BootImageHeaderVersion::V4(h) => {
                fragments.push(("header", 0, super::boot_image_header::V4_PAGE_SIZE as u64));
                if h.v3.kernel_size > 0 {
                    fragments.push((
                        super::boot_image_header::KERNEL,
                        h.kernel_offset(),
                        h.kernel_offset() + h.v3.kernel_size as u64,
                    ));
                }
                if h.v3.ramdisk_size > 0 {
                    fragments.push((
                        super::boot_image_header::RAMDISK,
                        h.ramdisk_offset(),
                        h.ramdisk_offset() + h.v3.ramdisk_size as u64,
                    ));
                }
            }
        }
        fragments
    }

    /// Compute the list of fragment descriptors for a parsed vendor boot image.
    ///
    /// Each fragment is `(name, start_offset, end_offset)`.
    pub fn vendor_boot_image_fragments(
        header: &VendorBootImageHeaderVersion,
    ) -> Vec<(&str, u64, u64)> {
        let mut fragments = Vec::new();
        match header {
            VendorBootImageHeaderVersion::V3(h) => {
                fragments.push(("header", 0, h.header_size as u64));
                if h.vendor_ramdisk_size > 0 {
                    fragments.push((
                        super::boot_image_header::RAMDISK,
                        h.vendor_ramdisk_offset(),
                        h.vendor_ramdisk_offset() + h.vendor_ramdisk_size as u64,
                    ));
                }
                if h.dtb_size > 0 {
                    fragments.push((
                        super::boot_image_header::DTB,
                        h.dtb_offset(),
                        h.dtb_offset() + h.dtb_size as u64,
                    ));
                }
            }
            VendorBootImageHeaderVersion::V4(h) => {
                fragments.push(("header", 0, h.v3.header_size as u64));
                if h.v3.vendor_ramdisk_size > 0 {
                    if h.vendor_ramdisk_table_entry_num > 1 {
                        for i in 0..h.vendor_ramdisk_table_entry_num as usize {
                            let name = format!("{}_{}", super::boot_image_header::RAMDISK, i);
                            // Leak the string to get a &'static str -- acceptable for
                            // a bounded, small set of fragments.
                            let name: &'static str = Box::leak(name.into_boxed_str());
                            let offset = h.nested_vendor_ramdisk_offset(i);
                            let size = h.nested_vendor_ramdisk_size(i) as u64;
                            fragments.push((name, offset, offset + size));
                        }
                    } else {
                        fragments.push((
                            super::boot_image_header::RAMDISK,
                            h.vendor_ramdisk_offset(),
                            h.vendor_ramdisk_offset() + h.v3.vendor_ramdisk_size as u64,
                        ));
                    }
                }
                if h.v3.dtb_size > 0 {
                    fragments.push((
                        super::boot_image_header::DTB,
                        h.dtb_offset(),
                        h.dtb_offset() + h.v3.dtb_size as u64,
                    ));
                }
                if h.vendor_ramdisk_table_size > 0 {
                    fragments.push((
                        "Ramdisk Table",
                        h.vendor_ramdisk_table_offset(),
                        h.vendor_ramdisk_table_offset() + h.vendor_ramdisk_table_size as u64,
                    ));
                }
                if h.bootconfig_size > 0 {
                    fragments.push((
                        "Boot Config",
                        h.bootconfig_offset(),
                        h.bootconfig_offset() + h.bootconfig_size as u64,
                    ));
                }
            }
        }
        fragments
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_analyze_boot_image() {
        let mut data = vec![0u8; 100];
        data[0..8].copy_from_slice(b"ANDROID!");
        assert!(BootImageAnalyzer::can_analyze(&data));
    }

    #[test]
    fn test_can_analyze_vendor_boot_image() {
        let mut data = vec![0u8; 100];
        data[0..8].copy_from_slice(b"VNDRBOOT");
        assert!(BootImageAnalyzer::can_analyze(&data));
    }

    #[test]
    fn test_cannot_analyze_random() {
        assert!(!BootImageAnalyzer::can_analyze(b"random data"));
    }

    #[test]
    fn test_is_supported_boot_image() {
        let mut data = vec![0u8; super::super::boot_image_header::BOOT_IMAGE_HEADER_V0_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[36..40].copy_from_slice(&4096u32.to_le_bytes()); // page_size
        data[40..44].copy_from_slice(&0u32.to_le_bytes()); // header_version
        assert!(BootImageAnalyzer::is_supported_boot_image(&data));
    }

    #[test]
    fn test_is_supported_boot_image_v3() {
        let mut data = vec![0u8; super::super::boot_image_header::BOOT_IMAGE_HEADER_V3_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[40..44].copy_from_slice(&3u32.to_le_bytes()); // header_version
        assert!(BootImageAnalyzer::is_supported_boot_image(&data));
    }

    #[test]
    fn test_is_supported_vendor_boot_image() {
        let mut data = vec![0u8; super::super::boot_image_header::VENDOR_BOOT_IMAGE_HEADER_V3_SIZE];
        data[0..8].copy_from_slice(b"VNDRBOOT");
        data[8..12].copy_from_slice(&3u32.to_le_bytes()); // header_version
        data[12..16].copy_from_slice(&4096u32.to_le_bytes()); // page_size
        data[2096..2100].copy_from_slice(&2112u32.to_le_bytes()); // header_size
        assert!(BootImageAnalyzer::is_supported_vendor_boot_image(&data));
    }

    #[test]
    fn test_analyze_boot_image_v0() {
        let mut data = vec![0u8; super::super::boot_image_header::BOOT_IMAGE_HEADER_V0_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[8..12].copy_from_slice(&8192u32.to_le_bytes()); // kernel_size
        data[16..20].copy_from_slice(&4096u32.to_le_bytes()); // ramdisk_size
        data[36..40].copy_from_slice(&4096u32.to_le_bytes()); // page_size
        data[40..44].copy_from_slice(&0u32.to_le_bytes()); // header_version

        let header = BootImageAnalyzer::analyze_boot_image(&data).unwrap();
        assert_eq!(header.version(), 0);
    }

    #[test]
    fn test_analyze_boot_image_v3() {
        let mut data = vec![0u8; super::super::boot_image_header::BOOT_IMAGE_HEADER_V3_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[8..12].copy_from_slice(&8192u32.to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[40..44].copy_from_slice(&3u32.to_le_bytes());

        let header = BootImageAnalyzer::analyze_boot_image(&data).unwrap();
        assert_eq!(header.version(), 3);
    }

    #[test]
    fn test_analyze_boot_image_v4() {
        let mut data = vec![0u8; super::super::boot_image_header::BOOT_IMAGE_HEADER_V4_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[8..12].copy_from_slice(&8192u32.to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[40..44].copy_from_slice(&4u32.to_le_bytes());

        let header = BootImageAnalyzer::analyze_boot_image(&data).unwrap();
        assert_eq!(header.version(), 4);
    }

    #[test]
    fn test_analyze_vendor_boot_v3() {
        let mut data = vec![0u8; super::super::boot_image_header::VENDOR_BOOT_IMAGE_HEADER_V3_SIZE];
        data[0..8].copy_from_slice(b"VNDRBOOT");
        data[8..12].copy_from_slice(&3u32.to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[24..28].copy_from_slice(&16384u32.to_le_bytes());
        data[2096..2100].copy_from_slice(&2112u32.to_le_bytes());
        data[2100..2104].copy_from_slice(&8192u32.to_le_bytes());

        let header = BootImageAnalyzer::analyze_vendor_boot_image(&data).unwrap();
        match &header {
            VendorBootImageHeaderVersion::V3(h) => {
                assert_eq!(h.header_version, 3);
            }
            _ => panic!("Expected vendor V3"),
        }
    }

    #[test]
    fn test_analyze_invalid() {
        assert!(BootImageAnalyzer::analyze_boot_image(b"bad data").is_err());
        assert!(BootImageAnalyzer::analyze_vendor_boot_image(b"bad data").is_err());
    }

    #[test]
    fn test_default_name() {
        let analyzer = BootImageAnalyzer::new();
        assert_eq!(analyzer.name, "Android Boot, Recovery, or Vendor Image Annotation");
        assert!(!analyzer.default_enablement);
    }

    #[test]
    fn test_boot_image_fragments_v0() {
        let mut data = vec![0u8; super::super::boot_image_header::BOOT_IMAGE_HEADER_V0_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[8..12].copy_from_slice(&8192u32.to_le_bytes()); // kernel_size
        data[16..20].copy_from_slice(&4096u32.to_le_bytes()); // ramdisk_size
        data[24..28].copy_from_slice(&2048u32.to_le_bytes()); // second_size
        data[36..40].copy_from_slice(&4096u32.to_le_bytes()); // page_size
        data[40..44].copy_from_slice(&0u32.to_le_bytes()); // header_version

        let header = BootImageAnalyzer::analyze_boot_image(&data).unwrap();
        let fragments = BootImageAnalyzer::boot_image_fragments(&header);
        // header + kernel + ramdisk + second stage = 4
        assert_eq!(fragments.len(), 4);
        assert_eq!(fragments[0].0, "header");
        assert_eq!(fragments[1].0, "kernel");
        assert_eq!(fragments[2].0, "ramdisk");
        assert_eq!(fragments[3].0, "second stage");
    }

    #[test]
    fn test_boot_image_fragments_v3() {
        let mut data = vec![0u8; super::super::boot_image_header::BOOT_IMAGE_HEADER_V3_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[8..12].copy_from_slice(&8192u32.to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[40..44].copy_from_slice(&3u32.to_le_bytes());

        let header = BootImageAnalyzer::analyze_boot_image(&data).unwrap();
        let fragments = BootImageAnalyzer::boot_image_fragments(&header);
        // header + kernel + ramdisk = 3 (no second stage in v3)
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0].0, "header");
        assert_eq!(fragments[1].0, "kernel");
        assert_eq!(fragments[2].0, "ramdisk");
    }

    #[test]
    fn test_boot_image_fragments_v4() {
        let mut data = vec![0u8; super::super::boot_image_header::BOOT_IMAGE_HEADER_V4_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[8..12].copy_from_slice(&8192u32.to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[40..44].copy_from_slice(&4u32.to_le_bytes());

        let header = BootImageAnalyzer::analyze_boot_image(&data).unwrap();
        let fragments = BootImageAnalyzer::boot_image_fragments(&header);
        // header + kernel + ramdisk = 3
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0].0, "header");
        assert_eq!(fragments[1].0, "kernel");
        assert_eq!(fragments[2].0, "ramdisk");
    }

    #[test]
    fn test_vendor_boot_fragments_v3() {
        let mut data = vec![0u8; super::super::boot_image_header::VENDOR_BOOT_IMAGE_HEADER_V3_SIZE];
        data[0..8].copy_from_slice(b"VNDRBOOT");
        data[8..12].copy_from_slice(&3u32.to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[24..28].copy_from_slice(&16384u32.to_le_bytes());
        data[2096..2100].copy_from_slice(&2112u32.to_le_bytes());
        data[2100..2104].copy_from_slice(&8192u32.to_le_bytes());

        let header = BootImageAnalyzer::analyze_vendor_boot_image(&data).unwrap();
        let fragments = BootImageAnalyzer::vendor_boot_image_fragments(&header);
        // header + ramdisk + dtb = 3
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0].0, "header");
        assert_eq!(fragments[1].0, "ramdisk");
        assert_eq!(fragments[2].0, "dtb");
    }
}
