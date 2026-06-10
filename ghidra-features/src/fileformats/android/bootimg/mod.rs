//! Android boot image file format modules.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.bootimg` package.
//!
//! Covers: boot image headers (v0-v4), vendor boot image headers (v3-v4),
//! vendor ramdisk table entries, constants, and the analyzer.

pub mod boot_image_analyzer;
pub mod boot_image_header;

// Re-exports
pub use boot_image_analyzer::BootImageAnalyzer;
pub use boot_image_header::{
    is_boot_image, is_vendor_boot_image, parse_boot_image_header, parse_vendor_boot_image_header,
    BootImageHeader, BootImageHeaderVersion, BootImageHeaderV0, BootImageHeaderV1,
    BootImageHeaderV2, BootImageHeaderV3, BootImageHeaderV4, VendorBootImageHeader,
    VendorBootImageHeaderVersion, VendorBootImageHeaderV3, VendorBootImageHeaderV4,
    VendorRamdiskTableEntryV4, BOOT_IMAGE_HEADER_V0_SIZE, BOOT_IMAGE_HEADER_V1_SIZE,
    BOOT_IMAGE_HEADER_V2_SIZE, BOOT_IMAGE_HEADER_V3_SIZE, BOOT_IMAGE_HEADER_V4_SIZE,
    BOOT_MAGIC, VENDOR_BOOT_IMAGE_HEADER_V3_SIZE, VENDOR_BOOT_IMAGE_HEADER_V4_SIZE,
    VENDOR_BOOT_MAGIC,
};
