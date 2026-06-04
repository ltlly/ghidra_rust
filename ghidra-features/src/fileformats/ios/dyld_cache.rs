//! Apple dyld shared cache format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.ios.dyldcache` package.
//!
//! References:
//! - dyld cache format in Apple's dyld source

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Dyld cache magic: `"dyld_v1   i386"`.
pub const DYLD_CACHE_MAGIC_32: [u8; 16] = *b"dyld_v1   i386\x00\x00";
/// Dyld cache magic: `"dyld_v1  x86_64"`.
pub const DYLD_CACHE_MAGIC_64: [u8; 16] = *b"dyld_v1  x86_64\x00";
/// Dyld cache magic: `"dyld_v1  armv5"`.
pub const DYLD_CACHE_MAGIC_ARMV5: [u8; 16] = *b"dyld_v1  armv5\x00\x00";
/// Dyld cache magic: `"dyld_v1  armv6"`.
pub const DYLD_CACHE_MAGIC_ARMV6: [u8; 16] = *b"dyld_v1  armv6\x00\x00";
/// Dyld cache magic: `"dyld_v1  armv7"`.
pub const DYLD_CACHE_MAGIC_ARMV7: [u8; 16] = *b"dyld_v1  armv7\x00\x00";
/// Dyld cache magic: `"dyld_v1 arm64  "`.
pub const DYLD_CACHE_MAGIC_ARM64: [u8; 16] = *b"dyld_v1 arm64  \x00";
/// Dyld cache magic: `"dyld_v1arm64e  "`.
pub const DYLD_CACHE_MAGIC_ARM64E: [u8; 16] = *b"dyld_v1arm64e  \x00";

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Architecture type of the dyld cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DyldCacheArch {
    I386,
    X86_64,
    ArmV5,
    ArmV6,
    ArmV7,
    Arm64,
    Arm64e,
    Unknown,
}

impl DyldCacheArch {
    pub fn from_magic(magic: &[u8; 16]) -> Self {
        match *magic {
            DYLD_CACHE_MAGIC_32 => DyldCacheArch::I386,
            DYLD_CACHE_MAGIC_64 => DyldCacheArch::X86_64,
            DYLD_CACHE_MAGIC_ARMV5 => DyldCacheArch::ArmV5,
            DYLD_CACHE_MAGIC_ARMV6 => DyldCacheArch::ArmV6,
            DYLD_CACHE_MAGIC_ARMV7 => DyldCacheArch::ArmV7,
            DYLD_CACHE_MAGIC_ARM64 => DyldCacheArch::Arm64,
            DYLD_CACHE_MAGIC_ARM64E => DyldCacheArch::Arm64e,
            _ => DyldCacheArch::Unknown,
        }
    }
}

/// Parsed dyld shared cache header.
#[derive(Debug, Clone)]
pub struct DyldCacheHeader {
    /// Magic string.
    pub magic: [u8; 16],
    /// Architecture.
    pub arch: DyldCacheArch,
    /// Number of mappings.
    pub mapping_offset: u32,
    pub mapping_count: u32,
    /// Images.
    pub images_offset: u32,
    pub images_count: u32,
    /// Dyld base address.
    pub dyld_base_address: u64,
    /// Code signature offset.
    pub code_signature_offset: u64,
    /// Code signature size.
    pub code_signature_size: u64,
    /// Slide info offset.
    pub slide_info_offset: u64,
    /// Slide info size.
    pub slide_info_size: u64,
    /// Local symbols offset.
    pub local_symbols_offset: u64,
    /// Local symbols size.
    pub local_symbols_size: u64,
    /// UUID.
    pub uuid: [u8; 16],
}

impl DyldCacheHeader {
    /// Minimum header size.
    pub const MIN_SIZE: usize = 248;

    /// Parse a dyld cache header.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::MIN_SIZE {
            return Err("Data too short for dyld cache header".to_string());
        }

        let mut magic = [0u8; 16];
        magic.copy_from_slice(&data[0..16]);

        let arch = DyldCacheArch::from_magic(&magic);
        if arch == DyldCacheArch::Unknown {
            return Err(format!("Unknown dyld cache magic: {:?}", &magic[..8]));
        }

        let mapping_offset = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let mapping_count = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let images_offset = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let images_count = u32::from_le_bytes(data[28..32].try_into().unwrap());

        // Skip some fields to reach dyld_base_address at offset 40
        let dyld_base_address = u64::from_le_bytes(data[40..48].try_into().unwrap());
        let code_signature_offset = u64::from_le_bytes(data[48..56].try_into().unwrap());
        let code_signature_size = u64::from_le_bytes(data[56..64].try_into().unwrap());
        let slide_info_offset = u64::from_le_bytes(data[64..72].try_into().unwrap());
        let slide_info_size = u64::from_le_bytes(data[72..80].try_into().unwrap());
        let local_symbols_offset = u64::from_le_bytes(data[80..88].try_into().unwrap());
        let local_symbols_size = u64::from_le_bytes(data[88..96].try_into().unwrap());

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&data[96..112]);

        Ok(DyldCacheHeader {
            magic,
            arch,
            mapping_offset,
            mapping_count,
            images_offset,
            images_count,
            dyld_base_address,
            code_signature_offset,
            code_signature_size,
            slide_info_offset,
            slide_info_size,
            local_symbols_offset,
            local_symbols_size,
            uuid,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.arch != DyldCacheArch::Unknown
    }
}

/// Check if data starts with dyld cache magic.
pub fn is_dyld_cache(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }
    let magic: [u8; 16] = data[0..16].try_into().unwrap();
    DyldCacheArch::from_magic(&magic) != DyldCacheArch::Unknown
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_detection() {
        assert!(is_dyld_cache(&DYLD_CACHE_MAGIC_ARM64));
        assert!(is_dyld_cache(&DYLD_CACHE_MAGIC_64));
        assert!(is_dyld_cache(&DYLD_CACHE_MAGIC_ARM64E));
        assert!(!is_dyld_cache(b"not a dyldcache"));
    }

    #[test]
    fn test_arch_from_magic() {
        assert_eq!(
            DyldCacheArch::from_magic(&DYLD_CACHE_MAGIC_32),
            DyldCacheArch::I386
        );
        assert_eq!(
            DyldCacheArch::from_magic(&DYLD_CACHE_MAGIC_ARM64),
            DyldCacheArch::Arm64
        );
        assert_eq!(
            DyldCacheArch::from_magic(&DYLD_CACHE_MAGIC_ARM64E),
            DyldCacheArch::Arm64e
        );
    }

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; DyldCacheHeader::MIN_SIZE];
        data[0..16].copy_from_slice(&DYLD_CACHE_MAGIC_ARM64);
        data[16..20].copy_from_slice(&160u32.to_le_bytes()); // mapping_offset
        data[20..24].copy_from_slice(&3u32.to_le_bytes()); // mapping_count
        data[24..28].copy_from_slice(&200u32.to_le_bytes()); // images_offset
        data[28..32].copy_from_slice(&100u32.to_le_bytes()); // images_count
        data[40..48].copy_from_slice(&0x180000000u64.to_le_bytes()); // dyld_base

        let hdr = DyldCacheHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.arch, DyldCacheArch::Arm64);
        assert_eq!(hdr.mapping_count, 3);
        assert_eq!(hdr.images_count, 100);
        assert_eq!(hdr.dyld_base_address, 0x180000000);
    }
}
