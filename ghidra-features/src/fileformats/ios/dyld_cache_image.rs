//! Dyld cache image info structures.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.macho.dyld` package.
//!
//! Each image entry in the dyld shared cache points to a Mach-O dylib
//! loaded at a specific address.  The structures here describe those
//! entries and provide helpers for resolving image paths.

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Image Info
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_image_info` structure.
///
/// This is the fundamental per-image entry in the dyld shared cache.
/// It records the load address, filesystem metadata, and a pointer to
/// the image's install path (stored as a C string elsewhere in the cache).
#[derive(Debug, Clone)]
pub struct DyldCacheImageInfo {
    /// Memory address where the image is loaded.
    pub address: u64,
    /// Modification time (mtime) of the original dylib on disk.
    pub mod_time: u64,
    /// Inode of the original dylib on disk.
    pub inode: u64,
    /// File offset to the null-terminated path string within the cache.
    pub path_file_offset: u32,
    /// Padding (always zero).
    pub pad: u32,
    /// The resolved image path (parsed from the cache at `path_file_offset`).
    pub path: String,
}

impl DyldCacheImageInfo {
    /// Size of the on-disk structure (32 bytes, excluding the path string).
    pub const SIZE: usize = 32;

    /// Parse from a byte slice.
    ///
    /// `path_file_offset` is read from the data, but the path string itself
    /// must be resolved separately from the full cache blob.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for DyldCacheImageInfo".to_string());
        }

        let address = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let mod_time = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let inode = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let path_file_offset = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let pad = u32::from_le_bytes(data[28..32].try_into().unwrap());

        Ok(DyldCacheImageInfo {
            address,
            mod_time,
            inode,
            path_file_offset,
            pad,
            path: String::new(),
        })
    }

    /// Parse from a byte slice and resolve the image path from the cache.
    ///
    /// `cache_data` must be the entire dyld cache blob.  The path is read
    /// as a NUL-terminated ASCII string starting at `path_file_offset`.
    pub fn parse_with_path(cache_data: &[u8], data: &[u8]) -> Result<Self, String> {
        let mut info = Self::parse(data)?;
        info.resolve_path(cache_data);
        Ok(info)
    }

    /// Resolve the path string from the cache data.
    pub fn resolve_path(&mut self, cache_data: &[u8]) {
        let offset = self.path_file_offset as usize;
        if offset >= cache_data.len() {
            self.path = String::new();
            return;
        }
        // Read NUL-terminated ASCII string
        let end = cache_data[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| offset + p)
            .unwrap_or(cache_data.len());
        self.path = String::from_utf8_lossy(&cache_data[offset..end]).to_string();
    }

    /// Returns the dylib name (last component of the path).
    pub fn name(&self) -> &str {
        self.path
            .rsplit('/')
            .next()
            .unwrap_or(&self.path)
    }

    /// Returns true if this is a framework image.
    pub fn is_framework(&self) -> bool {
        self.path.contains(".framework/")
    }

    /// Returns true if this is a system dylib.
    pub fn is_system_dylib(&self) -> bool {
        self.path.starts_with("/usr/lib/") || self.path.starts_with("/System/Library/")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Image Info Extra
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_image_info_extra` structure.
///
/// Extended image info added in later cache format versions.  Provides
/// additional metadata such as the image's UUID and more precise load info.
#[derive(Debug, Clone)]
pub struct DyldCacheImageInfoExtra {
    /// Dylib format version (cd_version).
    pub cd_hash: [u8; 20],
    /// Image string file offset (alternative path in newer formats).
    pub image_file_offset: u64,
    /// Image pointer auth (ptrauth) info.
    pub ptrauth_image_key: u64,
}

impl DyldCacheImageInfoExtra {
    /// Size of the on-disk structure (36 bytes).
    pub const SIZE: usize = 36;

    /// Parse from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for DyldCacheImageInfoExtra".to_string());
        }

        let mut cd_hash = [0u8; 20];
        cd_hash.copy_from_slice(&data[0..20]);

        let image_file_offset = u64::from_le_bytes(data[20..28].try_into().unwrap());
        let ptrauth_image_key = u64::from_le_bytes(data[28..36].try_into().unwrap());

        Ok(DyldCacheImageInfoExtra {
            cd_hash,
            image_file_offset,
            ptrauth_image_key,
        })
    }

    /// Returns the cd_hash as a hex string.
    pub fn cd_hash_hex(&self) -> String {
        self.cd_hash.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Image Text Info
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_image_text_info` structure.
///
/// Text-segment metadata for an image, used for ASLR slide computation
/// and code-signing validation.
#[derive(Debug, Clone)]
pub struct DyldCacheImageTextInfo {
    /// UUID of the image.
    pub uuid: [u8; 16],
    /// Image load address (unslid).
    pub load_address: u64,
    /// Image text segment file offset.
    pub text_offset: u32,
    /// Image text segment size.
    pub text_size: u32,
}

impl DyldCacheImageTextInfo {
    /// Size of the on-disk structure (32 bytes).
    pub const SIZE: usize = 32;

    /// Parse from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for DyldCacheImageTextInfo".to_string());
        }

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&data[0..16]);

        let load_address = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let text_offset = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let text_size = u32::from_le_bytes(data[28..32].try_into().unwrap());

        Ok(DyldCacheImageTextInfo {
            uuid,
            load_address,
            text_offset,
            text_size,
        })
    }

    /// Returns the UUID as a formatted string.
    pub fn uuid_string(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3],
            self.uuid[4], self.uuid[5],
            self.uuid[6], self.uuid[7],
            self.uuid[8], self.uuid[9],
            self.uuid[10], self.uuid[11], self.uuid[12], self.uuid[13],
            self.uuid[14], self.uuid[15]
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Accelerator Initializer
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_accelerator_initializer` structure.
///
/// Describes an initializer function that dyld must call during image
/// loading (e.g., `__attribute__((constructor))` or C++ static initializers).
#[derive(Debug, Clone)]
pub struct DyldCacheAcceleratorInitializer {
    /// Image index in the images array.
    pub image_index: u32,
    /// File offset of the initializer.
    pub initializer_file_offset: u64,
}

impl DyldCacheAcceleratorInitializer {
    /// Size of the on-disk structure (12 bytes).
    pub const SIZE: usize = 12;

    /// Parse from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for DyldCacheAcceleratorInitializer".to_string());
        }

        let image_index = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let initializer_file_offset = u64::from_le_bytes(data[4..12].try_into().unwrap());

        Ok(DyldCacheAcceleratorInitializer {
            image_index,
            initializer_file_offset,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Accelerator DOF
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_accelerator_dof` structure.
///
/// Describes a DTrace USDT probe section (DOF) within a cached image.
#[derive(Debug, Clone)]
pub struct DyldCacheAcceleratorDof {
    /// Image index in the images array.
    pub image_index: u32,
    /// File offset of the DOF section.
    pub dof_file_offset: u64,
    /// Size of the DOF section.
    pub dof_size: u64,
}

impl DyldCacheAcceleratorDof {
    /// Size of the on-disk structure (20 bytes).
    pub const SIZE: usize = 20;

    /// Parse from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for DyldCacheAcceleratorDof".to_string());
        }

        let image_index = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let dof_file_offset = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let dof_size = u64::from_le_bytes(data[12..20].try_into().unwrap());

        Ok(DyldCacheAcceleratorDof {
            image_index,
            dof_file_offset,
            dof_size,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_info_parse() {
        let mut data = vec![0u8; DyldCacheImageInfo::SIZE];
        data[0..8].copy_from_slice(&0x180040000u64.to_le_bytes()); // address
        data[8..16].copy_from_slice(&0x1234u64.to_le_bytes()); // mod_time
        data[16..24].copy_from_slice(&5678u64.to_le_bytes()); // inode
        data[24..28].copy_from_slice(&0x1000u32.to_le_bytes()); // path_file_offset

        let info = DyldCacheImageInfo::parse(&data).unwrap();
        assert_eq!(info.address, 0x180040000);
        assert_eq!(info.path_file_offset, 0x1000);
        assert!(info.path.is_empty());
    }

    #[test]
    fn test_image_info_with_path() {
        let mut data = vec![0u8; DyldCacheImageInfo::SIZE];
        data[0..8].copy_from_slice(&0x180040000u64.to_le_bytes());
        data[24..28].copy_from_slice(&0x100u32.to_le_bytes()); // path_file_offset = 0x100

        // Build a mock cache with the path at offset 0x100
        let mut cache = vec![0u8; 0x200];
        let path = b"/usr/lib/system/libsystem_c.dylib\0";
        cache[0x100..0x100 + path.len()].copy_from_slice(path);

        let info = DyldCacheImageInfo::parse_with_path(&cache, &data).unwrap();
        assert_eq!(info.path, "/usr/lib/system/libsystem_c.dylib");
        assert_eq!(info.name(), "libsystem_c.dylib");
        assert!(info.is_system_dylib());
        assert!(!info.is_framework());
    }

    #[test]
    fn test_image_info_framework_detection() {
        let mut info = DyldCacheImageInfo {
            address: 0,
            mod_time: 0,
            inode: 0,
            path_file_offset: 0,
            pad: 0,
            path: "/System/Library/Frameworks/UIKit.framework/UIKit".to_string(),
        };
        assert!(info.is_framework());
        assert!(info.is_system_dylib());

        info.path = "/usr/lib/libobjc.A.dylib".to_string();
        assert!(!info.is_framework());
        assert!(info.is_system_dylib());
    }

    #[test]
    fn test_image_info_extra_parse() {
        let mut data = vec![0u8; DyldCacheImageInfoExtra::SIZE];
        data[20..28].copy_from_slice(&0x2000u64.to_le_bytes()); // image_file_offset

        let extra = DyldCacheImageInfoExtra::parse(&data).unwrap();
        assert_eq!(extra.image_file_offset, 0x2000);
        assert_eq!(extra.cd_hash_hex(), "00".repeat(20));
    }

    #[test]
    fn test_image_text_info_parse() {
        let mut data = vec![0u8; DyldCacheImageTextInfo::SIZE];
        data[0..16].copy_from_slice(&[
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        ]);
        data[16..24].copy_from_slice(&0x180040000u64.to_le_bytes());
        data[24..28].copy_from_slice(&0x1000u32.to_le_bytes());
        data[28..32].copy_from_slice(&0x50000u32.to_le_bytes());

        let info = DyldCacheImageTextInfo::parse(&data).unwrap();
        assert_eq!(info.load_address, 0x180040000);
        assert_eq!(info.text_size, 0x50000);
        assert_eq!(
            info.uuid_string(),
            "aabbccdd-eeff-0011-2233-445566778899"
        );
    }

    #[test]
    fn test_accelerator_initializer_parse() {
        let mut data = vec![0u8; DyldCacheAcceleratorInitializer::SIZE];
        data[0..4].copy_from_slice(&5u32.to_le_bytes()); // image_index
        data[4..12].copy_from_slice(&0x8000u64.to_le_bytes());

        let init = DyldCacheAcceleratorInitializer::parse(&data).unwrap();
        assert_eq!(init.image_index, 5);
        assert_eq!(init.initializer_file_offset, 0x8000);
    }

    #[test]
    fn test_accelerator_dof_parse() {
        let mut data = vec![0u8; DyldCacheAcceleratorDof::SIZE];
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..12].copy_from_slice(&0x4000u64.to_le_bytes());
        data[12..20].copy_from_slice(&0x1000u64.to_le_bytes());

        let dof = DyldCacheAcceleratorDof::parse(&data).unwrap();
        assert_eq!(dof.image_index, 3);
        assert_eq!(dof.dof_size, 0x1000);
    }

    #[test]
    fn test_image_info_truncated() {
        let data = vec![0u8; 10];
        assert!(DyldCacheImageInfo::parse(&data).is_err());
    }
}
