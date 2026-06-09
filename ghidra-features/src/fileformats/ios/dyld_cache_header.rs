//! Dyld cache sub-header structures.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.macho.dyld` package.
//!
//! Covers `dyld_cache_image_info`, `dyld_cache_mapping_info`,
//! `dyld_cache_mapping_and_slide_info`, and related entry-level structures
//! that live inside the dyld shared cache after the top-level header.

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Mapping Info
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_mapping_info` structure.
///
/// Each mapping describes a contiguous region of the cache file mapped into
/// memory with specific permissions.
#[derive(Debug, Clone)]
pub struct DyldCacheMappingInfo {
    /// Memory address this mapping is loaded at.
    pub address: u64,
    /// Size of the mapping in memory.
    pub size: u64,
    /// File offset of the mapping data.
    pub file_offset: u64,
    /// Maximum protection (rwx) flags.
    pub max_prot: u32,
    /// Initial protection (rwx) flags.
    pub init_prot: u32,
}

impl DyldCacheMappingInfo {
    /// Size of the on-disk structure (32 bytes).
    pub const SIZE: usize = 32;

    /// Parse from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for DyldCacheMappingInfo".to_string());
        }

        let address = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let file_offset = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let max_prot = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let init_prot = u32::from_le_bytes(data[28..32].try_into().unwrap());

        Ok(DyldCacheMappingInfo {
            address,
            size,
            file_offset,
            max_prot,
            init_prot,
        })
    }

    /// Returns true if this mapping is readable.
    pub fn is_readable(&self) -> bool {
        self.init_prot & 0x1 != 0
    }

    /// Returns true if this mapping is writable.
    pub fn is_writable(&self) -> bool {
        self.init_prot & 0x2 != 0
    }

    /// Returns true if this mapping is executable.
    pub fn is_executable(&self) -> bool {
        self.init_prot & 0x4 != 0
    }

    /// Returns the end address (address + size).
    pub fn end_address(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    /// Returns the end file offset (file_offset + size).
    pub fn end_file_offset(&self) -> u64 {
        self.file_offset.saturating_add(self.size)
    }

    /// Returns a human-readable protection string (e.g., "r-x").
    pub fn prot_string(&self) -> String {
        let r = if self.init_prot & 0x1 != 0 { 'r' } else { '-' };
        let w = if self.init_prot & 0x2 != 0 { 'w' } else { '-' };
        let x = if self.init_prot & 0x4 != 0 { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Mapping And Slide Info
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_mapping_and_slide_info` structure (v1+).
///
/// Extends `MappingInfo` with slide-info metadata used by modern dyld caches
/// to describe pointer authentication and slide information.
#[derive(Debug, Clone)]
pub struct DyldCacheMappingAndSlideInfo {
    /// Memory address this mapping is loaded at.
    pub address: u64,
    /// Size of the mapping in memory.
    pub size: u64,
    /// File offset of the mapping data.
    pub file_offset: u64,
    /// Maximum protection (rwx) flags.
    pub max_prot: u32,
    /// Initial protection (rwx) flags.
    pub init_prot: u32,
    /// Slide info file offset (0 if no slide info).
    pub slide_info_file_offset: u64,
    /// Slide info size (0 if no slide info).
    pub slide_info_file_size: u64,
    /// Flags for this mapping.
    pub flags: u64,
}

impl DyldCacheMappingAndSlideInfo {
    /// Size of the on-disk structure (64 bytes).
    pub const SIZE: usize = 64;

    /// Parse from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for DyldCacheMappingAndSlideInfo".to_string());
        }

        let address = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let file_offset = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let max_prot = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let init_prot = u32::from_le_bytes(data[28..32].try_into().unwrap());
        let slide_info_file_offset = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let slide_info_file_size = u64::from_le_bytes(data[40..48].try_into().unwrap());
        let flags = u64::from_le_bytes(data[48..56].try_into().unwrap());

        Ok(DyldCacheMappingAndSlideInfo {
            address,
            size,
            file_offset,
            max_prot,
            init_prot,
            slide_info_file_offset,
            slide_info_file_size,
            flags,
        })
    }

    /// Returns true if this mapping has associated slide info.
    pub fn has_slide_info(&self) -> bool {
        self.slide_info_file_offset != 0 && self.slide_info_file_size != 0
    }

    /// Returns a human-readable protection string.
    pub fn prot_string(&self) -> String {
        let r = if self.init_prot & 0x1 != 0 { 'r' } else { '-' };
        let w = if self.init_prot & 0x2 != 0 { 'w' } else { '-' };
        let x = if self.init_prot & 0x4 != 0 { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Local Symbols Entry
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_local_symbols_entry` structure.
///
/// Describes local (non-exported) symbol information for a single image
/// within the dyld cache.
#[derive(Debug, Clone)]
pub struct DyldCacheLocalSymbolsEntry {
    /// The dylib ordinal (index in the images array).
    pub dylib_ordinal: u32,
    /// Number of nlist entries for this image.
    pub nlist_count: u32,
    /// Index into the local nlist array.
    pub nlist_start_index: u32,
    /// Number of strings for this image.
    pub strings_count: u32,
    /// Offset into the local strings table.
    pub strings_offset: u64,
}

impl DyldCacheLocalSymbolsEntry {
    /// Size of the on-disk structure (24 bytes).
    pub const SIZE: usize = 24;

    /// Parse from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for DyldCacheLocalSymbolsEntry".to_string());
        }

        let dylib_ordinal = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let nlist_count = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let nlist_start_index = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let strings_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let strings_offset = u64::from_le_bytes(data[16..24].try_into().unwrap());

        Ok(DyldCacheLocalSymbolsEntry {
            dylib_ordinal,
            nlist_count,
            nlist_start_index,
            strings_count,
            strings_offset,
        })
    }

    /// Returns true if this entry has local symbols.
    pub fn has_symbols(&self) -> bool {
        self.nlist_count > 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Range Entry
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_range_entry` structure.
///
/// Describes a contiguous address range within the dyld cache.
#[derive(Debug, Clone)]
pub struct DyldCacheRangeEntry {
    /// Start address of the range.
    pub address: u64,
    /// Size of the range in bytes.
    pub size: u64,
}

impl DyldCacheRangeEntry {
    /// Size of the on-disk structure (16 bytes).
    pub const SIZE: usize = 16;

    /// Parse from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for DyldCacheRangeEntry".to_string());
        }

        let address = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(data[8..16].try_into().unwrap());

        Ok(DyldCacheRangeEntry { address, size })
    }

    /// Returns the end address (address + size).
    pub fn end_address(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    /// Returns true if the given address falls within this range.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.end_address()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Dyld Cache Accelerate Info
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `dyld_cache_accelerator_info` structure.
///
/// Contains metadata used by dyld to speed up image loading, including
/// batch rebase and binding information.
#[derive(Debug, Clone)]
pub struct DyldCacheAccelerateInfo {
    /// Version of the accelerator info format.
    pub version: u32,
    /// Image extras count.
    pub image_extras_count: u32,
    /// Image extras offset.
    pub image_extras_offset: u64,
    /// Bottom-up rebase info offset.
    pub bottom_up_list_offset: u64,
    /// Bottom-up rebase info size.
    pub bottom_up_list_size: u64,
    /// Dylib trie offset.
    pub dylib_trie_offset: u64,
    /// Dylib trie size.
    pub dylib_trie_size: u64,
    /// Initializers offset.
    pub initializers_offset: u64,
    /// Initializers size.
    pub initializers_size: u64,
    /// DOFs offset.
    pub dofs_offset: u64,
    /// DOFs count.
    pub dofs_count: u32,
    /// Rebase info offset.
    pub rebase_info_offset: u64,
    /// Rebase info size.
    pub rebase_info_size: u64,
    /// Binding info offset.
    pub binding_info_offset: u64,
    /// Binding info size.
    pub binding_info_size: u64,
}

impl DyldCacheAccelerateInfo {
    /// Minimum size of the on-disk structure.
    pub const MIN_SIZE: usize = 104;

    /// Parse from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::MIN_SIZE {
            return Err("Data too short for DyldCacheAccelerateInfo".to_string());
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let image_extras_count = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let image_extras_offset = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let bottom_up_list_offset = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let bottom_up_list_size = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let dylib_trie_offset = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let dylib_trie_size = u64::from_le_bytes(data[40..48].try_into().unwrap());
        let initializers_offset = u64::from_le_bytes(data[48..56].try_into().unwrap());
        let initializers_size = u64::from_le_bytes(data[56..64].try_into().unwrap());
        let dofs_offset = u64::from_le_bytes(data[64..72].try_into().unwrap());
        let dofs_count = u32::from_le_bytes(data[72..76].try_into().unwrap());
        let rebase_info_offset = u64::from_le_bytes(data[76..84].try_into().unwrap());
        let rebase_info_size = u64::from_le_bytes(data[84..92].try_into().unwrap());
        let binding_info_offset = u64::from_le_bytes(data[92..100].try_into().unwrap());
        let binding_info_size = u64::from_le_bytes(data[100..108]
            .get(..8)
            .ok_or("Data too short for binding_info_size")?
            .try_into()
            .unwrap());

        Ok(DyldCacheAccelerateInfo {
            version,
            image_extras_count,
            image_extras_offset,
            bottom_up_list_offset,
            bottom_up_list_size,
            dylib_trie_offset,
            dylib_trie_size,
            initializers_offset,
            initializers_size,
            dofs_offset,
            dofs_count,
            rebase_info_offset,
            rebase_info_size,
            binding_info_offset,
            binding_info_size,
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
    fn test_mapping_info_parse() {
        let mut data = vec![0u8; DyldCacheMappingInfo::SIZE];
        data[0..8].copy_from_slice(&0x180000000u64.to_le_bytes()); // address
        data[8..16].copy_from_slice(&0x200000u64.to_le_bytes()); // size
        data[16..24].copy_from_slice(&0x4000u64.to_le_bytes()); // file_offset
        data[24..28].copy_from_slice(&7u32.to_le_bytes()); // max_prot = rwx
        data[28..32].copy_from_slice(&5u32.to_le_bytes()); // init_prot = r-x

        let mapping = DyldCacheMappingInfo::parse(&data).unwrap();
        assert_eq!(mapping.address, 0x180000000);
        assert_eq!(mapping.size, 0x200000);
        assert!(mapping.is_readable());
        assert!(!mapping.is_writable());
        assert!(mapping.is_executable());
        assert_eq!(mapping.prot_string(), "r-x");
        assert_eq!(mapping.end_address(), 0x180200000);
    }

    #[test]
    fn test_mapping_and_slide_info_parse() {
        let mut data = vec![0u8; DyldCacheMappingAndSlideInfo::SIZE];
        data[0..8].copy_from_slice(&0x180000000u64.to_le_bytes());
        data[8..16].copy_from_slice(&0x100000u64.to_le_bytes());
        data[16..24].copy_from_slice(&0x4000u64.to_le_bytes());
        data[24..28].copy_from_slice(&7u32.to_le_bytes());
        data[28..32].copy_from_slice(&5u32.to_le_bytes());
        data[32..40].copy_from_slice(&0x1000u64.to_le_bytes()); // slide_info_file_offset

        let info = DyldCacheMappingAndSlideInfo::parse(&data).unwrap();
        assert_eq!(info.address, 0x180000000);
        assert!(info.has_slide_info());
    }

    #[test]
    fn test_local_symbols_entry_parse() {
        let mut data = vec![0u8; DyldCacheLocalSymbolsEntry::SIZE];
        data[0..4].copy_from_slice(&42u32.to_le_bytes()); // dylib_ordinal
        data[4..8].copy_from_slice(&100u32.to_le_bytes()); // nlist_count
        data[8..12].copy_from_slice(&50u32.to_le_bytes()); // nlist_start_index
        data[12..16].copy_from_slice(&200u32.to_le_bytes()); // strings_count
        data[16..24].copy_from_slice(&0x8000u64.to_le_bytes()); // strings_offset

        let entry = DyldCacheLocalSymbolsEntry::parse(&data).unwrap();
        assert_eq!(entry.dylib_ordinal, 42);
        assert_eq!(entry.nlist_count, 100);
        assert!(entry.has_symbols());
    }

    #[test]
    fn test_range_entry_parse() {
        let mut data = vec![0u8; DyldCacheRangeEntry::SIZE];
        data[0..8].copy_from_slice(&0x180000000u64.to_le_bytes());
        data[8..16].copy_from_slice(&0x1000u64.to_le_bytes());

        let range = DyldCacheRangeEntry::parse(&data).unwrap();
        assert!(range.contains(0x180000000));
        assert!(range.contains(0x180000FFF));
        assert!(!range.contains(0x180001000));
        assert!(!range.contains(0x17FFFFFFF));
    }

    #[test]
    fn test_mapping_info_truncated() {
        let data = vec![0u8; 10];
        assert!(DyldCacheMappingInfo::parse(&data).is_err());
    }
}
