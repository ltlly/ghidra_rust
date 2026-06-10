//! Dyld cache mapping collections and lookup helpers.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.macho.dyld` package.
//!
//! Provides higher-level containers that manage arrays of
//! `DyldCacheMappingInfo` and `DyldCacheMappingAndSlideInfo` entries parsed
//! from the dyld shared cache.  Includes address/offset lookup, filtering by
//! protection flags, and aggregate statistics.

use super::dyld_cache_header::{
    DyldCacheMappingAndSlideInfo, DyldCacheMappingInfo,
};

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheMappings
// ═══════════════════════════════════════════════════════════════════════════════════

/// A collection of `DyldCacheMappingInfo` entries parsed from the dyld cache.
///
/// Provides helpers for looking up mappings by virtual address or file offset,
/// filtering by protection, and computing aggregate layout information.
#[derive(Debug, Clone)]
pub struct DyldCacheMappings {
    /// The parsed mapping entries.
    mappings: Vec<DyldCacheMappingInfo>,
}

impl DyldCacheMappings {
    /// Parse `count` mapping entries starting at `offset` within `cache_data`.
    pub fn parse(cache_data: &[u8], offset: u32, count: u32) -> Result<Self, String> {
        let mut mappings = Vec::with_capacity(count as usize);
        let base = offset as usize;
        for i in 0..count {
            let start = base + (i as usize) * DyldCacheMappingInfo::SIZE;
            let end = start + DyldCacheMappingInfo::SIZE;
            if end > cache_data.len() {
                return Err(format!(
                    "DyldCacheMappings: data too short at mapping index {i}"
                ));
            }
            mappings.push(DyldCacheMappingInfo::parse(&cache_data[start..end])?);
        }
        Ok(DyldCacheMappings { mappings })
    }

    /// Returns the number of mappings.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Returns true if there are no mappings.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// Returns a slice of all mappings.
    pub fn entries(&self) -> &[DyldCacheMappingInfo] {
        &self.mappings
    }

    /// Returns the mapping that contains the given virtual address, if any.
    pub fn find_by_address(&self, addr: u64) -> Option<&DyldCacheMappingInfo> {
        self.mappings
            .iter()
            .find(|m| addr >= m.address && addr < m.end_address())
    }

    /// Returns the mapping that contains the given file offset, if any.
    pub fn find_by_file_offset(&self, offset: u64) -> Option<&DyldCacheMappingInfo> {
        self.mappings
            .iter()
            .find(|m| offset >= m.file_offset && offset < m.end_file_offset())
    }

    /// Converts a virtual address to a file offset using the mapping table.
    ///
    /// Returns `None` if no mapping contains the address.
    pub fn address_to_file_offset(&self, addr: u64) -> Option<u64> {
        self.find_by_address(addr)
            .map(|m| m.file_offset + (addr - m.address))
    }

    /// Converts a file offset to a virtual address using the mapping table.
    ///
    /// Returns `None` if no mapping contains the offset.
    pub fn file_offset_to_address(&self, offset: u64) -> Option<u64> {
        self.find_by_file_offset(offset)
            .map(|m| m.address + (offset - m.file_offset))
    }

    /// Returns only mappings that are executable.
    pub fn executable_mappings(&self) -> Vec<&DyldCacheMappingInfo> {
        self.mappings.iter().filter(|m| m.is_executable()).collect()
    }

    /// Returns only mappings that are writable.
    pub fn writable_mappings(&self) -> Vec<&DyldCacheMappingInfo> {
        self.mappings.iter().filter(|m| m.is_writable()).collect()
    }

    /// Returns the lowest base address across all mappings.
    pub fn base_address(&self) -> u64 {
        self.mappings
            .iter()
            .map(|m| m.address)
            .min()
            .unwrap_or(0)
    }

    /// Returns the total span (highest end address - lowest base address).
    pub fn total_span(&self) -> u64 {
        let max_end = self
            .mappings
            .iter()
            .map(|m| m.end_address())
            .max()
            .unwrap_or(0);
        max_end.saturating_sub(self.base_address())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheMappingsAndSlide
// ═══════════════════════════════════════════════════════════════════════════════════

/// A collection of `DyldCacheMappingAndSlideInfo` entries parsed from the
/// dyld cache.
///
/// Similar to `DyldCacheMappings` but for the newer v1+ mapping-and-slide
/// format that includes slide/rebase metadata per mapping.
#[derive(Debug, Clone)]
pub struct DyldCacheMappingsAndSlide {
    /// The parsed mapping-and-slide entries.
    entries: Vec<DyldCacheMappingAndSlideInfo>,
}

impl DyldCacheMappingsAndSlide {
    /// Parse `count` mapping-and-slide entries starting at `offset` within `cache_data`.
    pub fn parse(cache_data: &[u8], offset: u32, count: u32) -> Result<Self, String> {
        let mut entries = Vec::with_capacity(count as usize);
        let base = offset as usize;
        for i in 0..count {
            let start = base + (i as usize) * DyldCacheMappingAndSlideInfo::SIZE;
            let end = start + DyldCacheMappingAndSlideInfo::SIZE;
            if end > cache_data.len() {
                return Err(format!(
                    "DyldCacheMappingsAndSlide: data too short at entry index {i}"
                ));
            }
            entries.push(DyldCacheMappingAndSlideInfo::parse(&cache_data[start..end])?);
        }
        Ok(DyldCacheMappingsAndSlide { entries })
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a slice of all entries.
    pub fn entries(&self) -> &[DyldCacheMappingAndSlideInfo] {
        &self.entries
    }

    /// Returns the entry that contains the given virtual address, if any.
    pub fn find_by_address(&self, addr: u64) -> Option<&DyldCacheMappingAndSlideInfo> {
        self.entries
            .iter()
            .find(|e| addr >= e.address && addr < e.address.saturating_add(e.size))
    }

    /// Returns the entry that contains the given file offset, if any.
    pub fn find_by_file_offset(&self, offset: u64) -> Option<&DyldCacheMappingAndSlideInfo> {
        self.entries
            .iter()
            .find(|e| offset >= e.file_offset && offset < e.file_offset.saturating_add(e.size))
    }

    /// Converts a virtual address to a file offset.
    pub fn address_to_file_offset(&self, addr: u64) -> Option<u64> {
        self.find_by_address(addr)
            .map(|e| e.file_offset + (addr - e.address))
    }

    /// Converts a file offset to a virtual address.
    pub fn file_offset_to_address(&self, offset: u64) -> Option<u64> {
        self.find_by_file_offset(offset)
            .map(|e| e.address + (offset - e.file_offset))
    }

    /// Returns only entries that have associated slide info.
    pub fn with_slide_info(&self) -> Vec<&DyldCacheMappingAndSlideInfo> {
        self.entries.iter().filter(|e| e.has_slide_info()).collect()
    }

    /// Returns only entries that are executable.
    pub fn executable_entries(&self) -> Vec<&DyldCacheMappingAndSlideInfo> {
        self.entries
            .iter()
            .filter(|e| e.init_prot & 0x4 != 0)
            .collect()
    }

    /// Returns the lowest base address across all entries.
    pub fn base_address(&self) -> u64 {
        self.entries.iter().map(|e| e.address).min().unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mapping_info(address: u64, size: u64, file_offset: u64, prot: u32) -> Vec<u8> {
        let mut data = vec![0u8; DyldCacheMappingInfo::SIZE];
        data[0..8].copy_from_slice(&address.to_le_bytes());
        data[8..16].copy_from_slice(&size.to_le_bytes());
        data[16..24].copy_from_slice(&file_offset.to_le_bytes());
        data[24..28].copy_from_slice(&7u32.to_le_bytes()); // max_prot = rwx
        data[28..32].copy_from_slice(&prot.to_le_bytes());
        data
    }

    fn make_mapping_slide_info(address: u64, size: u64, file_offset: u64, prot: u32) -> Vec<u8> {
        let mut data = vec![0u8; DyldCacheMappingAndSlideInfo::SIZE];
        data[0..8].copy_from_slice(&address.to_le_bytes());
        data[8..16].copy_from_slice(&size.to_le_bytes());
        data[16..24].copy_from_slice(&file_offset.to_le_bytes());
        data[24..28].copy_from_slice(&7u32.to_le_bytes()); // max_prot = rwx
        data[28..32].copy_from_slice(&prot.to_le_bytes());
        data
    }

    #[test]
    fn test_mappings_parse_and_lookup() {
        // Two mappings: text at 0x180000000, data at 0x181000000
        let mut cache = vec![0u8; 512];
        let m1 = make_mapping_info(0x180000000, 0x100000, 0x4000, 5); // r-x
        let m2 = make_mapping_info(0x181000000, 0x80000, 0x104000, 3); // rw-
        cache[0..32].copy_from_slice(&m1);
        cache[32..64].copy_from_slice(&m2);

        let mappings = DyldCacheMappings::parse(&cache, 0, 2).unwrap();
        assert_eq!(mappings.len(), 2);

        let found = mappings.find_by_address(0x180050000).unwrap();
        assert_eq!(found.address, 0x180000000);
        assert!(found.is_executable());
        assert!(!found.is_writable());

        // Address-to-file-offset
        let foff = mappings.address_to_file_offset(0x180010000).unwrap();
        assert_eq!(foff, 0x4000 + 0x10000);

        // Reverse lookup
        let addr = mappings.file_offset_to_address(0x104000).unwrap();
        assert_eq!(addr, 0x181000000);

        assert_eq!(mappings.executable_mappings().len(), 1);
        assert_eq!(mappings.writable_mappings().len(), 1);
    }

    #[test]
    fn test_mappings_and_slide_parse() {
        let mut cache = vec![0u8; 256];
        let e1 = make_mapping_slide_info(0x180000000, 0x100000, 0x4000, 5);
        cache[0..64].copy_from_slice(&e1);

        let ms = DyldCacheMappingsAndSlide::parse(&cache, 0, 1).unwrap();
        assert_eq!(ms.len(), 1);
        assert_eq!(ms.base_address(), 0x180000000);
        assert_eq!(ms.executable_entries().len(), 1);
    }

    #[test]
    fn test_mappings_truncated() {
        let cache = vec![0u8; 10];
        assert!(DyldCacheMappings::parse(&cache, 0, 1).is_err());
    }

    #[test]
    fn test_mappings_empty() {
        let cache = vec![0u8; 0];
        let mappings = DyldCacheMappings::parse(&cache, 0, 0).unwrap();
        assert!(mappings.is_empty());
        assert_eq!(mappings.base_address(), 0);
        assert_eq!(mappings.total_span(), 0);
    }
}
