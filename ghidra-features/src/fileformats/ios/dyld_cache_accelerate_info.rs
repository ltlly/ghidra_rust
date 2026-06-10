//! Dyld cache accelerate info with sub-structure parsing.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.macho.dyld.DyldCacheAccelerateInfo`.
//!
//! The accelerate info header contains offsets into the cache file where
//! various acceleration tables live.  This module provides
//! `DyldCacheAccelerateInfoTable` which parses the header *and* all
//! referenced sub-structures in a single pass:
//!
//! - `DyldCacheImageInfoExtra` entries
//! - `DyldCacheAcceleratorInitializer` entries
//! - `DyldCacheAcceleratorDof` entries
//! - `DyldCacheRangeEntry` entries

use super::dyld_cache_header::DyldCacheAccelerateInfo;
use super::dyld_cache_image::{
    DyldCacheAcceleratorDof, DyldCacheAcceleratorInitializer,
    DyldCacheImageInfoExtra,
};
use super::dyld_cache_header::DyldCacheRangeEntry;

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheAccelerateInfoTable
// ═══════════════════════════════════════════════════════════════════════════════════

/// A fully-parsed accelerate info block from the dyld shared cache.
///
/// Wraps the base `DyldCacheAccelerateInfo` header and all sub-structures
/// it references.  The `parse` method reads the header, then follows each
/// offset/count pair to populate the sub-structure vectors.
#[derive(Debug, Clone)]
pub struct DyldCacheAccelerateInfoTable {
    /// The parsed header.
    pub header: DyldCacheAccelerateInfo,
    /// Image info extras (indexed same as the images array).
    pub image_info_extras: Vec<DyldCacheImageInfoExtra>,
    /// Accelerator initializer entries.
    pub initializers: Vec<DyldCacheAcceleratorInitializer>,
    /// Accelerator DOF (DTrace) entries.
    pub dofs: Vec<DyldCacheAcceleratorDof>,
    /// Range entries.
    pub range_entries: Vec<DyldCacheRangeEntry>,
}

impl DyldCacheAccelerateInfoTable {
    /// Actual on-disk size of `dyld_cache_accelerator_info` (the last field,
    /// `binding_info_size`, extends 4 bytes past `MIN_SIZE`).
    const ACTUAL_SIZE: usize = 108;

    /// Parse the accelerate info header and all referenced sub-structures
    /// from `cache_data`.
    ///
    /// `offset` is the file offset of the `dyld_cache_accelerator_info`
    /// structure within the cache.
    pub fn parse(cache_data: &[u8], offset: u64) -> Result<Self, String> {
        let off = offset as usize;
        let end = off + Self::ACTUAL_SIZE;
        if end > cache_data.len() {
            return Err("DyldCacheAccelerateInfoTable: data too short for header".to_string());
        }
        let header = DyldCacheAccelerateInfo::parse(&cache_data[off..end])?;

        let image_info_extras = Self::parse_sub_array::<DyldCacheImageInfoExtra>(
            cache_data,
            header.image_extras_offset,
            header.image_extras_count as u64,
            DyldCacheImageInfoExtra::SIZE,
            "DyldCacheImageInfoExtra",
        )?;

        let initializers = Self::parse_sub_array::<DyldCacheAcceleratorInitializer>(
            cache_data,
            header.initializers_offset,
            header.initializers_size,
            DyldCacheAcceleratorInitializer::SIZE,
            "DyldCacheAcceleratorInitializer",
        )?;

        let dofs = Self::parse_sub_array::<DyldCacheAcceleratorDof>(
            cache_data,
            header.dofs_offset,
            header.dofs_count as u64,
            DyldCacheAcceleratorDof::SIZE,
            "DyldCacheAcceleratorDof",
        )?;

        let range_entries = Self::parse_sub_array::<DyldCacheRangeEntry>(
            cache_data,
            header.rebase_info_offset, // Note: range table is separate in original Java
            0, // count depends on format version; caller may override
            DyldCacheRangeEntry::SIZE,
            "DyldCacheRangeEntry",
        )?;

        Ok(DyldCacheAccelerateInfoTable {
            header,
            image_info_extras,
            initializers,
            dofs,
            range_entries,
        })
    }

    /// Parse the accelerate info, using explicit range-table offset/count
    /// (needed because the header v1 layout maps range table separately).
    pub fn parse_with_ranges(
        cache_data: &[u8],
        offset: u64,
        range_table_offset: u32,
        range_table_count: u32,
    ) -> Result<Self, String> {
        let off = offset as usize;
        let end = off + Self::ACTUAL_SIZE;
        if end > cache_data.len() {
            return Err("DyldCacheAccelerateInfoTable: data too short for header".to_string());
        }
        let header = DyldCacheAccelerateInfo::parse(&cache_data[off..end])?;

        let image_info_extras = Self::parse_sub_array::<DyldCacheImageInfoExtra>(
            cache_data,
            header.image_extras_offset,
            header.image_extras_count as u64,
            DyldCacheImageInfoExtra::SIZE,
            "DyldCacheImageInfoExtra",
        )?;

        let initializers = Self::parse_sub_array::<DyldCacheAcceleratorInitializer>(
            cache_data,
            header.initializers_offset,
            header.initializers_size,
            DyldCacheAcceleratorInitializer::SIZE,
            "DyldCacheAcceleratorInitializer",
        )?;

        let dofs = Self::parse_sub_array::<DyldCacheAcceleratorDof>(
            cache_data,
            header.dofs_offset,
            header.dofs_count as u64,
            DyldCacheAcceleratorDof::SIZE,
            "DyldCacheAcceleratorDof",
        )?;

        let range_entries = Self::parse_sub_array::<DyldCacheRangeEntry>(
            cache_data,
            range_table_offset as u64,
            range_table_count as u64,
            DyldCacheRangeEntry::SIZE,
            "DyldCacheRangeEntry",
        )?;

        Ok(DyldCacheAccelerateInfoTable {
            header,
            image_info_extras,
            initializers,
            dofs,
            range_entries,
        })
    }

    /// Returns the number of image info extras.
    pub fn image_extras_count(&self) -> usize {
        self.image_info_extras.len()
    }

    /// Returns the number of initializer entries.
    pub fn initializer_count(&self) -> usize {
        self.initializers.len()
    }

    /// Returns the number of DOF entries.
    pub fn dof_count(&self) -> usize {
        self.dofs.len()
    }

    /// Returns the number of range entries.
    pub fn range_count(&self) -> usize {
        self.range_entries.len()
    }

    /// Find the image info extra at the given index.
    pub fn image_info_extra(&self, index: usize) -> Option<&DyldCacheImageInfoExtra> {
        self.image_info_extras.get(index)
    }

    /// Find the initializer at the given index.
    pub fn initializer(&self, index: usize) -> Option<&DyldCacheAcceleratorInitializer> {
        self.initializers.get(index)
    }

    /// Find all range entries that contain the given address.
    pub fn ranges_containing(&self, addr: u64) -> Vec<&DyldCacheRangeEntry> {
        self.range_entries
            .iter()
            .filter(|r| r.contains(addr))
            .collect()
    }

    /// Generic helper: parse `count` items of `item_size` bytes each starting
    /// at `sub_offset` in `cache_data`.
    fn parse_sub_array<T>(
        cache_data: &[u8],
        sub_offset: u64,
        count: u64,
        item_size: usize,
        name: &str,
    ) -> Result<Vec<T>, String>
    where
        T: Parseable,
    {
        let mut items = Vec::with_capacity(count as usize);
        let base = sub_offset as usize;
        for i in 0..count as usize {
            let start = base + i * item_size;
            let end = start + item_size;
            if end > cache_data.len() {
                return Err(format!(
                    "{name}: data too short at index {i} (need {end}, have {})",
                    cache_data.len()
                ));
            }
            items.push(T::from_bytes(&cache_data[start..end])?);
        }
        Ok(items)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Parseable trait
// ═══════════════════════════════════════════════════════════════════════════════════

/// Trait for types that can be parsed from a fixed-size byte slice.
trait Parseable: Sized {
    fn from_bytes(data: &[u8]) -> Result<Self, String>;
}

impl Parseable for DyldCacheImageInfoExtra {
    fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::parse(data)
    }
}

impl Parseable for DyldCacheAcceleratorInitializer {
    fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::parse(data)
    }
}

impl Parseable for DyldCacheAcceleratorDof {
    fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::parse(data)
    }
}

impl Parseable for DyldCacheRangeEntry {
    fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::parse(data)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accelerate_info_table_parse_with_ranges() {
        // Build a minimal cache blob with the accelerate info header at offset 0,
        // followed by sub-structures at their referenced offsets.
        //
        // Header layout (104 bytes):
        //   0..4:   version (1)
        //   4..8:   image_extras_count (1)
        //   8..16:  image_extras_offset (256)
        //   16..24: bottom_up_list_offset (0)
        //   24..32: bottom_up_list_size (0)
        //   32..40: dylib_trie_offset (0)
        //   40..48: dylib_trie_size (0)
        //   48..56: initializers_offset (300)
        //   56..64: initializers_size (1) -- count = 1
        //   64..72: dofs_offset (320)
        //   72..76: dofs_count (1)
        //   76..84: rebase_info_offset (0)
        //   84..92: rebase_info_size (0)
        //   92..100: binding_info_offset (0)
        //   100..108: binding_info_size (0)
        //
        // ImageInfoExtra at 256: 36 bytes
        // AcceleratorInitializer at 300: 12 bytes
        // AcceleratorDof at 320: 20 bytes
        // RangeEntry at 400: 16 bytes (via parse_with_ranges)

        let mut cache = vec![0u8; 512];

        // Header
        cache[0..4].copy_from_slice(&1u32.to_le_bytes()); // version
        cache[4..8].copy_from_slice(&1u32.to_le_bytes()); // image_extras_count
        cache[8..16].copy_from_slice(&256u64.to_le_bytes()); // image_extras_offset
        cache[48..56].copy_from_slice(&300u64.to_le_bytes()); // initializers_offset
        cache[56..64].copy_from_slice(&1u64.to_le_bytes()); // initializers_size (1 entry)
        cache[64..72].copy_from_slice(&320u64.to_le_bytes()); // dofs_offset
        cache[72..76].copy_from_slice(&1u32.to_le_bytes()); // dofs_count

        // ImageInfoExtra at 256 (36 bytes)
        cache[276..284].copy_from_slice(&0xF000u64.to_le_bytes()); // image_file_offset

        // AcceleratorInitializer at 300 (12 bytes)
        cache[300..304].copy_from_slice(&42u32.to_le_bytes()); // image_index
        cache[304..312].copy_from_slice(&0x8000u64.to_le_bytes()); // initializer offset

        // AcceleratorDof at 320 (20 bytes)
        cache[320..324].copy_from_slice(&7u32.to_le_bytes()); // image_index
        cache[324..332].copy_from_slice(&0x4000u64.to_le_bytes()); // dof offset
        cache[332..340].copy_from_slice(&0x2000u64.to_le_bytes()); // dof size

        // RangeEntry at 400 (16 bytes)
        cache[400..408].copy_from_slice(&0x180000000u64.to_le_bytes()); // address
        cache[408..416].copy_from_slice(&0x10000u64.to_le_bytes()); // size

        let table =
            DyldCacheAccelerateInfoTable::parse_with_ranges(&cache, 0, 400, 1).unwrap();

        assert_eq!(table.header.version, 1);
        assert_eq!(table.image_extras_count(), 1);
        assert_eq!(table.image_info_extras[0].image_file_offset, 0xF000);

        assert_eq!(table.initializer_count(), 1);
        assert_eq!(table.initializers[0].image_index, 42);
        assert_eq!(table.initializers[0].initializer_file_offset, 0x8000);

        assert_eq!(table.dof_count(), 1);
        assert_eq!(table.dofs[0].image_index, 7);
        assert_eq!(table.dofs[0].dof_size, 0x2000);

        assert_eq!(table.range_count(), 1);
        assert!(table.range_entries[0].contains(0x180000000));
        assert!(table.range_entries[0].contains(0x18000FFFF));
        assert!(!table.range_entries[0].contains(0x180010000));
    }

    #[test]
    fn test_accelerate_info_table_truncated() {
        let cache = vec![0u8; 10];
        assert!(DyldCacheAccelerateInfoTable::parse_with_ranges(&cache, 0, 0, 0).is_err());
    }
}
