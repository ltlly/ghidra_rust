//! Dyld cache image info collection and batch parsing.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.macho.dyld.DyldCacheImageInfo`.
//!
//! Provides `DyldCacheImageInfoTable` which parses all image entries from
//! the dyld shared cache in a single pass and resolves their install paths.
//! Includes lookup helpers for finding images by name, path prefix, or
//! address.

use super::dyld_cache_image::DyldCacheImageInfo;

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheImageInfoTable
// ═══════════════════════════════════════════════════════════════════════════════════

/// A collection of `DyldCacheImageInfo` entries parsed from the dyld cache.
///
/// Holds all image entries and provides helpers for querying the image list
/// by name, path, address, or category (framework / system dylib / etc.).
#[derive(Debug, Clone)]
pub struct DyldCacheImageInfoTable {
    /// Parsed image info entries with resolved paths.
    images: Vec<DyldCacheImageInfo>,
}

impl DyldCacheImageInfoTable {
    /// Parse all image entries from the dyld cache.
    ///
    /// `cache_data` is the full dyld cache blob.  `images_offset` and
    /// `images_count` come from the dyld cache header.
    pub fn parse(
        cache_data: &[u8],
        images_offset: u32,
        images_count: u32,
    ) -> Result<Self, String> {
        let mut images = Vec::with_capacity(images_count as usize);
        let base = images_offset as usize;
        for i in 0..images_count {
            let start = base + (i as usize) * DyldCacheImageInfo::SIZE;
            let end = start + DyldCacheImageInfo::SIZE;
            if end > cache_data.len() {
                return Err(format!(
                    "DyldCacheImageInfoTable: data too short at image index {i}"
                ));
            }
            let info =
                DyldCacheImageInfo::parse_with_path(cache_data, &cache_data[start..end])?;
            images.push(info);
        }
        Ok(DyldCacheImageInfoTable { images })
    }

    /// Returns the number of images.
    pub fn len(&self) -> usize {
        self.images.len()
    }

    /// Returns true if there are no images.
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// Returns a slice of all image entries.
    pub fn entries(&self) -> &[DyldCacheImageInfo] {
        &self.images
    }

    /// Returns the image entry at the given ordinal (index).
    pub fn get(&self, index: usize) -> Option<&DyldCacheImageInfo> {
        self.images.get(index)
    }

    /// Find an image by its exact install path.
    pub fn find_by_path(&self, path: &str) -> Option<&DyldCacheImageInfo> {
        self.images.iter().find(|img| img.path == path)
    }

    /// Find an image by its dylib name (last path component).
    pub fn find_by_name(&self, name: &str) -> Option<&DyldCacheImageInfo> {
        self.images.iter().find(|img| img.name() == name)
    }

    /// Find all images whose path starts with the given prefix.
    pub fn find_by_path_prefix(&self, prefix: &str) -> Vec<&DyldCacheImageInfo> {
        self.images
            .iter()
            .filter(|img| img.path.starts_with(prefix))
            .collect()
    }

    /// Find the image that is loaded at the given address.
    pub fn find_by_address(&self, addr: u64) -> Option<&DyldCacheImageInfo> {
        // Note: DyldCacheImageInfo stores the load address.  Exact match only
        // (the image address is the base, not a range).
        self.images.iter().find(|img| img.address == addr)
    }

    /// Returns all framework images (paths containing `.framework/`).
    pub fn frameworks(&self) -> Vec<&DyldCacheImageInfo> {
        self.images.iter().filter(|img| img.is_framework()).collect()
    }

    /// Returns all system dylib images (paths under `/usr/lib/` or
    /// `/System/Library/`).
    pub fn system_dylibs(&self) -> Vec<&DyldCacheImageInfo> {
        self.images
            .iter()
            .filter(|img| img.is_system_dylib())
            .collect()
    }

    /// Returns the ordinal (index) of the image with the given path, if found.
    pub fn ordinal_of(&self, path: &str) -> Option<usize> {
        self.images.iter().position(|img| img.path == path)
    }

    /// Returns the ordinal (index) of the image at the given address, if found.
    pub fn ordinal_of_address(&self, addr: u64) -> Option<usize> {
        self.images.iter().position(|img| img.address == addr)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal cache blob with `count` image entries at `images_offset`
    /// and path strings placed at their recorded `path_file_offset` values.
    fn build_test_cache(image_descs: &[(u64, &str)]) -> Vec<u8> {
        let count = image_descs.len();
        let entry_size = DyldCacheImageInfo::SIZE;
        let images_offset: u32 = 0;
        let entries_end = count * entry_size;

        // Place path strings starting at a safe offset after entries.
        let string_base = ((entries_end + 0x100) & !0xF) as u32; // 16-byte aligned
        let total = string_base as usize
            + image_descs
                .iter()
                .map(|(_, p)| p.len() + 1)
                .sum::<usize>()
                + 64;
        let mut cache = vec![0u8; total];

        let mut str_off = string_base;
        for (i, (addr, path)) in image_descs.iter().enumerate() {
            let base = i * entry_size;
            cache[base..base + 8].copy_from_slice(&addr.to_le_bytes());
            // mod_time, inode left as 0
            cache[base + 24..base + 28].copy_from_slice(&str_off.to_le_bytes());
            // pad left as 0

            let p_bytes = path.as_bytes();
            cache[str_off as usize..str_off as usize + p_bytes.len()].copy_from_slice(p_bytes);
            // NUL terminator is already 0 from vec init
            str_off += p_bytes.len() as u32 + 1;
        }

        cache
    }

    #[test]
    fn test_image_info_table_parse() {
        let cache = build_test_cache(&[
            (0x180040000, "/usr/lib/system/libsystem_c.dylib"),
            (0x180080000, "/System/Library/Frameworks/UIKit.framework/UIKit"),
            (0x1800C0000, "/usr/lib/libobjc.A.dylib"),
        ]);

        let table = DyldCacheImageInfoTable::parse(&cache, 0, 3).unwrap();
        assert_eq!(table.len(), 3);

        // Lookup by name
        let img = table.find_by_name("libobjc.A.dylib").unwrap();
        assert_eq!(img.address, 0x1800C0000);

        // Lookup by path
        let img = table.find_by_path("/usr/lib/system/libsystem_c.dylib").unwrap();
        assert_eq!(img.name(), "libsystem_c.dylib");

        // Frameworks
        let fws = table.frameworks();
        assert_eq!(fws.len(), 1);
        assert!(fws[0].is_framework());

        // System dylibs
        let sys = table.system_dylibs();
        assert_eq!(sys.len(), 3); // all three are under /usr/lib or /System/Library

        // Ordinal lookup
        assert_eq!(
            table.ordinal_of("/usr/lib/libobjc.A.dylib"),
            Some(2)
        );
        assert_eq!(
            table.ordinal_of_address(0x180080000),
            Some(1)
        );

        // Path prefix
        let usr_libs = table.find_by_path_prefix("/usr/lib/");
        assert_eq!(usr_libs.len(), 2);
    }

    #[test]
    fn test_image_info_table_empty() {
        let cache = vec![0u8; 0];
        let table = DyldCacheImageInfoTable::parse(&cache, 0, 0).unwrap();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_image_info_table_truncated() {
        let cache = vec![0u8; 10];
        assert!(DyldCacheImageInfoTable::parse(&cache, 0, 1).is_err());
    }
}
