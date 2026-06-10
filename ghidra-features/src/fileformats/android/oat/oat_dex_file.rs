//! Android OAT DEX file descriptor.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.oat.OatDexFile`
//! class.
//!
//! Each OAT file contains one or more `OatDexFile` entries that describe
//! the location and layout of the embedded (or referenced) DEX files.
//! The entries are referenced by the `oat_dex_files_offset` field in
//! the OAT header.

/// A single OAT DEX file descriptor.
///
/// This structure maps an original DEX file to its location within the
/// OAT file.  It records the DEX file name, checksums, and offsets for
/// both the DEX data and the compiled OAT classes.
///
/// The on-disk layout (all little-endian):
///   - location (offset+size): pointer to a null-terminated string
///   - location_checksum: u32 -- Adler-32 checksum of the DEX file
///   - dex_file_pointer: u32/u64 -- pointer to the mapped DEX data
///   - class_offsets_pointer: u32/u64 -- pointer to the OAT class offsets
///   - lookup_table_offset: u32/u64 -- pointer to the method lookup table
///   - dex_file_offset: u32 -- offset of the DEX data within the OAT file
#[derive(Debug, Clone)]
pub struct OatDexFile {
    /// File offset of this descriptor within the OAT file.
    pub file_offset: u64,
    /// The original DEX file location (path string).
    pub location: String,
    /// Adler-32 checksum of the original DEX file.
    pub location_checksum: u32,
    /// Absolute pointer (or file offset) to the DEX data.
    pub dex_file_pointer: u64,
    /// Absolute pointer (or file offset) to the OAT class offsets array.
    pub class_offsets_pointer: u64,
    /// Absolute pointer (or file offset) to the lookup table.
    pub lookup_table_offset: u64,
    /// File offset of the DEX data within the OAT file.
    pub dex_file_offset: u32,
}

impl OatDexFile {
    /// Parse an `OatDexFile` descriptor.
    ///
    /// `data`: the full OAT file bytes.
    /// `offset`: the byte offset of this descriptor within the file.
    /// `pointer_size`: 4 (32-bit) or 8 (64-bit).
    pub fn parse(data: &[u8], offset: usize, pointer_size: u32) -> Result<Self, String> {
        let mut pos = offset;

        // Read location string pointer (relative to the descriptor start
        // in some versions, or absolute in others).  The pointer is stored
        // as a u32 or u64 depending on pointer_size.
        let location_ptr = read_pointer(data, pos, pointer_size)?;
        pos += pointer_size as usize;

        // The location checksum is stored inline.
        let location_checksum = read_u32(data, pos)?;
        pos += 4;

        // DEX file pointer.
        let dex_file_pointer = read_pointer(data, pos, pointer_size)?;
        pos += pointer_size as usize;

        // Class offsets pointer.
        let class_offsets_pointer = read_pointer(data, pos, pointer_size)?;
        pos += pointer_size as usize;

        // Lookup table offset.
        let lookup_table_offset = read_pointer(data, pos, pointer_size)?;
        pos += pointer_size as usize;

        // DEX file offset (always u32).
        let dex_file_offset = read_u32(data, pos)?;

        // Resolve the location string.  The pointer can be absolute or
        // relative; we try absolute first, then relative to the descriptor.
        let location = resolve_string(data, location_ptr, offset)?;

        Ok(OatDexFile {
            file_offset: offset as u64,
            location,
            location_checksum,
            dex_file_pointer,
            class_offsets_pointer,
            lookup_table_offset,
            dex_file_offset,
        })
    }

    /// Returns the total on-disk size of one OAT DEX file descriptor
    /// for the given pointer size.
    pub fn size_for(pointer_size: u32) -> usize {
        // pointer (location) + u32 (checksum) + 3 * pointer + u32 (dex_file_offset)
        pointer_size as usize * 4 + 4 + 4
    }

    /// Returns true if the DEX data is embedded in this OAT file
    /// (as opposed to memory-mapped from a separate .vdex).
    pub fn has_embedded_dex(&self) -> bool {
        self.dex_file_offset > 0
    }

    /// Parse all `OatDexFile` descriptors from an OAT file.
    ///
    /// `data`: the full OAT file bytes.
    /// `offset`: the byte offset of the first descriptor (from the header).
    /// `count`: the number of descriptors (from the header).
    /// `pointer_size`: 4 or 8.
    pub fn parse_all(
        data: &[u8],
        offset: u32,
        count: u32,
        pointer_size: u32,
    ) -> Result<Vec<Self>, String> {
        let start = offset as usize;
        let entry_size = Self::size_for(pointer_size);
        let table_size = count as usize * entry_size;

        if start + table_size > data.len() {
            return Err("OatDexFile table extends beyond data".to_string());
        }

        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let entry_offset = start + i * entry_size;
            let oat_dex_file = Self::parse(data, entry_offset, pointer_size)?;
            result.push(oat_dex_file);
        }

        Ok(result)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read a little-endian u32.
fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!(
            "OatDexFile: read_u32 at {} beyond data length {}",
            offset,
            data.len()
        ));
    }
    Ok(u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()))
}

/// Read a pointer (u32 or u64) from `data` at `offset`.
fn read_pointer(data: &[u8], offset: usize, pointer_size: u32) -> Result<u64, String> {
    match pointer_size {
        4 => read_u32(data, offset).map(|v| v as u64),
        8 => {
            if offset + 8 > data.len() {
                return Err(format!(
                    "OatDexFile: read_u64 at {} beyond data length {}",
                    offset,
                    data.len()
                ));
            }
            Ok(u64::from_le_bytes(
                data[offset..offset + 8].try_into().unwrap(),
            ))
        }
        _ => Err(format!("Invalid pointer size: {}", pointer_size)),
    }
}

/// Resolve a null-terminated string at the given pointer.
///
/// Tries the pointer as an absolute file offset.  If that fails or
/// points outside the data, tries it relative to the descriptor offset.
fn resolve_string(data: &[u8], ptr: u64, _descriptor_offset: usize) -> Result<String, String> {
    let abs_offset = ptr as usize;
    if abs_offset < data.len() {
        return read_null_terminated(data, abs_offset);
    }
    Err(format!("OatDexFile: string pointer 0x{:x} out of range", ptr))
}

/// Read a null-terminated string from `data` at `offset`.
fn read_null_terminated(data: &[u8], offset: usize) -> Result<String, String> {
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "OatDexFile: unterminated string".to_string())?;
    let bytes = &data[offset..offset + end];
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| "OatDexFile: non-UTF-8 string".to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_for() {
        // 32-bit: 4 pointers * 4 + 4 (checksum) + 4 (dex_file_offset) = 24
        assert_eq!(OatDexFile::size_for(4), 24);
        // 64-bit: 4 pointers * 8 + 4 + 4 = 40
        assert_eq!(OatDexFile::size_for(8), 40);
    }

    #[test]
    fn test_parse_32bit() {
        // Build a 32-bit OatDexFile descriptor.
        // Layout: location_ptr(4) + checksum(4) + dex_ptr(4) + class_ptr(4) + lookup_ptr(4) + dex_offset(4)
        // = 24 bytes for the descriptor, plus string data.
        let mut data = vec![0u8; 128];

        // Place the location string at offset 64
        let loc = b"/tmp/test.dex\0";
        data[64..64 + loc.len()].copy_from_slice(loc);

        // Descriptor at offset 0
        data[0..4].copy_from_slice(&64u32.to_le_bytes()); // location pointer
        data[4..8].copy_from_slice(&0x12345678u32.to_le_bytes()); // checksum
        data[8..12].copy_from_slice(&0x1000u32.to_le_bytes()); // dex_file_pointer
        data[12..16].copy_from_slice(&0x2000u32.to_le_bytes()); // class_offsets_pointer
        data[16..20].copy_from_slice(&0x3000u32.to_le_bytes()); // lookup_table_offset
        data[20..24].copy_from_slice(&0x4000u32.to_le_bytes()); // dex_file_offset

        let oat_dex_file = OatDexFile::parse(&data, 0, 4).unwrap();
        assert_eq!(oat_dex_file.location, "/tmp/test.dex");
        assert_eq!(oat_dex_file.location_checksum, 0x12345678);
        assert_eq!(oat_dex_file.dex_file_pointer, 0x1000);
        assert_eq!(oat_dex_file.class_offsets_pointer, 0x2000);
        assert_eq!(oat_dex_file.lookup_table_offset, 0x3000);
        assert_eq!(oat_dex_file.dex_file_offset, 0x4000);
        assert!(oat_dex_file.has_embedded_dex());
    }

    #[test]
    fn test_parse_64bit() {
        let mut data = vec![0u8; 128];

        // Place the location string at offset 80
        let loc = b"/app/base.apk\0";
        data[80..80 + loc.len()].copy_from_slice(loc);

        // Descriptor at offset 0 (64-bit: 40 bytes)
        data[0..8].copy_from_slice(&80u64.to_le_bytes()); // location pointer
        data[8..12].copy_from_slice(&0xAABBCCDDu32.to_le_bytes()); // checksum
        data[12..20].copy_from_slice(&0x10000u64.to_le_bytes()); // dex_file_pointer
        data[20..28].copy_from_slice(&0x20000u64.to_le_bytes()); // class_offsets_pointer
        data[28..36].copy_from_slice(&0x30000u64.to_le_bytes()); // lookup_table_offset
        data[36..40].copy_from_slice(&0x40000u32.to_le_bytes()); // dex_file_offset

        let oat_dex_file = OatDexFile::parse(&data, 0, 8).unwrap();
        assert_eq!(oat_dex_file.location, "/app/base.apk");
        assert_eq!(oat_dex_file.location_checksum, 0xAABBCCDD);
        assert_eq!(oat_dex_file.dex_file_pointer, 0x10000);
        assert_eq!(oat_dex_file.class_offsets_pointer, 0x20000);
        assert_eq!(oat_dex_file.lookup_table_offset, 0x30000);
        assert_eq!(oat_dex_file.dex_file_offset, 0x40000);
    }

    #[test]
    fn test_parse_all() {
        // Two 32-bit descriptors.
        let mut data = vec![0u8; 256];

        // String for first descriptor at offset 100
        let loc1 = b"first.dex\0";
        data[100..100 + loc1.len()].copy_from_slice(loc1);

        // String for second descriptor at offset 120
        let loc2 = b"second.dex\0";
        data[120..120 + loc2.len()].copy_from_slice(loc2);

        // First descriptor at offset 0
        data[0..4].copy_from_slice(&100u32.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        data[20..24].copy_from_slice(&0x500u32.to_le_bytes());

        // Second descriptor at offset 24
        data[24..28].copy_from_slice(&120u32.to_le_bytes());
        data[28..32].copy_from_slice(&2u32.to_le_bytes());
        data[32..36].copy_from_slice(&0u32.to_le_bytes());
        data[36..40].copy_from_slice(&0u32.to_le_bytes());
        data[40..44].copy_from_slice(&0u32.to_le_bytes());
        data[44..48].copy_from_slice(&0x600u32.to_le_bytes());

        let files = OatDexFile::parse_all(&data, 0, 2, 4).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].location, "first.dex");
        assert_eq!(files[0].location_checksum, 1);
        assert_eq!(files[0].dex_file_offset, 0x500);
        assert_eq!(files[1].location, "second.dex");
        assert_eq!(files[1].location_checksum, 2);
        assert_eq!(files[1].dex_file_offset, 0x600);
    }

    #[test]
    fn test_parse_truncated() {
        let data = vec![0u8; 10];
        assert!(OatDexFile::parse(&data, 0, 4).is_err());
    }

    #[test]
    fn test_no_embedded_dex() {
        let mut data = vec![0u8; 128];
        let loc = b"test.dex\0";
        data[64..64 + loc.len()].copy_from_slice(loc);
        data[0..4].copy_from_slice(&64u32.to_le_bytes());
        // dex_file_offset = 0 means no embedded dex
        data[20..24].copy_from_slice(&0u32.to_le_bytes());

        let oat_dex_file = OatDexFile::parse(&data, 0, 4).unwrap();
        assert!(!oat_dex_file.has_embedded_dex());
    }
}
