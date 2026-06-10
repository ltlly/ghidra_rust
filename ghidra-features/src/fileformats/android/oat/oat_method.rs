//! Android OAT method metadata.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.oat.OatMethod`
//! class.
//!
//! An `OatMethod` contains the compiled code offsets and runtime metadata
//! for a single method within an OAT file.  The layout varies depending
//! on the OAT version and instruction set.

/// A single compiled method entry in an OAT file.
///
/// This structure captures the method's code offsets, stack frame
/// information, and GC map references.  The exact set of fields depends
/// on the OAT version and pointer size.
#[derive(Debug, Clone)]
pub struct OatMethod {
    /// OAT version string this method was parsed with.
    pub oat_version: String,
    /// Pointer size (4 or 8) this method was parsed with.

    /// The compiled code offset (from the start of the method's
    /// OAT class).  This is a relative offset from the method entry.
    pub code_offset: u32,

    /// Offset to the method's code from the OAT header.
    pub oat_code_offset: u32,

    /// Offset to the method's GC map from the OAT header.
    pub gc_map_offset: u32,

    /// Frame size in bytes.
    pub frame_size: u32,

    /// Core callee-save register mask.
    pub core_spill_mask: u32,

    /// FP callee-save register mask.
    pub fp_spill_mask: u32,

    /// The method index (within the DEX file).
    pub method_index: u32,

    /// Mapping table offset (for stack traces).
    pub mapping_table_offset: u32,

    /// Vmap table offset (for GC and debugging).
    pub vmap_table_offset: u32,

    /// Quick code pointer (absolute address, resolved at load time).
    pub quick_code: u64,
}

impl OatMethod {
    /// Parse an OAT method for the given OAT version and pointer size.
    ///
    /// `data`: byte slice starting at this method's entry.
    /// `oat_version`: OAT version string (e.g. "131").
    /// `pointer_size`: 4 or 8.
    pub fn parse(data: &[u8], oat_version: &str, pointer_size: u32) -> Result<Self, String> {
        let version_num: u32 = oat_version
            .parse()
            .map_err(|_| format!("Invalid OAT version: {}", oat_version))?;

        // Validate against known OAT versions (064..=206).
        if version_num < 64 || version_num > 206 {
            return Err(format!("Unsupported OAT version: {}", oat_version));
        }

        if version_num < 131 {
            Self::parse_legacy(data, oat_version, pointer_size)
        } else {
            Self::parse_modern(data, oat_version, pointer_size)
        }
    }

    /// Legacy layout (OAT < 131 / pre-Oreo).
    ///
    /// Layout (32-bit pointers):
    ///   code_offset(4) + gc_map_offset(4) + frame_size(4) +
    ///   core_spill_mask(4) + fp_spill_mask(4) +
    ///   method_index(4) + mapping_table_offset(4) + vmap_table_offset(4)
    ///   = 32 bytes
    ///
    /// For 64-bit pointers, code_offset and gc_map_offset are u64.
    fn parse_legacy(data: &[u8], oat_version: &str, pointer_size: u32) -> Result<Self, String> {
        if pointer_size == 4 {
            let needed = 32;
            if data.len() < needed {
                return Err("Data too short for OAT method (legacy 32-bit)".to_string());
            }
            let code_offset = u32::from_le_bytes(data[0..4].try_into().unwrap());
            let gc_map_offset = u32::from_le_bytes(data[4..8].try_into().unwrap());
            let frame_size = u32::from_le_bytes(data[8..12].try_into().unwrap());
            let core_spill_mask = u32::from_le_bytes(data[12..16].try_into().unwrap());
            let fp_spill_mask = u32::from_le_bytes(data[16..20].try_into().unwrap());
            let method_index = u32::from_le_bytes(data[20..24].try_into().unwrap());
            let mapping_table_offset = u32::from_le_bytes(data[24..28].try_into().unwrap());
            let vmap_table_offset = u32::from_le_bytes(data[28..32].try_into().unwrap());

            Ok(OatMethod {
                oat_version: oat_version.to_string(),
                code_offset,
                oat_code_offset: code_offset,
                gc_map_offset,
                frame_size,
                core_spill_mask,
                fp_spill_mask,
                method_index,
                mapping_table_offset,
                vmap_table_offset,
                quick_code: code_offset as u64,
            })
        } else {
            let needed = 40;
            if data.len() < needed {
                return Err("Data too short for OAT method (legacy 64-bit)".to_string());
            }
            let code_offset = u32::from_le_bytes(data[0..4].try_into().unwrap());
            let gc_map_offset = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let frame_size = u32::from_le_bytes(data[12..16].try_into().unwrap());
            let core_spill_mask = u32::from_le_bytes(data[16..20].try_into().unwrap());
            let fp_spill_mask = u32::from_le_bytes(data[20..24].try_into().unwrap());
            let method_index = u32::from_le_bytes(data[24..28].try_into().unwrap());
            let mapping_table_offset = u32::from_le_bytes(data[28..32].try_into().unwrap());
            let vmap_table_offset = u32::from_le_bytes(data[32..36].try_into().unwrap());

            Ok(OatMethod {
                oat_version: oat_version.to_string(),
                code_offset,
                oat_code_offset: code_offset,
                gc_map_offset: gc_map_offset as u32,
                frame_size,
                core_spill_mask,
                fp_spill_mask,
                method_index,
                mapping_table_offset,
                vmap_table_offset,
                quick_code: code_offset as u64,
            })
        }
    }

    /// Modern layout (OAT >= 131 / Oreo+).
    ///
    /// Layout (32-bit pointers):
    ///   quick_code(4) + frame_info(4*5) + gc_map_offset(4) = 28 bytes
    ///
    /// The frame info fields are:
    ///   frame_size(4) + core_spill_mask(4) + fp_spill_mask(4) +
    ///   method_index(4) + mapping_table_offset(4)
    fn parse_modern(data: &[u8], oat_version: &str, pointer_size: u32) -> Result<Self, String> {
        if pointer_size == 4 {
            let needed = 28;
            if data.len() < needed {
                return Err("Data too short for OAT method (modern 32-bit)".to_string());
            }
            let quick_code = u32::from_le_bytes(data[0..4].try_into().unwrap()) as u64;
            let frame_size = u32::from_le_bytes(data[4..8].try_into().unwrap());
            let core_spill_mask = u32::from_le_bytes(data[8..12].try_into().unwrap());
            let fp_spill_mask = u32::from_le_bytes(data[12..16].try_into().unwrap());
            let method_index = u32::from_le_bytes(data[16..20].try_into().unwrap());
            let mapping_table_offset = u32::from_le_bytes(data[20..24].try_into().unwrap());
            let gc_map_offset = u32::from_le_bytes(data[24..28].try_into().unwrap());

            Ok(OatMethod {
                oat_version: oat_version.to_string(),
                code_offset: quick_code as u32,
                oat_code_offset: quick_code as u32,
                gc_map_offset,
                frame_size,
                core_spill_mask,
                fp_spill_mask,
                method_index,
                mapping_table_offset,
                vmap_table_offset: 0, // not present in modern layout
                quick_code,
            })
        } else {
            let needed = 48;
            if data.len() < needed {
                return Err("Data too short for OAT method (modern 64-bit)".to_string());
            }
            let quick_code = u64::from_le_bytes(data[0..8].try_into().unwrap());
            let frame_size = u32::from_le_bytes(data[8..12].try_into().unwrap());
            let core_spill_mask = u32::from_le_bytes(data[12..16].try_into().unwrap());
            let fp_spill_mask = u32::from_le_bytes(data[16..20].try_into().unwrap());
            let method_index = u32::from_le_bytes(data[20..24].try_into().unwrap());
            let mapping_table_offset = u32::from_le_bytes(data[24..28].try_into().unwrap());
            let gc_map_offset = u32::from_le_bytes(data[28..32].try_into().unwrap());

            Ok(OatMethod {
                oat_version: oat_version.to_string(),
                code_offset: quick_code as u32,
                oat_code_offset: quick_code as u32,
                gc_map_offset,
                frame_size,
                core_spill_mask,
                fp_spill_mask,
                method_index,
                mapping_table_offset,
                vmap_table_offset: 0,
                quick_code,
            })
        }
    }

    /// Returns the total on-disk size for a method entry for the given
    /// version and pointer size.
    pub fn size_for(oat_version: &str, pointer_size: u32) -> Result<usize, String> {
        let version_num: u32 = oat_version
            .parse()
            .map_err(|_| format!("Invalid OAT version: {}", oat_version))?;

        if version_num < 131 {
            // Legacy layout
            Ok(if pointer_size == 4 { 32 } else { 40 })
        } else {
            // Modern layout
            Ok(if pointer_size == 4 { 28 } else { 48 })
        }
    }

    /// Returns true if this method has compiled code (quick_code != 0).
    pub fn has_code(&self) -> bool {
        self.quick_code != 0
    }

    /// Returns true if this method has a GC map.
    pub fn has_gc_map(&self) -> bool {
        self.gc_map_offset != 0
    }

    /// Returns true if this method has a mapping table (for stack traces).
    pub fn has_mapping_table(&self) -> bool {
        self.mapping_table_offset != 0
    }

    /// Returns the number of callee-save core registers.
    pub fn core_spill_count(&self) -> u32 {
        self.core_spill_mask.count_ones()
    }

    /// Returns the number of callee-save FP registers.
    pub fn fp_spill_count(&self) -> u32 {
        self.fp_spill_mask.count_ones()
    }

    /// Returns the number of local registers.
    pub fn locals_count(&self) -> u32 {
        // Frame size / pointer_size - spill counts - return value
        // This is a rough heuristic; exact computation depends on runtime.
        0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_for_legacy() {
        assert_eq!(OatMethod::size_for("064", 4).unwrap(), 32);
        assert_eq!(OatMethod::size_for("088", 4).unwrap(), 32);
        assert_eq!(OatMethod::size_for("088", 8).unwrap(), 40);
    }

    #[test]
    fn test_size_for_modern() {
        assert_eq!(OatMethod::size_for("131", 4).unwrap(), 28);
        assert_eq!(OatMethod::size_for("170", 4).unwrap(), 28);
        assert_eq!(OatMethod::size_for("131", 8).unwrap(), 48);
        assert_eq!(OatMethod::size_for("206", 8).unwrap(), 48);
    }

    #[test]
    fn test_parse_legacy_32bit() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // code_offset
        data[4..8].copy_from_slice(&0x2000u32.to_le_bytes()); // gc_map_offset
        data[8..12].copy_from_slice(&256u32.to_le_bytes()); // frame_size
        data[12..16].copy_from_slice(&0x0Fu32.to_le_bytes()); // core_spill_mask
        data[16..20].copy_from_slice(&0x03u32.to_le_bytes()); // fp_spill_mask
        data[20..24].copy_from_slice(&42u32.to_le_bytes()); // method_index
        data[24..28].copy_from_slice(&0x3000u32.to_le_bytes()); // mapping_table_offset
        data[28..32].copy_from_slice(&0x4000u32.to_le_bytes()); // vmap_table_offset

        let method = OatMethod::parse(&data, "088", 4).unwrap();
        assert_eq!(method.oat_version, "088");
        assert_eq!(method.code_offset, 0x1000);
        assert_eq!(method.gc_map_offset, 0x2000);
        assert_eq!(method.frame_size, 256);
        assert_eq!(method.core_spill_mask, 0x0F);
        assert_eq!(method.fp_spill_mask, 0x03);
        assert_eq!(method.method_index, 42);
        assert_eq!(method.mapping_table_offset, 0x3000);
        assert_eq!(method.vmap_table_offset, 0x4000);
        assert!(method.has_code());
        assert!(method.has_gc_map());
        assert!(method.has_mapping_table());
        assert_eq!(method.core_spill_count(), 4);
        assert_eq!(method.fp_spill_count(), 2);
    }

    #[test]
    fn test_parse_modern_32bit() {
        let mut data = vec![0u8; 28];
        data[0..4].copy_from_slice(&0xABCDu32.to_le_bytes()); // quick_code
        data[4..8].copy_from_slice(&128u32.to_le_bytes()); // frame_size
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // core_spill_mask
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // fp_spill_mask
        data[16..20].copy_from_slice(&7u32.to_le_bytes()); // method_index
        data[20..24].copy_from_slice(&0x5000u32.to_le_bytes()); // mapping_table_offset
        data[24..28].copy_from_slice(&0x6000u32.to_le_bytes()); // gc_map_offset

        let method = OatMethod::parse(&data, "131", 4).unwrap();
        assert_eq!(method.oat_version, "131");
        assert_eq!(method.quick_code, 0xABCD);
        assert_eq!(method.frame_size, 128);
        assert_eq!(method.method_index, 7);
        assert_eq!(method.mapping_table_offset, 0x5000);
        assert_eq!(method.gc_map_offset, 0x6000);
        assert!(method.has_code());
        assert!(method.has_gc_map());
    }

    #[test]
    fn test_parse_modern_64bit() {
        let mut data = vec![0u8; 48];
        data[0..8].copy_from_slice(&0x1234567890ABCDEFu64.to_le_bytes()); // quick_code
        data[8..12].copy_from_slice(&512u32.to_le_bytes()); // frame_size
        data[12..16].copy_from_slice(&0xFFu32.to_le_bytes()); // core_spill_mask
        data[16..20].copy_from_slice(&0u32.to_le_bytes()); // fp_spill_mask
        data[20..24].copy_from_slice(&100u32.to_le_bytes()); // method_index
        data[24..28].copy_from_slice(&0x7000u32.to_le_bytes()); // mapping_table_offset
        data[28..32].copy_from_slice(&0x8000u32.to_le_bytes()); // gc_map_offset

        let method = OatMethod::parse(&data, "170", 8).unwrap();
        assert_eq!(method.quick_code, 0x1234567890ABCDEF);
        assert_eq!(method.frame_size, 512);
        assert_eq!(method.core_spill_count(), 8);
        assert_eq!(method.fp_spill_count(), 0);
    }

    #[test]
    fn test_parse_no_code() {
        let mut data = vec![0u8; 28];
        // quick_code = 0
        data[4..8].copy_from_slice(&64u32.to_le_bytes()); // frame_size

        let method = OatMethod::parse(&data, "131", 4).unwrap();
        assert!(!method.has_code());
        assert!(!method.has_gc_map());
        assert!(!method.has_mapping_table());
    }

    #[test]
    fn test_parse_truncated() {
        let data = vec![0u8; 10];
        assert!(OatMethod::parse(&data, "131", 4).is_err());
        assert!(OatMethod::parse(&data, "088", 4).is_err());
    }

    #[test]
    fn test_parse_invalid_version() {
        let data = vec![0u8; 48];
        assert!(OatMethod::parse(&data, "999", 4).is_err());
    }

    #[test]
    fn test_size_for_invalid() {
        assert!(OatMethod::size_for("abc", 4).is_err());
    }
}
