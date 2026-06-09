//! ART method and method group structures.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.art.ArtMethod`
//! and `ArtMethodGroup`.
//!
//! An `ArtMethod` represents a single compiled method in the ART image.
//! The layout varies by ART version and pointer size (4 vs 8 bytes).
//!
//! An `ArtMethodGroup` wraps a count-prefixed array of `ArtMethod`
//! entries (used in versions after Marshmallow).

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtMethod
// ═══════════════════════════════════════════════════════════════════════════════════

/// A single ART method entry.
///
/// The on-disk layout depends on the ART version and pointer size.
/// This struct captures all possible fields; unused fields are set to 0.
#[derive(Debug, Clone)]
pub struct ArtMethod {
    /// ART version string this method was parsed with.
    pub art_version: String,
    /// Pointer size (4 or 8) this method was parsed with.
    pub pointer_size: u32,

    /// Pointer to the declaring class.
    pub declaring_class: u32,
    /// Access flags (ACC_PUBLIC, ACC_STATIC, etc.).
    pub access_flags: u32,
    /// Offset to the DEX code item.
    pub dex_code_item_offset: u32,
    /// Index into the DEX method IDs table.
    pub dex_method_index: u32,
    /// Method index within the class vtable.
    pub method_index: u16,
    /// Hotness/profiling counter.
    pub hotness_count: u16,
    /// Interface method table index.
    pub imt_index: u16,
    /// Padding.
    pub padding: u16,

    // Older version fields (may be 0 if not applicable).
    /// Pointer to DEX cache resolved methods.
    pub dex_cache_resolved_methods: u64,
    /// Pointer to DEX cache resolved types.
    pub dex_cache_resolved_types: u64,
    /// Entry point from the interpreter.
    pub entry_point_from_interpreter: u64,
    /// Entry point from JNI.
    pub entry_point_from_jni: u64,
    /// Opaque data pointer (method/compiled code pointer).
    pub data: u64,
    /// Unknown field (Oreo+ 64-bit).
    pub unknown1: u64,
    /// Entry point from quick compiled code.
    pub entry_point_from_quick_compiled_code: u64,
}

impl ArtMethod {
    /// Parse an ArtMethod from raw bytes.
    ///
    /// `data`: the byte slice to read from.
    /// `pointer_size`: 4 or 8.
    /// `art_version`: the ART version string (e.g. "017", "074").
    pub fn parse(data: &[u8], pointer_size: u32, art_version: &str) -> Result<Self, String> {
        match art_version {
            "017" => Self::parse_v017(data, pointer_size),
            "029" | "030" => Self::parse_v029(data, pointer_size),
            "043" | "044" | "046" => Self::parse_v043(data, pointer_size),
            "056" => Self::parse_v056(data, pointer_size),
            "074" => Self::parse_v074(data, pointer_size),
            "085" => Self::parse_v085(data, pointer_size),
            "099" => Self::parse_v099(data, pointer_size),
            "106" => Self::parse_v106(data, pointer_size),
            _ => Err(format!("Unsupported ART method version: {}", art_version)),
        }
    }

    fn parse_v017(data: &[u8], pointer_size: u32) -> Result<Self, String> {
        if pointer_size == 4 {
            let needed = 40; // 10 x u32
            if data.len() < needed {
                return Err("Data too short for ART method v017 (32-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "017".to_string(),
                pointer_size,
                declaring_class: u32::from_le_bytes(data[0..4].try_into().unwrap()),
                dex_cache_resolved_methods: u32::from_le_bytes(data[4..8].try_into().unwrap()) as u64,
                dex_cache_resolved_types: u32::from_le_bytes(data[8..12].try_into().unwrap()) as u64,
                access_flags: u32::from_le_bytes(data[12..16].try_into().unwrap()),
                dex_code_item_offset: u32::from_le_bytes(data[16..20].try_into().unwrap()),
                dex_method_index: u32::from_le_bytes(data[20..24].try_into().unwrap()),
                method_index: u16::from_le_bytes(data[24..26].try_into().unwrap()),
                padding: u16::from_le_bytes(data[26..28].try_into().unwrap()),
                entry_point_from_interpreter: u32::from_le_bytes(data[28..32].try_into().unwrap()) as u64,
                entry_point_from_jni: u32::from_le_bytes(data[32..36].try_into().unwrap()) as u64,
                entry_point_from_quick_compiled_code: u32::from_le_bytes(data[36..40].try_into().unwrap()) as u64,
                hotness_count: 0,
                imt_index: 0,
                data: 0,
                unknown1: 0,
            })
        } else {
            Err("Unsupported 64-bit ART method format: 017".to_string())
        }
    }

    fn parse_v029(data: &[u8], pointer_size: u32) -> Result<Self, String> {
        if pointer_size == 4 {
            let needed = 40;
            if data.len() < needed {
                return Err("Data too short for ART method v029 (32-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "029".to_string(),
                pointer_size,
                declaring_class: u32::from_le_bytes(data[0..4].try_into().unwrap()),
                access_flags: u32::from_le_bytes(data[4..8].try_into().unwrap()),
                dex_code_item_offset: u32::from_le_bytes(data[8..12].try_into().unwrap()),
                dex_method_index: u32::from_le_bytes(data[12..16].try_into().unwrap()),
                method_index: u16::from_le_bytes(data[16..18].try_into().unwrap()),
                hotness_count: u16::from_le_bytes(data[18..20].try_into().unwrap()),
                dex_cache_resolved_methods: u32::from_le_bytes(data[20..24].try_into().unwrap()) as u64,
                dex_cache_resolved_types: u32::from_le_bytes(data[24..28].try_into().unwrap()) as u64,
                entry_point_from_jni: u32::from_le_bytes(data[28..32].try_into().unwrap()) as u64,
                entry_point_from_quick_compiled_code: u32::from_le_bytes(data[32..36].try_into().unwrap()) as u64,
                imt_index: 0,
                padding: 0,
                entry_point_from_interpreter: 0,
                data: 0,
                unknown1: 0,
            })
        } else {
            // 64-bit: 4 x u32 + 4 x u16 + 4 x u64 = 16 + 8 + 32 = 56
            let needed = 56;
            if data.len() < needed {
                return Err("Data too short for ART method v029 (64-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "029".to_string(),
                pointer_size,
                declaring_class: u32::from_le_bytes(data[0..4].try_into().unwrap()),
                access_flags: u32::from_le_bytes(data[4..8].try_into().unwrap()),
                dex_code_item_offset: u32::from_le_bytes(data[8..12].try_into().unwrap()),
                dex_method_index: u32::from_le_bytes(data[12..16].try_into().unwrap()),
                method_index: u16::from_le_bytes(data[16..18].try_into().unwrap()),
                hotness_count: u16::from_le_bytes(data[18..20].try_into().unwrap()),
                imt_index: u16::from_le_bytes(data[20..22].try_into().unwrap()),
                padding: u16::from_le_bytes(data[22..24].try_into().unwrap()),
                dex_cache_resolved_methods: u64::from_le_bytes(data[24..32].try_into().unwrap()),
                dex_cache_resolved_types: u64::from_le_bytes(data[32..40].try_into().unwrap()),
                entry_point_from_jni: u64::from_le_bytes(data[40..48].try_into().unwrap()),
                entry_point_from_quick_compiled_code: u64::from_le_bytes(data[48..56].try_into().unwrap()),
                entry_point_from_interpreter: 0,
                data: 0,
                unknown1: 0,
            })
        }
    }

    fn parse_v043(data: &[u8], pointer_size: u32) -> Result<Self, String> {
        if pointer_size == 4 {
            let needed = 32; // 4 x u32 + 2 x u16 + 8 (data) + 4 (entry) = 32
            if data.len() < needed {
                return Err("Data too short for ART method v043 (32-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "043".to_string(),
                pointer_size,
                declaring_class: u32::from_le_bytes(data[0..4].try_into().unwrap()),
                access_flags: u32::from_le_bytes(data[4..8].try_into().unwrap()),
                dex_code_item_offset: u32::from_le_bytes(data[8..12].try_into().unwrap()),
                dex_method_index: u32::from_le_bytes(data[12..16].try_into().unwrap()),
                method_index: u16::from_le_bytes(data[16..18].try_into().unwrap()),
                hotness_count: u16::from_le_bytes(data[18..20].try_into().unwrap()),
                data: u64::from_le_bytes(data[20..28].try_into().unwrap()),
                entry_point_from_quick_compiled_code: u32::from_le_bytes(data[28..32].try_into().unwrap()) as u64,
                imt_index: 0,
                padding: 0,
                dex_cache_resolved_methods: 0,
                dex_cache_resolved_types: 0,
                entry_point_from_interpreter: 0,
                entry_point_from_jni: 0,
                unknown1: 0,
            })
        } else {
            // 64-bit: 4 x u32 + 4 x u16 + u64 + u64 + u64 = 16+8+8+8+8 = 48
            let needed = 48;
            if data.len() < needed {
                return Err("Data too short for ART method v043 (64-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "043".to_string(),
                pointer_size,
                declaring_class: u32::from_le_bytes(data[0..4].try_into().unwrap()),
                access_flags: u32::from_le_bytes(data[4..8].try_into().unwrap()),
                dex_code_item_offset: u32::from_le_bytes(data[8..12].try_into().unwrap()),
                dex_method_index: u32::from_le_bytes(data[12..16].try_into().unwrap()),
                method_index: u16::from_le_bytes(data[16..18].try_into().unwrap()),
                hotness_count: u16::from_le_bytes(data[18..20].try_into().unwrap()),
                imt_index: u16::from_le_bytes(data[20..22].try_into().unwrap()),
                padding: u16::from_le_bytes(data[22..24].try_into().unwrap()),
                data: u64::from_le_bytes(data[24..32].try_into().unwrap()),
                unknown1: u64::from_le_bytes(data[32..40].try_into().unwrap()),
                entry_point_from_quick_compiled_code: u64::from_le_bytes(data[40..48].try_into().unwrap()),
                dex_cache_resolved_methods: 0,
                dex_cache_resolved_types: 0,
                entry_point_from_interpreter: 0,
                entry_point_from_jni: 0,
            })
        }
    }

    fn parse_v056(data: &[u8], pointer_size: u32) -> Result<Self, String> {
        // Common header: 4 x u32 + 4 x u16 = 24 bytes
        let header_size = 24;
        if data.len() < header_size {
            return Err("Data too short for ART method v056 header".to_string());
        }
        let declaring_class = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let access_flags = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let dex_code_item_offset = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let dex_method_index = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let method_index = u16::from_le_bytes(data[16..18].try_into().unwrap());
        let hotness_count = u16::from_le_bytes(data[18..20].try_into().unwrap());
        let imt_index = u16::from_le_bytes(data[20..22].try_into().unwrap());
        let padding = u16::from_le_bytes(data[22..24].try_into().unwrap());

        if pointer_size == 4 {
            if data.len() < header_size + 4 {
                return Err("Data too short for ART method v056 (32-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "056".to_string(),
                pointer_size,
                declaring_class,
                access_flags,
                dex_code_item_offset,
                dex_method_index,
                method_index,
                hotness_count,
                imt_index,
                padding,
                data: u32::from_le_bytes(data[24..28].try_into().unwrap()) as u64,
                dex_cache_resolved_methods: 0,
                dex_cache_resolved_types: 0,
                entry_point_from_interpreter: 0,
                entry_point_from_jni: 0,
                unknown1: 0,
                entry_point_from_quick_compiled_code: 0,
            })
        } else {
            // 64-bit: header(24) + u64(data) + u64(entry) = 40
            if data.len() < header_size + 16 {
                return Err("Data too short for ART method v056 (64-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "056".to_string(),
                pointer_size,
                declaring_class,
                access_flags,
                dex_code_item_offset,
                dex_method_index,
                method_index,
                hotness_count,
                imt_index,
                padding,
                data: u64::from_le_bytes(data[24..32].try_into().unwrap()),
                entry_point_from_quick_compiled_code: u64::from_le_bytes(data[32..40].try_into().unwrap()),
                dex_cache_resolved_methods: 0,
                dex_cache_resolved_types: 0,
                entry_point_from_interpreter: 0,
                entry_point_from_jni: 0,
                unknown1: 0,
            })
        }
    }

    fn parse_v074(data: &[u8], pointer_size: u32) -> Result<Self, String> {
        // Same layout as v056
        let header_size = 24;
        if data.len() < header_size {
            return Err("Data too short for ART method v074 header".to_string());
        }
        let declaring_class = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let access_flags = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let dex_code_item_offset = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let dex_method_index = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let method_index = u16::from_le_bytes(data[16..18].try_into().unwrap());
        let hotness_count = u16::from_le_bytes(data[18..20].try_into().unwrap());
        let imt_index = u16::from_le_bytes(data[20..22].try_into().unwrap());
        let padding = u16::from_le_bytes(data[22..24].try_into().unwrap());

        if pointer_size == 4 {
            if data.len() < header_size + 4 {
                return Err("Data too short for ART method v074 (32-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "074".to_string(),
                pointer_size,
                declaring_class,
                access_flags,
                dex_code_item_offset,
                dex_method_index,
                method_index,
                hotness_count,
                imt_index,
                padding,
                data: u32::from_le_bytes(data[24..28].try_into().unwrap()) as u64,
                dex_cache_resolved_methods: 0,
                dex_cache_resolved_types: 0,
                entry_point_from_interpreter: 0,
                entry_point_from_jni: 0,
                unknown1: 0,
                entry_point_from_quick_compiled_code: 0,
            })
        } else {
            if data.len() < header_size + 16 {
                return Err("Data too short for ART method v074 (64-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "074".to_string(),
                pointer_size,
                declaring_class,
                access_flags,
                dex_code_item_offset,
                dex_method_index,
                method_index,
                hotness_count,
                imt_index,
                padding,
                data: u64::from_le_bytes(data[24..32].try_into().unwrap()),
                entry_point_from_quick_compiled_code: u64::from_le_bytes(data[32..40].try_into().unwrap()),
                dex_cache_resolved_methods: 0,
                dex_cache_resolved_types: 0,
                entry_point_from_interpreter: 0,
                entry_point_from_jni: 0,
                unknown1: 0,
            })
        }
    }

    fn parse_v085(data: &[u8], pointer_size: u32) -> Result<Self, String> {
        // Same layout as v074
        Self::parse_v074(data, pointer_size).map(|mut m| {
            m.art_version = "085".to_string();
            m
        })
    }

    fn parse_v099(data: &[u8], pointer_size: u32) -> Result<Self, String> {
        // v099: same 4xu32+4xu16 header, but drops dex_code_item_offset
        let header_size = 20; // 3 x u32 + 4 x u16 = 12 + 8 = 20
        if data.len() < header_size {
            return Err("Data too short for ART method v099 header".to_string());
        }
        let declaring_class = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let access_flags = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let dex_method_index = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let method_index = u16::from_le_bytes(data[12..14].try_into().unwrap());
        let hotness_count = u16::from_le_bytes(data[14..16].try_into().unwrap());
        let imt_index = u16::from_le_bytes(data[16..18].try_into().unwrap());
        let padding = u16::from_le_bytes(data[18..20].try_into().unwrap());

        if pointer_size == 4 {
            if data.len() < header_size + 4 {
                return Err("Data too short for ART method v099 (32-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "099".to_string(),
                pointer_size,
                declaring_class,
                access_flags,
                dex_code_item_offset: 0, // not present in v099
                dex_method_index,
                method_index,
                hotness_count,
                imt_index,
                padding,
                data: u32::from_le_bytes(data[20..24].try_into().unwrap()) as u64,
                dex_cache_resolved_methods: 0,
                dex_cache_resolved_types: 0,
                entry_point_from_interpreter: 0,
                entry_point_from_jni: 0,
                unknown1: 0,
                entry_point_from_quick_compiled_code: 0,
            })
        } else {
            // 64-bit: header(20) + u32(data) + u64(entry) = 32
            if data.len() < header_size + 12 {
                return Err("Data too short for ART method v099 (64-bit)".to_string());
            }
            Ok(ArtMethod {
                art_version: "099".to_string(),
                pointer_size,
                declaring_class,
                access_flags,
                dex_code_item_offset: 0,
                dex_method_index,
                method_index,
                hotness_count,
                imt_index,
                padding,
                data: u32::from_le_bytes(data[20..24].try_into().unwrap()) as u64,
                entry_point_from_quick_compiled_code: u64::from_le_bytes(data[24..32].try_into().unwrap()),
                dex_cache_resolved_methods: 0,
                dex_cache_resolved_types: 0,
                entry_point_from_interpreter: 0,
                entry_point_from_jni: 0,
                unknown1: 0,
            })
        }
    }

    fn parse_v106(data: &[u8], pointer_size: u32) -> Result<Self, String> {
        // Same layout as v099
        Self::parse_v099(data, pointer_size).map(|mut m| {
            m.art_version = "106".to_string();
            m
        })
    }

    /// Returns true if the method is public.
    pub fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }

    /// Returns true if the method is static.
    pub fn is_static(&self) -> bool {
        self.access_flags & 0x0008 != 0
    }

    /// Returns true if the method is native.
    pub fn is_native(&self) -> bool {
        self.access_flags & 0x0100 != 0
    }

    /// Returns true if the method is abstract.
    pub fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    /// Returns true if the method is a constructor.
    pub fn is_constructor(&self) -> bool {
        self.access_flags & 0x10000 != 0
    }

    /// Returns the total on-disk size for this method given its version and pointer size.
    pub fn size_for(art_version: &str, pointer_size: u32) -> Result<usize, String> {
        match art_version {
            "017" => Ok(if pointer_size == 4 { 40 } else { return Err("64-bit v017 unsupported".into()) }),
            "029" | "030" => Ok(if pointer_size == 4 { 40 } else { 56 }),
            "043" | "044" | "046" => Ok(if pointer_size == 4 { 32 } else { 48 }),
            "056" | "074" | "085" => Ok(if pointer_size == 4 { 28 } else { 40 }),
            "099" | "106" => Ok(if pointer_size == 4 { 24 } else { 32 }),
            _ => Err(format!("Unknown ART version for method size: {}", art_version)),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtMethodGroup
// ═══════════════════════════════════════════════════════════════════════════════════

/// A group of ART methods, prefixed by a count.
///
/// For pointer_size == 4, the count is a u32.
/// For pointer_size == 8, the count is a u64.
///
/// Ported from Ghidra's `ArtMethodGroup`.
#[derive(Debug, Clone)]
pub struct ArtMethodGroup {
    /// Number of methods in the group.
    pub method_count: u64,
    /// The methods.
    pub methods: Vec<ArtMethod>,
}

impl ArtMethodGroup {
    /// Sanity limit on method count.
    const MAX_METHOD_COUNT: u64 = 0xFFFF;

    /// Parse an ArtMethodGroup from raw bytes.
    ///
    /// `data`: byte slice starting at the group.
    /// `pointer_size`: 4 or 8.
    /// `art_version`: ART version string.
    pub fn parse(data: &[u8], pointer_size: u32, art_version: &str) -> Result<Self, String> {
        let (count, count_size) = if pointer_size == 8 {
            if data.len() < 8 {
                return Err("Data too short for ArtMethodGroup count (64-bit)".to_string());
            }
            (u64::from_le_bytes(data[0..8].try_into().unwrap()), 8)
        } else {
            if data.len() < 4 {
                return Err("Data too short for ArtMethodGroup count (32-bit)".to_string());
            }
            (u32::from_le_bytes(data[0..4].try_into().unwrap()) as u64, 4)
        };

        if count > Self::MAX_METHOD_COUNT {
            return Err(format!("Too many ART methods: {}", count));
        }

        let method_size = ArtMethod::size_for(art_version, pointer_size)?;
        let mut methods = Vec::with_capacity(count as usize);
        let mut pos = count_size;

        for _ in 0..count {
            if pos + method_size > data.len() {
                return Err("Data too short while parsing ArtMethodGroup methods".to_string());
            }
            let method = ArtMethod::parse(&data[pos..pos + method_size], pointer_size, art_version)?;
            methods.push(method);
            pos += method_size;
        }

        Ok(ArtMethodGroup {
            method_count: count,
            methods,
        })
    }

    /// Returns the total number of methods in this group.
    pub fn method_count(&self) -> u64 {
        self.method_count
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v017_32bit() {
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // declaring_class
        data[4..8].copy_from_slice(&0x2000u32.to_le_bytes()); // dex_cache_resolved_methods
        data[8..12].copy_from_slice(&0x3000u32.to_le_bytes()); // dex_cache_resolved_types
        data[12..16].copy_from_slice(&0x0009u32.to_le_bytes()); // access_flags = PUBLIC | STATIC
        data[16..20].copy_from_slice(&0x100u32.to_le_bytes()); // dex_code_item_offset
        data[20..24].copy_from_slice(&5u32.to_le_bytes()); // dex_method_index

        let method = ArtMethod::parse(&data, 4, "017").unwrap();
        assert_eq!(method.declaring_class, 0x1000);
        assert!(method.is_public());
        assert!(method.is_static());
        assert_eq!(method.dex_code_item_offset, 0x100);
    }

    #[test]
    fn test_parse_v074_64bit() {
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(&0xABCDu32.to_le_bytes()); // declaring_class
        data[4..8].copy_from_slice(&0x0001u32.to_le_bytes()); // access_flags = PUBLIC
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // dex_code_item_offset
        data[12..16].copy_from_slice(&10u32.to_le_bytes()); // dex_method_index
        // 24..32: data
        data[24..32].copy_from_slice(&0xDEADBEEFu64.to_le_bytes());
        // 32..40: entry_point_from_quick_compiled_code
        data[32..40].copy_from_slice(&0xCAFEBABEu64.to_le_bytes());

        let method = ArtMethod::parse(&data, 8, "074").unwrap();
        assert_eq!(method.declaring_class, 0xABCD);
        assert!(method.is_public());
        assert_eq!(method.data, 0xDEADBEEF);
        assert_eq!(method.entry_point_from_quick_compiled_code, 0xCAFEBABE);
    }

    #[test]
    fn test_parse_v099_64bit() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&0x1234u32.to_le_bytes()); // declaring_class
        data[4..8].copy_from_slice(&0x0400u32.to_le_bytes()); // access_flags = ABSTRACT
        data[8..12].copy_from_slice(&5u32.to_le_bytes()); // dex_method_index
        // 20..24: data
        data[20..24].copy_from_slice(&0x42u32.to_le_bytes());
        // 24..32: entry_point_from_quick_compiled_code
        data[24..32].copy_from_slice(&0x99u64.to_le_bytes());

        let method = ArtMethod::parse(&data, 8, "099").unwrap();
        assert_eq!(method.declaring_class, 0x1234);
        assert!(method.is_abstract());
        assert_eq!(method.dex_method_index, 5);
        assert_eq!(method.data, 0x42);
    }

    #[test]
    fn test_parse_unsupported_version() {
        let data = vec![0u8; 40];
        assert!(ArtMethod::parse(&data, 4, "999").is_err());
    }

    #[test]
    fn test_parse_truncated() {
        let data = vec![0u8; 10];
        assert!(ArtMethod::parse(&data, 4, "017").is_err());
    }

    #[test]
    fn test_method_size_for() {
        assert_eq!(ArtMethod::size_for("017", 4).unwrap(), 40);
        assert_eq!(ArtMethod::size_for("029", 4).unwrap(), 40);
        assert_eq!(ArtMethod::size_for("029", 8).unwrap(), 56);
        assert_eq!(ArtMethod::size_for("074", 4).unwrap(), 28);
        assert_eq!(ArtMethod::size_for("074", 8).unwrap(), 40);
        assert_eq!(ArtMethod::size_for("099", 4).unwrap(), 24);
        assert_eq!(ArtMethod::size_for("099", 8).unwrap(), 32);
    }

    #[test]
    fn test_method_group_parse() {
        // Group: count(u32=1) + method(v074, 32-bit, 28 bytes)
        let mut data = vec![0u8; 4 + 28];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // count
        // method at offset 4
        data[4..8].copy_from_slice(&0x100u32.to_le_bytes()); // declaring_class
        data[8..12].copy_from_slice(&0x0001u32.to_le_bytes()); // access_flags
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // dex_code_item_offset
        data[16..20].copy_from_slice(&0u32.to_le_bytes()); // dex_method_index
        data[20..22].copy_from_slice(&0u16.to_le_bytes()); // method_index
        data[22..24].copy_from_slice(&0u16.to_le_bytes()); // hotness_count

        let group = ArtMethodGroup::parse(&data, 4, "074").unwrap();
        assert_eq!(group.method_count(), 1);
        assert_eq!(group.methods[0].declaring_class, 0x100);
    }

    #[test]
    fn test_method_group_too_many() {
        // count = 0x10000 (too large)
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&0x10000u32.to_le_bytes());
        assert!(ArtMethodGroup::parse(&data, 4, "074").is_err());
    }
}
