//! Dyld cache slide info structures (v1 through v5).
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.macho.dyld` package.
//!
//! Slide info describes how pointers within the dyld shared cache must be
//! relocated (slid) from their on-disk positions to their in-memory addresses.
//! Each version uses a different encoding scheme:
//!
//! - **v1**: Bit-table per page (iOS 8 and earlier)
//! - **v2**: Delta-chain with `deltaMask`/`valueAdd` (iOS 10-11)
//! - **v3**: Authenticated pointer chains with PAC support (iOS 12+)
//! - **v4**: 32-bit delta-chain variant (not yet seen in the wild)
//! - **v5**: ARM64e shared-cache chained pointers (macOS 14.4+)
//!
//! References:
//! - <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h>

use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Bytes per chain offset entry in v2/v4 page starts.
pub const BYTES_PER_CHAIN_OFFSET: u64 = 4;
/// Mask for extracting the chain offset from a page start entry.
pub const CHAIN_OFFSET_MASK: u16 = 0x3FFF;

// v2 constants
const DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE: u16 = 0x4000;
const DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA: u16 = 0x8000;

// v3 constants
const DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE: u16 = 0xFFFF;

// v4 constants
const DYLD_CACHE_SLIDE4_PAGE_NO_REBASE: u16 = 0xFFFF;
const DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA: u16 = 0x8000;

// v5 constants
const DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE: u16 = 0xFFFF;

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldFixup
// ═══════════════════════════════════════════════════════════════════════════════════

/// Stores information needed to perform a dyld pointer fixup.
///
/// Each fixup records the offset of a pointer within the mapping, its
/// corrected value, the pointer size, and optional symbol/library info.
#[derive(Debug, Clone)]
pub struct DyldFixup {
    /// Offset (from mapping base) of the pointer to fix up.
    pub offset: u64,
    /// The corrected pointer value after applying the slide.
    pub value: u64,
    /// Size of the pointer in bytes (4 or 8).
    pub size: u32,
    /// Symbol name associated with this fixup (if a bind).
    pub symbol: Option<String>,
    /// Library ordinal associated with this fixup (if a bind).
    pub lib_ordinal: Option<i32>,
}

impl DyldFixup {
    pub fn new(offset: u64, value: u64, size: u32) -> Self {
        Self {
            offset,
            value,
            size,
            symbol: None,
            lib_ordinal: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheSlideInfo (unified enum)
// ═══════════════════════════════════════════════════════════════════════════════════

/// A parsed dyld cache slide info structure, covering versions 1 through 5.
///
/// Call [`DyldCacheSlideInfo::parse`] to auto-detect the version from the
/// data, or use one of the version-specific `parse_v*` methods directly.
#[derive(Debug, Clone)]
pub enum DyldCacheSlideInfo {
    V1(DyldCacheSlideInfo1),
    V2(DyldCacheSlideInfo2),
    V3(DyldCacheSlideInfo3),
    V4(DyldCacheSlideInfo4),
    V5(DyldCacheSlideInfo5),
}

impl DyldCacheSlideInfo {
    /// Parse slide info from a byte slice, auto-detecting the version.
    ///
    /// `data` must start at the slide info offset within the cache file.
    /// Returns `None` if the version is unrecognized.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        match version {
            1 => DyldCacheSlideInfo1::parse(data).ok().map(Self::V1),
            2 => DyldCacheSlideInfo2::parse(data).ok().map(Self::V2),
            3 => DyldCacheSlideInfo3::parse(data).ok().map(Self::V3),
            4 => DyldCacheSlideInfo4::parse(data).ok().map(Self::V4),
            5 => DyldCacheSlideInfo5::parse(data).ok().map(Self::V5),
            _ => None,
        }
    }

    /// Returns the version number.
    pub fn version(&self) -> u32 {
        match self {
            Self::V1(s) => s.version,
            Self::V2(s) => s.version,
            Self::V3(s) => s.version,
            Self::V4(s) => s.version,
            Self::V5(s) => s.version,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheSlideInfo1
// ═══════════════════════════════════════════════════════════════════════════════════

/// `dyld_cache_slide_info` version 1.
///
/// Seen in iOS 8 and earlier. Uses a TOC + per-entry bit-table to indicate
/// which 4-byte addresses need sliding.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo1 {
    /// Version number (always 1).
    pub version: u32,
    /// Offset to the TOC array (relative to start of this structure).
    pub toc_offset: u32,
    /// Number of entries in the TOC.
    pub toc_count: u32,
    /// Offset to the entries array.
    pub entries_offset: u32,
    /// Number of entries.
    pub entries_count: u32,
    /// Size of each entry in bytes.
    pub entries_size: u32,
    /// Table of contents: maps page index to entry index.
    pub toc: Vec<u16>,
    /// Per-entry bit tables indicating which pointers need sliding.
    pub entries: Vec<Vec<u8>>,
}

impl DyldCacheSlideInfo1 {
    /// Minimum header size (24 bytes: version + 5 u32 fields).
    const HEADER_SIZE: usize = 24;

    /// Parse a v1 slide info structure from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::HEADER_SIZE {
            return Err("Data too short for DyldCacheSlideInfo1".to_string());
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let toc_offset = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let toc_count = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let entries_offset = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let entries_count = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let entries_size = u32::from_le_bytes(data[20..24].try_into().unwrap());

        // Parse TOC (array of u16)
        let toc_start = toc_offset as usize;
        let toc_end = toc_start + toc_count as usize * 2;
        if toc_end > data.len() {
            return Err("TOC extends past end of data".to_string());
        }
        let toc: Vec<u16> = (0..toc_count as usize)
            .map(|i| {
                let off = toc_start + i * 2;
                u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
            })
            .collect();

        // Parse entries (entries_count arrays of entries_size bytes each)
        let ent_start = entries_offset as usize;
        let ent_total = entries_count as usize * entries_size as usize;
        if ent_start + ent_total > data.len() {
            return Err("Entries extend past end of data".to_string());
        }
        let entries: Vec<Vec<u8>> = (0..entries_count as usize)
            .map(|i| {
                let off = ent_start + i * entries_size as usize;
                data[off..off + entries_size as usize].to_vec()
            })
            .collect();

        Ok(DyldCacheSlideInfo1 {
            version,
            toc_offset,
            toc_count,
            entries_offset,
            entries_count,
            entries_size,
            toc,
            entries,
        })
    }

    /// Compute slide fixups for the given mapping data.
    ///
    /// `mapping_data` is the raw bytes of the memory region covered by this
    /// slide info. Each bit in the bit-tables indicates whether the
    /// corresponding 4-byte-aligned pointer needs a fixup.
    pub fn get_slide_fixups(&self, mapping_data: &[u8]) -> Vec<DyldFixup> {
        let mut fixups = Vec::new();

        for toc_index in 0..self.toc_count as usize {
            let entry_index = self.toc[toc_index] as usize;
            if entry_index >= self.entries_count as usize {
                continue;
            }

            let entry = &self.entries[entry_index];
            let segment_offset = 4096u64 * toc_index as u64;

            for page_entries_index in 0..128usize {
                if page_entries_index >= entry.len() {
                    break;
                }
                let prt_entry_bitmap = entry[page_entries_index];

                if prt_entry_bitmap != 0 {
                    for bit_map_index in 0..8u64 {
                        if (prt_entry_bitmap & (1 << bit_map_index)) != 0 {
                            let page_offset =
                                page_entries_index as u64 * 8 * 4 + bit_map_index * 4;
                            let data_offset = (segment_offset + page_offset) as usize;
                            if data_offset + 8 <= mapping_data.len() {
                                let value = u64::from_le_bytes(
                                    mapping_data[data_offset..data_offset + 8]
                                        .try_into()
                                        .unwrap(),
                                );
                                fixups.push(DyldFixup::new(segment_offset + page_offset, value, 8));
                            }
                        }
                    }
                }
            }
        }

        fixups
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheSlideInfo2
// ═══════════════════════════════════════════════════════════════════════════════════

/// `dyld_cache_slide_info2` structure.
///
/// Seen in iOS 10 and 11. Uses delta-chained pointers with a configurable
/// `delta_mask` and `value_add` for rebase computation.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo2 {
    /// Version number (always 2).
    pub version: u32,
    /// Page size (typically 4096 or 16384).
    pub page_size: u32,
    /// Offset to the page starts array.
    pub page_starts_offset: u32,
    /// Number of page start entries.
    pub page_starts_count: u32,
    /// Offset to the page extras array.
    pub page_extras_offset: u32,
    /// Number of page extras entries.
    pub page_extras_count: u32,
    /// Bitmask selecting the delta bits within each chain value.
    pub delta_mask: u64,
    /// Value added to each rebase target.
    pub value_add: u64,
    /// Per-page chain start offsets.
    pub page_starts: Vec<u16>,
    /// Extra chain start entries for pages with multiple chains.
    pub page_extras: Vec<u16>,
}

impl DyldCacheSlideInfo2 {
    /// Minimum header size (40 bytes: version + 5 u32 + 2 u64).
    const HEADER_SIZE: usize = 40;

    /// Parse a v2 slide info structure from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::HEADER_SIZE {
            return Err("Data too short for DyldCacheSlideInfo2".to_string());
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let page_size = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let page_starts_offset = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let page_starts_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let page_extras_offset = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let page_extras_count = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let delta_mask = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let value_add = u64::from_le_bytes(data[32..40].try_into().unwrap());

        // Parse page_starts
        let ps_start = page_starts_offset as usize;
        let ps_end = ps_start + page_starts_count as usize * 2;
        if ps_end > data.len() {
            return Err("page_starts extends past end of data".to_string());
        }
        let page_starts: Vec<u16> = (0..page_starts_count as usize)
            .map(|i| {
                let off = ps_start + i * 2;
                u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
            })
            .collect();

        // Parse page_extras
        let pe_start = page_extras_offset as usize;
        let pe_end = pe_start + page_extras_count as usize * 2;
        if pe_end > data.len() {
            return Err("page_extras extends past end of data".to_string());
        }
        let page_extras: Vec<u16> = (0..page_extras_count as usize)
            .map(|i| {
                let off = pe_start + i * 2;
                u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
            })
            .collect();

        Ok(DyldCacheSlideInfo2 {
            version,
            page_size,
            page_starts_offset,
            page_starts_count,
            page_extras_offset,
            page_extras_count,
            delta_mask,
            value_add,
            page_starts,
            page_extras,
        })
    }

    /// Compute slide fixups for the given mapping data.
    pub fn get_slide_fixups(&self, mapping_data: &[u8], pointer_size: u32) -> Vec<DyldFixup> {
        let mut fixups = Vec::new();

        for index in 0..self.page_starts_count as usize {
            let segment_offset = self.page_size as u64 * index as u64;
            let page_entry = self.page_starts[index];

            if page_entry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE {
                continue;
            }

            if (page_entry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) != 0 {
                let mut extra_index = (page_entry & CHAIN_OFFSET_MASK) as usize;
                loop {
                    if extra_index >= self.page_extras.len() {
                        break;
                    }
                    let extra_entry = self.page_extras[extra_index];
                    let page_offset =
                        (extra_entry & CHAIN_OFFSET_MASK) as u64 * BYTES_PER_CHAIN_OFFSET;
                    Self::process_pointer_chain_v2(
                        &mut fixups,
                        mapping_data,
                        segment_offset,
                        page_offset,
                        pointer_size,
                        self.delta_mask,
                        self.value_add,
                    );
                    if (extra_entry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) == 0 {
                        break;
                    }
                    extra_index += 1;
                }
            } else {
                let page_offset = page_entry as u64 * BYTES_PER_CHAIN_OFFSET;
                Self::process_pointer_chain_v2(
                    &mut fixups,
                    mapping_data,
                    segment_offset,
                    page_offset,
                    pointer_size,
                    self.delta_mask,
                    self.value_add,
                );
            }
        }

        fixups
    }

    fn process_pointer_chain_v2(
        fixups: &mut Vec<DyldFixup>,
        mapping_data: &[u8],
        segment_offset: u64,
        mut page_offset: u64,
        pointer_size: u32,
        delta_mask: u64,
        value_add: u64,
    ) {
        let value_mask = !delta_mask;
        let delta_shift = delta_mask.trailing_zeros();

        loop {
            let data_offset = segment_offset + page_offset;
            let data_usize = data_offset as usize;

            let chain_value: u64 = if pointer_size == 8 {
                if data_usize + 8 > mapping_data.len() {
                    break;
                }
                u64::from_le_bytes(mapping_data[data_usize..data_usize + 8].try_into().unwrap())
            } else {
                if data_usize + 4 > mapping_data.len() {
                    break;
                }
                u32::from_le_bytes(mapping_data[data_usize..data_usize + 4].try_into().unwrap())
                    as u64
            };

            let delta = (chain_value & delta_mask) >> delta_shift;
            let mut chain_value = chain_value & value_mask;

            if chain_value != 0 {
                chain_value = chain_value.wrapping_add(value_add);
                fixups.push(DyldFixup::new(data_offset, chain_value, pointer_size));
            }

            if delta == 0 {
                break;
            }
            page_offset = page_offset.wrapping_add(delta * 4);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheSlideInfo3
// ═══════════════════════════════════════════════════════════════════════════════════

/// `dyld_cache_slide_info3` structure.
///
/// Seen in iOS 12 and later. Uses authenticated pointer chains with PAC
/// (Pointer Authentication Code) support.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo3 {
    /// Version number (always 3).
    pub version: u32,
    /// Page size (typically 4096 or 16384).
    pub page_size: u32,
    /// Number of page start entries.
    pub page_starts_count: u32,
    /// Value added to authenticated pointer targets.
    pub auth_value_add: u64,
    /// Per-page chain start offsets (byte-based).
    pub page_starts: Vec<u16>,
}

impl DyldCacheSlideInfo3 {
    /// Header size (24 bytes: version + pageSize + pageStartsCount + pad + authValueAdd).
    const HEADER_SIZE: usize = 24;

    /// Parse a v3 slide info structure from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::HEADER_SIZE {
            return Err("Data too short for DyldCacheSlideInfo3".to_string());
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let page_size = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let page_starts_count = u32::from_le_bytes(data[8..12].try_into().unwrap());
        // skip padding at 12..16
        let auth_value_add = u64::from_le_bytes(data[16..24].try_into().unwrap());

        let ps_start = Self::HEADER_SIZE;
        let ps_end = ps_start + page_starts_count as usize * 2;
        if ps_end > data.len() {
            return Err("page_starts extends past end of data".to_string());
        }
        let page_starts: Vec<u16> = (0..page_starts_count as usize)
            .map(|i| {
                let off = ps_start + i * 2;
                u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
            })
            .collect();

        Ok(DyldCacheSlideInfo3 {
            version,
            page_size,
            page_starts_count,
            auth_value_add,
            page_starts,
        })
    }

    /// Compute slide fixups for the given mapping data.
    pub fn get_slide_fixups(&self, mapping_data: &[u8]) -> Vec<DyldFixup> {
        let mut fixups = Vec::new();

        for index in 0..self.page_starts_count as usize {
            let segment_offset = self.page_size as u64 * index as u64;
            let page_entry = self.page_starts[index];

            if page_entry == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
                continue;
            }

            let page_offset = (page_entry as u64 / 8) * 8;
            Self::process_pointer_chain_v3(
                &mut fixups,
                mapping_data,
                segment_offset,
                page_offset,
                self.auth_value_add,
            );
        }

        fixups
    }

    fn process_pointer_chain_v3(
        fixups: &mut Vec<DyldFixup>,
        mapping_data: &[u8],
        segment_offset: u64,
        mut page_offset: u64,
        auth_value_add: u64,
    ) {
        loop {
            let data_offset = segment_offset + page_offset;
            let data_usize = data_offset as usize;

            if data_usize + 8 > mapping_data.len() {
                break;
            }
            let chain_value =
                u64::from_le_bytes(mapping_data[data_usize..data_usize + 8].try_into().unwrap());

            let is_authenticated = (chain_value >> 63) != 0;
            let delta = (chain_value & (0x7FFu64 << 51)) >> 51;

            let final_value = if is_authenticated {
                let offset_from_shared_cache_base = chain_value & 0xFFFFFFFF;
                offset_from_shared_cache_base.wrapping_add(auth_value_add)
            } else {
                let top8_bits = chain_value & 0x0007F800_00000000;
                let bottom43_bits = chain_value & 0x000007FF_FFFFFFFF;
                (top8_bits << 13) | bottom43_bits
            };

            fixups.push(DyldFixup::new(data_offset, final_value, 8));

            if delta == 0 {
                break;
            }
            page_offset = page_offset.wrapping_add(delta * 8);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheSlideInfo4
// ═══════════════════════════════════════════════════════════════════════════════════

/// `dyld_cache_slide_info4` structure.
///
/// A 32-bit delta-chain variant. Not yet seen in the wild.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo4 {
    /// Version number (always 4).
    pub version: u32,
    /// Page size.
    pub page_size: u32,
    /// Offset to the page starts array.
    pub page_starts_offset: u32,
    /// Number of page start entries.
    pub page_starts_count: u32,
    /// Offset to the page extras array.
    pub page_extras_offset: u32,
    /// Number of page extras entries.
    pub page_extras_count: u32,
    /// Bitmask selecting the delta bits within each chain value.
    pub delta_mask: u64,
    /// Value added to each rebase target.
    pub value_add: u64,
    /// Per-page chain start offsets.
    pub page_starts: Vec<u16>,
    /// Extra chain start entries for pages with multiple chains.
    pub page_extras: Vec<u16>,
}

impl DyldCacheSlideInfo4 {
    /// Header size (40 bytes: version + 5 u32 + 2 u64).
    const HEADER_SIZE: usize = 40;

    /// Parse a v4 slide info structure from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::HEADER_SIZE {
            return Err("Data too short for DyldCacheSlideInfo4".to_string());
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let page_size = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let page_starts_offset = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let page_starts_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let page_extras_offset = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let page_extras_count = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let delta_mask = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let value_add = u64::from_le_bytes(data[32..40].try_into().unwrap());

        // Parse page_starts
        let ps_start = page_starts_offset as usize;
        let ps_end = ps_start + page_starts_count as usize * 2;
        if ps_end > data.len() {
            return Err("page_starts extends past end of data".to_string());
        }
        let page_starts: Vec<u16> = (0..page_starts_count as usize)
            .map(|i| {
                let off = ps_start + i * 2;
                u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
            })
            .collect();

        // Parse page_extras
        let pe_start = page_extras_offset as usize;
        let pe_end = pe_start + page_extras_count as usize * 2;
        if pe_end > data.len() {
            return Err("page_extras extends past end of data".to_string());
        }
        let page_extras: Vec<u16> = (0..page_extras_count as usize)
            .map(|i| {
                let off = pe_start + i * 2;
                u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
            })
            .collect();

        Ok(DyldCacheSlideInfo4 {
            version,
            page_size,
            page_starts_offset,
            page_starts_count,
            page_extras_offset,
            page_extras_count,
            delta_mask,
            value_add,
            page_starts,
            page_extras,
        })
    }

    /// Compute slide fixups for the given mapping data.
    pub fn get_slide_fixups(&self, mapping_data: &[u8]) -> Vec<DyldFixup> {
        let mut fixups = Vec::new();

        for index in 0..self.page_starts_count as usize {
            let segment_offset = self.page_size as u64 * index as u64;
            let page_entry = self.page_starts[index];

            if page_entry == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE {
                continue;
            }

            if (page_entry & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) != 0 {
                let mut extra_index = (page_entry & CHAIN_OFFSET_MASK) as usize;
                loop {
                    if extra_index >= self.page_extras.len() {
                        break;
                    }
                    let extra_entry = self.page_extras[extra_index];
                    let page_offset =
                        (extra_entry & CHAIN_OFFSET_MASK) as u64 * BYTES_PER_CHAIN_OFFSET;
                    Self::process_pointer_chain_v4(
                        &mut fixups,
                        mapping_data,
                        segment_offset,
                        page_offset,
                        self.delta_mask,
                        self.value_add,
                    );
                    if (extra_entry & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) == 0 {
                        break;
                    }
                    extra_index += 1;
                }
            } else {
                let page_offset = page_entry as u64 * BYTES_PER_CHAIN_OFFSET;
                Self::process_pointer_chain_v4(
                    &mut fixups,
                    mapping_data,
                    segment_offset,
                    page_offset,
                    self.delta_mask,
                    self.value_add,
                );
            }
        }

        fixups
    }

    fn process_pointer_chain_v4(
        fixups: &mut Vec<DyldFixup>,
        mapping_data: &[u8],
        segment_offset: u64,
        mut page_offset: u64,
        delta_mask: u64,
        value_add: u64,
    ) {
        let value_mask = !delta_mask;
        let delta_shift = delta_mask.trailing_zeros();

        loop {
            let data_offset = segment_offset + page_offset;
            let data_usize = data_offset as usize;

            if data_usize + 4 > mapping_data.len() {
                break;
            }
            let raw = u32::from_le_bytes(
                mapping_data[data_usize..data_usize + 4]
                    .try_into()
                    .unwrap(),
            );

            let delta = ((raw as u64) & delta_mask) >> delta_shift;
            let mut chain_value = (raw as u64) & value_mask;

            if (chain_value & 0xFFFF8000) == 0 {
                // small positive non-pointer, use as-is
            } else if (chain_value & 0x3FFF8000) == 0x3FFF8000 {
                chain_value |= 0xC000_0000;
            } else {
                chain_value = chain_value.wrapping_add(value_add);
            }

            fixups.push(DyldFixup::new(data_offset, chain_value, 4));

            if delta == 0 {
                break;
            }
            page_offset = page_offset.wrapping_add(delta * 4);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// DyldCacheSlideInfo5
// ═══════════════════════════════════════════════════════════════════════════════════

/// `dyld_cache_slide_info5` structure.
///
/// Seen in macOS 14.4 and later. Uses ARM64e shared-cache chained pointers
/// with pointer authentication.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo5 {
    /// Version number (always 5).
    pub version: u32,
    /// Page size.
    pub page_size: u32,
    /// Number of page start entries.
    pub page_starts_count: u32,
    /// Value added to pointer targets.
    pub value_add: u64,
    /// Per-page chain start offsets (byte-based).
    pub page_starts: Vec<u16>,
}

impl DyldCacheSlideInfo5 {
    /// Header size (24 bytes: version + pageSize + pageStartsCount + pad + valueAdd).
    const HEADER_SIZE: usize = 24;

    /// Parse a v5 slide info structure from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::HEADER_SIZE {
            return Err("Data too short for DyldCacheSlideInfo5".to_string());
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let page_size = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let page_starts_count = u32::from_le_bytes(data[8..12].try_into().unwrap());
        // skip padding at 12..16
        let value_add = u64::from_le_bytes(data[16..24].try_into().unwrap());

        let ps_start = Self::HEADER_SIZE;
        let ps_end = ps_start + page_starts_count as usize * 2;
        if ps_end > data.len() {
            return Err("page_starts extends past end of data".to_string());
        }
        let page_starts: Vec<u16> = (0..page_starts_count as usize)
            .map(|i| {
                let off = ps_start + i * 2;
                u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
            })
            .collect();

        Ok(DyldCacheSlideInfo5 {
            version,
            page_size,
            page_starts_count,
            value_add,
            page_starts,
        })
    }

    /// Compute slide fixups for the given mapping data.
    ///
    /// Uses the ARM64e shared-cache chained pointer format: 8-byte entries
    /// with stride of 8, 11-bit delta field at bits [51:61].
    pub fn get_slide_fixups(&self, mapping_data: &[u8]) -> Vec<DyldFixup> {
        let mut fixups = Vec::new();

        for index in 0..self.page_starts_count as usize {
            let segment_offset = self.page_size as u64 * index as u64;
            let page_entry = self.page_starts[index];

            if page_entry == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE {
                continue;
            }

            let page_offset = (page_entry as u64 / 8) * 8;
            Self::process_pointer_chain_v5(
                &mut fixups,
                mapping_data,
                segment_offset,
                page_offset,
                self.value_add,
            );
        }

        fixups
    }

    fn process_pointer_chain_v5(
        fixups: &mut Vec<DyldFixup>,
        mapping_data: &[u8],
        segment_offset: u64,
        mut page_offset: u64,
        value_add: u64,
    ) {
        // ARM64e shared-cache chained pointer:
        //   stride = 8, size = 8
        //   delta = bits [51:61]  (11 bits)
        //   authenticated = bit 63
        let stride = 8u64;

        loop {
            let data_offset = segment_offset + page_offset;
            let data_usize = data_offset as usize;

            if data_usize + 8 > mapping_data.len() {
                break;
            }
            let chain_value =
                u64::from_le_bytes(mapping_data[data_usize..data_usize + 8].try_into().unwrap());

            let is_authenticated = (chain_value >> 63) != 0;
            let delta = (chain_value >> 51) & 0x7FF;

            // Extract target: lower 32 bits (shared cache offset)
            let target = chain_value & 0xFFFF_FFFF;
            let mut new_ptr_value = target.wrapping_add(value_add);

            if !is_authenticated {
                // Reconstruct high 8 bits from bits [34:41]
                let high8 = (chain_value >> 34) & 0xFF;
                new_ptr_value |= high8 << 56;
            }

            fixups.push(DyldFixup::new(data_offset, new_ptr_value, 8));

            if delta == 0 {
                break;
            }
            page_offset = page_offset.wrapping_add(delta * stride);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Display
// ═══════════════════════════════════════════════════════════════════════════════════

impl fmt::Display for DyldCacheSlideInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1(s) => write!(f, "SlideInfo v1 (toc_count={}, entries={})", s.toc_count, s.entries_count),
            Self::V2(s) => write!(f, "SlideInfo v2 (pages={}, value_add=0x{:x})", s.page_starts_count, s.value_add),
            Self::V3(s) => write!(f, "SlideInfo v3 (pages={}, auth_value_add=0x{:x})", s.page_starts_count, s.auth_value_add),
            Self::V4(s) => write!(f, "SlideInfo v4 (pages={}, value_add=0x{:x})", s.page_starts_count, s.value_add),
            Self::V5(s) => write!(f, "SlideInfo v5 (pages={}, value_add=0x{:x})", s.page_starts_count, s.value_add),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── v1 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_slide_info1_parse() {
        let mut data = vec![0u8; 0x200];
        // version = 1
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        // toc_offset = 0x18 (right after header)
        data[4..8].copy_from_slice(&0x18u32.to_le_bytes());
        // toc_count = 2
        data[8..12].copy_from_slice(&2u32.to_le_bytes());
        // entries_offset = 0x20
        data[12..16].copy_from_slice(&0x20u32.to_le_bytes());
        // entries_count = 1
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        // entries_size = 128
        data[20..24].copy_from_slice(&128u32.to_le_bytes());

        // TOC: [0, 0]
        data[0x18..0x1a].copy_from_slice(&0u16.to_le_bytes());
        data[0x1a..0x1c].copy_from_slice(&0u16.to_le_bytes());

        let info = DyldCacheSlideInfo1::parse(&data).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.toc_count, 2);
        assert_eq!(info.entries_count, 1);
        assert_eq!(info.entries_size, 128);
        assert_eq!(info.toc.len(), 2);
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].len(), 128);
    }

    #[test]
    fn test_slide_info1_parse_truncated() {
        let data = vec![0u8; 10];
        assert!(DyldCacheSlideInfo1::parse(&data).is_err());
    }

    // ── v2 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_slide_info2_parse() {
        let mut data = vec![0u8; 0x100];
        // version = 2
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        // page_size = 4096
        data[4..8].copy_from_slice(&4096u32.to_le_bytes());
        // page_starts_offset = 0x28
        data[8..12].copy_from_slice(&0x28u32.to_le_bytes());
        // page_starts_count = 1
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        // page_extras_offset = 0x2a
        data[16..20].copy_from_slice(&0x2au32.to_le_bytes());
        // page_extras_count = 0
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        // delta_mask = 0x3FF8000000000000
        data[24..32].copy_from_slice(&0x3FF8_0000_0000_0000u64.to_le_bytes());
        // value_add = 0x180000000
        data[32..40].copy_from_slice(&0x18000_0000u64.to_le_bytes());
        // page_starts[0] = DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE (skip page)
        data[0x28..0x2a].copy_from_slice(&DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE.to_le_bytes());

        let info = DyldCacheSlideInfo2::parse(&data).unwrap();
        assert_eq!(info.version, 2);
        assert_eq!(info.page_size, 4096);
        assert_eq!(info.page_starts_count, 1);
        assert_eq!(info.delta_mask, 0x3FF8_0000_0000_0000);
        assert_eq!(info.value_add, 0x18000_0000);
    }

    // ── v3 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_slide_info3_parse() {
        let mut data = vec![0u8; 0x100];
        // version = 3
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        // page_size = 4096
        data[4..8].copy_from_slice(&4096u32.to_le_bytes());
        // page_starts_count = 1
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        // padding at 12..16
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        // auth_value_add = 0x180000000
        data[16..24].copy_from_slice(&0x18000_0000u64.to_le_bytes());
        // page_starts[0] = 0xFFFF (no rebase)
        data[24..26].copy_from_slice(&DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE.to_le_bytes());

        let info = DyldCacheSlideInfo3::parse(&data).unwrap();
        assert_eq!(info.version, 3);
        assert_eq!(info.page_size, 4096);
        assert_eq!(info.page_starts_count, 1);
        assert_eq!(info.auth_value_add, 0x18000_0000);
        assert_eq!(info.page_starts[0], 0xFFFF);
    }

    #[test]
    fn test_slide_info3_fixups_no_rebase() {
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..8].copy_from_slice(&4096u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..24].copy_from_slice(&0x18000_0000u64.to_le_bytes());
        data[24..26].copy_from_slice(&0xFFFFu16.to_le_bytes()); // no rebase

        let info = DyldCacheSlideInfo3::parse(&data).unwrap();
        let fixups = info.get_slide_fixups(&[0u8; 4096]);
        assert!(fixups.is_empty());
    }

    // ── v4 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_slide_info4_parse() {
        let mut data = vec![0u8; 0x100];
        // version = 4
        data[0..4].copy_from_slice(&4u32.to_le_bytes());
        data[4..8].copy_from_slice(&4096u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x28u32.to_le_bytes()); // page_starts_offset
        data[12..16].copy_from_slice(&1u32.to_le_bytes()); // page_starts_count
        data[16..20].copy_from_slice(&0x2au32.to_le_bytes()); // page_extras_offset
        data[20..24].copy_from_slice(&0u32.to_le_bytes()); // page_extras_count
        data[24..32].copy_from_slice(&0xC000_0000u64.to_le_bytes()); // delta_mask
        data[32..40].copy_from_slice(&0x18000_0000u64.to_le_bytes()); // value_add
        data[0x28..0x2a].copy_from_slice(&DYLD_CACHE_SLIDE4_PAGE_NO_REBASE.to_le_bytes());

        let info = DyldCacheSlideInfo4::parse(&data).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.page_size, 4096);
        assert_eq!(info.delta_mask, 0xC000_0000);
    }

    // ── v5 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_slide_info5_parse() {
        let mut data = vec![0u8; 0x100];
        // version = 5
        data[0..4].copy_from_slice(&5u32.to_le_bytes());
        data[4..8].copy_from_slice(&4096u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes()); // page_starts_count
        // padding at 12..16
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..24].copy_from_slice(&0x18000_0000u64.to_le_bytes()); // value_add
        data[24..26].copy_from_slice(&DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE.to_le_bytes());

        let info = DyldCacheSlideInfo5::parse(&data).unwrap();
        assert_eq!(info.version, 5);
        assert_eq!(info.page_size, 4096);
        assert_eq!(info.page_starts_count, 1);
        assert_eq!(info.value_add, 0x18000_0000);
    }

    #[test]
    fn test_slide_info5_fixups_no_rebase() {
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&5u32.to_le_bytes());
        data[4..8].copy_from_slice(&4096u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..24].copy_from_slice(&0x18000_0000u64.to_le_bytes());
        data[24..26].copy_from_slice(&0xFFFFu16.to_le_bytes());

        let info = DyldCacheSlideInfo5::parse(&data).unwrap();
        let fixups = info.get_slide_fixups(&[0u8; 4096]);
        assert!(fixups.is_empty());
    }

    // ── Unified enum ───────────────────────────────────────────────────────

    #[test]
    fn test_unified_parse() {
        // v3 header
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..8].copy_from_slice(&4096u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        data[16..24].copy_from_slice(&0x18000_0000u64.to_le_bytes());

        let info = DyldCacheSlideInfo::parse(&data).unwrap();
        assert_eq!(info.version(), 3);
        assert!(info.to_string().contains("SlideInfo v3"));
    }

    #[test]
    fn test_unified_parse_unknown_version() {
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        assert!(DyldCacheSlideInfo::parse(&data).is_none());
    }

    #[test]
    fn test_unified_parse_too_short() {
        let data = vec![0u8; 2];
        assert!(DyldCacheSlideInfo::parse(&data).is_none());
    }

    // ── DyldFixup ──────────────────────────────────────────────────────────

    #[test]
    fn test_dyld_fixup_new() {
        let fixup = DyldFixup::new(0x100, 0x18000_0000, 8);
        assert_eq!(fixup.offset, 0x100);
        assert_eq!(fixup.value, 0x18000_0000);
        assert_eq!(fixup.size, 8);
        assert!(fixup.symbol.is_none());
        assert!(fixup.lib_ordinal.is_none());
    }

    // ── v3 authenticated pointer chain ─────────────────────────────────────

    #[test]
    fn test_slide_info3_authenticated_chain() {
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..8].copy_from_slice(&4096u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        // auth_value_add = 0x180000000
        data[16..24].copy_from_slice(&0x18000_0000u64.to_le_bytes());
        // page_starts[0] = 0 (offset 0 into page)
        data[24..26].copy_from_slice(&0u16.to_le_bytes());

        let info = DyldCacheSlideInfo3::parse(&data).unwrap();

        // Build a mapping where offset 0 has an authenticated pointer:
        //   bit 63 = 1 (authenticated)
        //   bits [51:61] = 0 (delta = 0, end of chain)
        //   lower 32 bits = 0x1000 (offset from shared cache base)
        let mut mapping = vec![0u8; 4096];
        let chain_value: u64 = (1u64 << 63) | 0x1000;
        mapping[0..8].copy_from_slice(&chain_value.to_le_bytes());

        let fixups = info.get_slide_fixups(&mapping);
        assert_eq!(fixups.len(), 1);
        // Expected: 0x1000 + 0x180000000 = 0x180001000
        assert_eq!(fixups[0].value, 0x18000_1000);
    }

    #[test]
    fn test_slide_info3_non_authenticated_chain() {
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..8].copy_from_slice(&4096u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..24].copy_from_slice(&0x18000_0000u64.to_le_bytes());
        data[24..26].copy_from_slice(&0u16.to_le_bytes());

        let info = DyldCacheSlideInfo3::parse(&data).unwrap();

        // Non-authenticated pointer: bit 63 = 0
        // top8 bits at [35:42], bottom43 bits at [0:42]
        // For a simple test: chain_value with delta=0 and a known target
        let mut mapping = vec![0u8; 4096];
        // non-auth: top8=0, bottom43 = 0x12345678, delta=0
        let chain_value: u64 = 0x0000_0000_1234_5678;
        mapping[0..8].copy_from_slice(&chain_value.to_le_bytes());

        let fixups = info.get_slide_fixups(&mapping);
        assert_eq!(fixups.len(), 1);
        // top8_bits = 0, bottom43 = 0x12345678, result = (0 << 13) | 0x12345678
        assert_eq!(fixups[0].value, 0x1234_5678);
    }
}
