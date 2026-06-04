//! Global Symbol Information Table (GSI/PSI) hash table parsing.
//! Ported from Ghidra's GlobalSymbolTable.java and PublicSymbolTable.java.

use super::le_u32_at;

// =============================================================================
// GSI Hash Header
// =============================================================================

/// Header for the GSI (Global Symbol Information) hash table.
/// The hash table uses a simple open-addressing hash with buckets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GsiHashHeader {
    pub version_signature: u32,
    pub version_header: u32,
    pub hash_record_size: u32,
    pub num_buckets: u32,
}

impl GsiHashHeader {
    /// Parse a GSI hash header from a byte slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 { return None; }
        Some(Self {
            version_signature: le_u32_at(data, 0),
            version_header: le_u32_at(data, 4),
            hash_record_size: le_u32_at(data, 8),
            num_buckets: le_u32_at(data, 12),
        })
    }
}

// =============================================================================
// GSI Hash Table
// =============================================================================

/// A parsed global symbol hash table.
/// This is a companion to the global/public symbol streams,
/// used for O(1) lookups by name.
#[derive(Debug, Clone)]
pub struct GsiHashTable {
    pub header: GsiHashHeader,
    /// Bitmap of hash buckets (each bit = one bucket).
    pub buckets: Vec<u32>,
    /// Hash entries: each entry is (hash_value, symbol_offset).
    pub entries: Vec<GsiHashEntry>,
}

/// A single entry in the GSI hash table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GsiHashEntry {
    /// The hash value of the symbol name.
    pub hash: u32,
    /// Offset into the symbol stream where this symbol lives.
    pub symbol_offset: u32,
}

impl GsiHashTable {
    /// Parse a GSI hash table from a stream's raw data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = GsiHashHeader::parse(data)?;
        let bitmap_start = 16;
        let num_buckets = header.num_buckets as usize;
        let bucket_words = (num_buckets + 31) / 32;
        let bitmap_end = bitmap_start + bucket_words * 4;
        if data.len() < bitmap_end { return None; }
        let mut buckets = Vec::with_capacity(bucket_words);
        for i in 0..bucket_words {
            let off = bitmap_start + i * 4;
            buckets.push(le_u32_at(data, off));
        }
        // After the bitmap come hash entries (pairs of u32: hash + offset)
        let entries_start = bitmap_end;
        let mut entries = Vec::new();
        let mut pos = entries_start;
        while pos + 8 <= data.len() {
            entries.push(GsiHashEntry {
                hash: le_u32_at(data, pos),
                symbol_offset: le_u32_at(data, pos + 4),
            });
            pos += 8;
        }
        Some(Self { header, buckets, entries })
    }

    /// Check if a bucket is present (occupied).
    pub fn is_bucket_present(&self, bucket_index: u32) -> bool {
        let word = bucket_index / 32;
        let bit = bucket_index % 32;
        if let Some(&w) = self.buckets.get(word as usize) {
            (w >> bit) & 1 != 0
        } else {
            false
        }
    }
}

// =============================================================================
// Public Symbol Header
// =============================================================================

/// Header for the Public Symbol stream.
/// This includes a GSI hash table plus extra metadata.
#[derive(Debug, Clone)]
pub struct PublicSymbolHeader {
    pub sym_hash: GsiHashTable,
    /// Address map: array of offsets into the public symbol stream.
    pub address_map: Vec<u32>,
    /// Thunks: array of thunk-to-address mappings.
    pub num_thunks: u32,
    pub thunk_size: u32,
    pub isect_thunk_table: u16,
    pub padding: u16,
    pub off_thunk_table: u32,
    pub num_sections: u32,
}

impl PublicSymbolHeader {
    /// Parse the public symbol header from raw stream data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let sym_hash = GsiHashTable::parse(data)?;
        // After the hash table, parse the public symbol header extensions
        let hash_end = 16 + ((sym_hash.header.num_buckets as usize + 31) / 32) * 4 + sym_hash.entries.len() * 8;
        if data.len() < hash_end + 20 {
            return Some(Self {
                sym_hash, address_map: Vec::new(), num_thunks: 0, thunk_size: 0,
                isect_thunk_table: 0, padding: 0, off_thunk_table: 0, num_sections: 0,
            });
        }
        let p = hash_end;
        let num_thunks = le_u32_at(data, p);
        let thunk_size = le_u32_at(data, p + 4);
        let isect_thunk_table = u16::from_le_bytes([data[p + 8], data[p + 9]]);
        let padding = u16::from_le_bytes([data[p + 10], data[p + 11]]);
        let off_thunk_table = le_u32_at(data, p + 12);
        let num_sections = le_u32_at(data, p + 16);
        // Address map follows
        let addr_map_start = p + 20;
        let mut address_map = Vec::new();
        let mut pos = addr_map_start;
        while pos + 4 <= data.len() {
            address_map.push(le_u32_at(data, pos));
            pos += 4;
        }
        Some(Self { sym_hash, address_map, num_thunks, thunk_size, isect_thunk_table, padding, off_thunk_table, num_sections })
    }
}

// =============================================================================
// Symbol hashing utility
// =============================================================================

/// Compute the PDB hash for a symbol name (used by GSI/PSI).
/// This implements the standard PDB hash function.
pub fn pdb_symbol_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for &b in name.as_bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    h
}
