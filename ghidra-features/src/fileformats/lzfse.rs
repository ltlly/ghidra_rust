//! LZFSE (Lempel-Ziv Finite State Entropy) compression format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.lzfse` package.
//! LZFSE is Apple's compression algorithm used in iOS/macOS.
//!
//! References:
//! - Apple's lzfse library: <https://github.com/lzfse/lzfse>

use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32, le_u8},
    IResult,
};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// LZFSE stream magic values (4-byte block signatures).
/// "bvx-" = LZFSE compressed stream (LZVN + FSE).
pub const LZFSE_V1_MAGIC: u32 = 0x2D787662;

/// "bvx1" = LZFSE end-of-stream marker.
pub const LZFSE_V1_END_MAGIC: u32 = 0x31787662;

/// "bvxn" = LZFSE v2 compressed stream (new format).
pub const LZFSE_V2_MAGIC: u32 = 0x6E787662;

/// "bvxi" = uncompressed stream.
pub const LZFSE_UNCOMPRESSED_MAGIC: u32 = 0x69787662;

/// "bvxl" = LZVN compressed stream.
pub const LZFSE_LZVN_MAGIC: u32 = 0x6C787662;

// ═══════════════════════════════════════════════════════════════════════════════════
// LZFSE Block Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// The block type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzfseBlockType {
    /// End of stream.
    End,
    /// LZFSE compressed (v1).
    LzfseV1,
    /// LZFSE compressed (v2).
    LzfseV2,
    /// Uncompressed.
    Uncompressed,
    /// LZVN compressed.
    Lzvn,
    Unknown(u32),
}

impl LzfseBlockType {
    pub fn from_magic(magic: u32) -> Self {
        match magic {
            LZFSE_V1_END_MAGIC => LzfseBlockType::End,
            LZFSE_V1_MAGIC => LzfseBlockType::LzfseV1,
            LZFSE_V2_MAGIC => LzfseBlockType::LzfseV2,
            LZFSE_UNCOMPRESSED_MAGIC => LzfseBlockType::Uncompressed,
            LZFSE_LZVN_MAGIC => LzfseBlockType::Lzvn,
            other => LzfseBlockType::Unknown(other),
        }
    }
}

/// LZFSE compressed block header (v1 and v2).
#[derive(Debug, Clone, Copy)]
pub struct LzfseBlockHeader {
    /// Block magic/signature.
    pub magic: u32,
    /// Block type.
    pub block_type: LzfseBlockType,
    /// Number of packed bytes in the block.
    pub packed_size: u32,
    /// Number of uncompressed bytes.
    pub unpacked_size: u32,
    /// Number of raw (uncompressed) literal symbols in the block.
    pub n_raw_symbols: u32,
    /// Number of literal states.
    pub n_encoded_symbols: u32,
    /// Base for literal value encoding.
    pub literal_bits: u32,
}

impl LzfseBlockHeader {
    /// Parse a 4-byte block signature and determine the block type.
    pub fn peek_block_type(data: &[u8]) -> Option<LzfseBlockType> {
        if data.len() < 4 {
            return None;
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        Some(LzfseBlockType::from_magic(magic))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// LZFSE Stream
// ═══════════════════════════════════════════════════════════════════════════════════

/// Information about an LZFSE-compressed stream.
#[derive(Debug, Clone)]
pub struct LzfseStreamInfo {
    /// The magic of the first block.
    pub magic: u32,
    /// Total compressed data size (all blocks combined).
    pub compressed_size: usize,
    /// Number of blocks found.
    pub block_count: usize,
}

/// Check if data starts with a valid LZFSE magic.
pub fn is_lzfse(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    matches!(
        magic,
        LZFSE_V1_MAGIC | LZFSE_V2_MAGIC | LZFSE_UNCOMPRESSED_MAGIC | LZFSE_LZVN_MAGIC
    )
}

/// Scan an LZFSE stream and return basic info.
pub fn scan_stream(data: &[u8]) -> Result<LzfseStreamInfo, String> {
    if data.len() < 4 {
        return Err("Data too short for LZFSE".to_string());
    }

    let first_magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let mut offset = 0usize;
    let mut block_count = 0usize;

    while offset + 4 <= data.len() {
        let magic = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        let block_type = LzfseBlockType::from_magic(magic);

        match block_type {
            LzfseBlockType::End => {
                block_count += 1;
                offset += 4;
                break;
            }
            LzfseBlockType::LzfseV1 | LzfseBlockType::LzfseV2 => {
                if offset + 20 > data.len() {
                    break;
                }
                let packed_size = u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]) as usize;
                // Skip this block: magic (4) + packed_size field (4) + packed_size bytes
                // Total block overhead varies, use 20-byte header minimum
                offset += 20 + packed_size;
                block_count += 1;
            }
            LzfseBlockType::Uncompressed => {
                if offset + 12 > data.len() {
                    break;
                }
                let unpacked_size = u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]) as usize;
                offset += 12 + unpacked_size;
                block_count += 1;
            }
            LzfseBlockType::Lzvn => {
                if offset + 8 > data.len() {
                    break;
                }
                let packed_size = u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]) as usize;
                offset += 8 + packed_size;
                block_count += 1;
            }
            LzfseBlockType::Unknown(_) => {
                return Err(format!("Unknown LZFSE block magic: 0x{:08X}", magic));
            }
        }
    }

    Ok(LzfseStreamInfo {
        magic: first_magic,
        compressed_size: offset,
        block_count,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_values() {
        assert_eq!(LZFSE_V1_MAGIC, 0x2D787662); // "bvx-"
        assert_eq!(LZFSE_V1_END_MAGIC, 0x31787662); // "bvx1"
        assert_eq!(LZFSE_V2_MAGIC, 0x6E787662); // "bvxn"
        assert_eq!(LZFSE_UNCOMPRESSED_MAGIC, 0x69787662); // "bvxi"
        assert_eq!(LZFSE_LZVN_MAGIC, 0x6C787662); // "bvxl"
    }

    #[test]
    fn test_is_lzfse() {
        assert!(is_lzfse(&LZFSE_V1_MAGIC.to_le_bytes()));
        assert!(is_lzfse(&LZFSE_V2_MAGIC.to_le_bytes()));
        assert!(is_lzfse(&LZFSE_UNCOMPRESSED_MAGIC.to_le_bytes()));
        assert!(is_lzfse(&LZFSE_LZVN_MAGIC.to_le_bytes()));
        assert!(!is_lzfse(&[0x00, 0x00, 0x00, 0x00]));
        assert!(!is_lzfse(&[0x01, 0x02]));
    }

    #[test]
    fn test_block_type_from_magic() {
        assert_eq!(
            LzfseBlockType::from_magic(LZFSE_V1_END_MAGIC),
            LzfseBlockType::End
        );
        assert_eq!(
            LzfseBlockType::from_magic(LZFSE_V1_MAGIC),
            LzfseBlockType::LzfseV1
        );
        assert_eq!(
            LzfseBlockType::from_magic(LZFSE_V2_MAGIC),
            LzfseBlockType::LzfseV2
        );
        assert_eq!(
            LzfseBlockType::from_magic(0xDEADBEEF),
            LzfseBlockType::Unknown(0xDEADBEEF)
        );
    }

    #[test]
    fn test_peek_block_type() {
        let data = LZFSE_V1_MAGIC.to_le_bytes();
        assert_eq!(
            LzfseBlockHeader::peek_block_type(&data),
            Some(LzfseBlockType::LzfseV1)
        );
        assert_eq!(LzfseBlockHeader::peek_block_type(&[0x01, 0x02]), None);
    }

    #[test]
    fn test_scan_end_only() {
        let data = LZFSE_V1_END_MAGIC.to_le_bytes();
        let info = scan_stream(&data).unwrap();
        assert_eq!(info.block_count, 1);
        assert_eq!(info.compressed_size, 4);
    }
}
