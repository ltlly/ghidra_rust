//! Android Sparse Image format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.sparseimage` package.
//!
//! References:
//! - Android sparse image format: <https://android.googlesource.com/platform/system/core/+/refs/heads/main/libsparse/>

use nom::{bytes::complete::take, number::complete::{le_u16, le_u32}, IResult};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Sparse image magic: `\x3A\xFF\x26\xED`.
pub const SPARSE_HEADER_MAGIC: u32 = 0xED26FF3A;

/// Sparse header version.
pub const SPARSE_HEADER_MAJOR_VER: u16 = 1;
pub const SPARSE_HEADER_MINOR_VER: u16 = 0;

/// Chunk types.
pub const CHUNK_TYPE_RAW: u16 = 0xCAC1;
pub const CHUNK_TYPE_FILL: u16 = 0xCAC2;
pub const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;
pub const CHUNK_TYPE_CRC32: u16 = 0xCAC4;

/// Header size.
pub const SPARSE_HEADER_SIZE: usize = 28;

/// Chunk header size.
pub const CHUNK_HEADER_SIZE: usize = 12;

// ═══════════════════════════════════════════════════════════════════════════════════
// Sparse Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android sparse image file header.
#[derive(Debug, Clone, Copy)]
pub struct SparseHeader {
    /// Magic: `0xED26FF3A`.
    pub magic: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// File header size (28 bytes).
    pub file_hdr_size: u16,
    /// Chunk header size (12 bytes).
    pub chunk_hdr_size: u16,
    /// Block size (must be multiple of 4).
    pub block_size: u32,
    /// Total number of blocks.
    pub total_blocks: u32,
    /// Total number of chunks.
    pub total_chunks: u32,
    /// CRC32 checksum of the original data.
    pub image_checksum: u32,
}

impl SparseHeader {
    /// Parse a sparse header from little-endian bytes.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, magic) = le_u32(data)?;
        let (i, major_version) = le_u16(i)?;
        let (i, minor_version) = le_u16(i)?;
        let (i, file_hdr_size) = le_u16(i)?;
        let (i, chunk_hdr_size) = le_u16(i)?;
        let (i, block_size) = le_u32(i)?;
        let (i, total_blocks) = le_u32(i)?;
        let (i, total_chunks) = le_u32(i)?;
        let (i, image_checksum) = le_u32(i)?;

        Ok((
            i,
            SparseHeader {
                magic,
                major_version,
                minor_version,
                file_hdr_size,
                chunk_hdr_size,
                block_size,
                total_blocks,
                total_chunks,
                image_checksum,
            },
        ))
    }

    /// Whether the magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == SPARSE_HEADER_MAGIC
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Chunk Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Chunk type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    /// Raw data follows.
    Raw,
    /// Fill data (4 bytes).
    Fill,
    /// Don't care (skip).
    DontCare,
    /// CRC32 checksum.
    Crc32,
    Unknown(u16),
}

impl ChunkType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            CHUNK_TYPE_RAW => ChunkType::Raw,
            CHUNK_TYPE_FILL => ChunkType::Fill,
            CHUNK_TYPE_DONT_CARE => ChunkType::DontCare,
            CHUNK_TYPE_CRC32 => ChunkType::Crc32,
            other => ChunkType::Unknown(other),
        }
    }
}

/// A chunk header in a sparse image.
#[derive(Debug, Clone, Copy)]
pub struct ChunkHeader {
    /// Chunk type.
    pub chunk_type: ChunkType,
    /// Reserved.
    pub reserved: u16,
    /// Number of blocks in this chunk.
    pub chunk_blocks: u32,
    /// Total size of the chunk data in bytes (excluding header).
    pub total_size: u32,
}

impl ChunkHeader {
    /// Parse a chunk header.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, chunk_type_raw) = le_u16(data)?;
        let (i, reserved) = le_u16(i)?;
        let (i, chunk_blocks) = le_u32(i)?;
        let (i, total_size) = le_u32(i)?;

        Ok((
            i,
            ChunkHeader {
                chunk_type: ChunkType::from_u16(chunk_type_raw),
                reserved,
                chunk_blocks,
                total_size,
            },
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; SPARSE_HEADER_SIZE];
        data[0..4].copy_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        data[4..6].copy_from_slice(&1u16.to_le_bytes()); // major
        data[6..8].copy_from_slice(&0u16.to_le_bytes()); // minor
        data[8..10].copy_from_slice(&(SPARSE_HEADER_SIZE as u16).to_le_bytes());
        data[10..12].copy_from_slice(&(CHUNK_HEADER_SIZE as u16).to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes()); // block_size
        data[16..20].copy_from_slice(&100u32.to_le_bytes()); // total_blocks
        data[20..24].copy_from_slice(&3u32.to_le_bytes()); // total_chunks
        data[24..28].copy_from_slice(&0u32.to_le_bytes()); // checksum

        let (_, hdr) = SparseHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.block_size, 4096);
        assert_eq!(hdr.total_blocks, 100);
        assert_eq!(hdr.total_chunks, 3);
    }

    #[test]
    fn test_chunk_header_parse() {
        let mut data = vec![0u8; CHUNK_HEADER_SIZE];
        data[0..2].copy_from_slice(&CHUNK_TYPE_RAW.to_le_bytes());
        data[2..4].copy_from_slice(&0u16.to_le_bytes()); // reserved
        data[4..8].copy_from_slice(&10u32.to_le_bytes()); // chunk_blocks
        data[8..12].copy_from_slice(&40960u32.to_le_bytes()); // total_size

        let (_, chunk) = ChunkHeader::parse(&data).unwrap();
        assert_eq!(chunk.chunk_type, ChunkType::Raw);
        assert_eq!(chunk.chunk_blocks, 10);
        assert_eq!(chunk.total_size, 40960);
    }

    #[test]
    fn test_chunk_types() {
        assert_eq!(ChunkType::from_u16(CHUNK_TYPE_RAW), ChunkType::Raw);
        assert_eq!(ChunkType::from_u16(CHUNK_TYPE_FILL), ChunkType::Fill);
        assert_eq!(ChunkType::from_u16(CHUNK_TYPE_DONT_CARE), ChunkType::DontCare);
        assert_eq!(ChunkType::from_u16(CHUNK_TYPE_CRC32), ChunkType::Crc32);
        assert_eq!(ChunkType::from_u16(0xFFFF), ChunkType::Unknown(0xFFFF));
    }

    #[test]
    fn test_constants() {
        assert_eq!(SPARSE_HEADER_MAGIC, 0xED26FF3A);
        assert_eq!(SPARSE_HEADER_SIZE, 28);
        assert_eq!(CHUNK_HEADER_SIZE, 12);
    }
}
