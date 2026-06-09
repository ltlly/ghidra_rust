//! ART image block descriptor.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.art.ArtBlock`.
//!
//! An `ArtBlock` describes a contiguous region within an ART image file.
//! Each block records the storage mode (uncompressed, LZ4, LZ4HC),
//! the compressed data offset/size, and the decompressed image offset/size.
//! Blocks are used for decompressing ART images that use LZ4 compression.
//!
//! On-disk size: 20 bytes (5 x u32).

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtStorageMode
// ═══════════════════════════════════════════════════════════════════════════════════

/// ART image storage/compression mode.
///
/// Ported from Ghidra's `ghidra.file.formats.android.art.ArtStorageMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ArtStorageMode {
    /// No compression.
    Uncompressed = 0,
    /// LZ4 compression.
    Lz4 = 1,
    /// LZ4HC compression.
    Lz4hc = 2,
}

impl ArtStorageMode {
    /// On-disk size (32 bits / 4 bytes).
    pub const SIZE: usize = 4;

    /// Convert a raw u32 value to an `ArtStorageMode`.
    ///
    /// Returns an error for unknown values.
    pub fn from_u32(value: u32) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Uncompressed),
            1 => Ok(Self::Lz4),
            2 => Ok(Self::Lz4hc),
            _ => Err(format!("Unknown ART storage mode: {}", value)),
        }
    }

    /// Returns the default storage mode (Uncompressed).
    pub fn default_mode() -> Self {
        Self::Uncompressed
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtBlock
// ═══════════════════════════════════════════════════════════════════════════════════

/// An ART image block descriptor (20 bytes on disk).
///
/// Fields (all little-endian u32):
/// - `storage_mode`: compression mode (0 = uncompressed, 1 = LZ4, 2 = LZ4HC)
/// - `data_offset`: offset to the compressed bytes in the file
/// - `data_size`: size of the compressed data
/// - `image_offset`: offset where decompressed bytes should be placed
/// - `image_size`: expected size after decompression
#[derive(Debug, Clone)]
pub struct ArtBlock {
    /// Compression/storage mode.
    pub storage_mode: ArtStorageMode,
    /// Offset to the compressed data in the file.
    pub data_offset: u32,
    /// Size of the compressed data.
    pub data_size: u32,
    /// Offset where the decompressed data should be placed.
    pub image_offset: u32,
    /// Expected decompressed size.
    pub image_size: u32,
}

impl ArtBlock {
    /// On-disk size of an ArtBlock (20 bytes).
    pub const SIZE: usize = 20;

    /// Parse an ArtBlock from a byte slice at the given offset.
    pub fn parse_at(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + Self::SIZE > data.len() {
            return Err(format!(
                "ArtBlock: need {} bytes at offset {}, only {} available",
                Self::SIZE,
                offset,
                data.len()
            ));
        }

        let storage_mode_val = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let storage_mode = ArtStorageMode::from_u32(storage_mode_val)?;

        Ok(ArtBlock {
            storage_mode,
            data_offset: u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()),
            data_size: u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()),
            image_offset: u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap()),
            image_size: u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap()),
        })
    }

    /// Parse an ArtBlock from the start of a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Returns the compressed data offset as u64 (unsigned).
    pub fn compressed_offset(&self) -> u64 {
        self.data_offset as u64
    }

    /// Returns the compressed data size.
    pub fn compressed_size(&self) -> u32 {
        self.data_size
    }

    /// Returns the decompressed image offset as u64 (unsigned).
    pub fn decompressed_offset(&self) -> u64 {
        self.image_offset as u64
    }

    /// Returns the expected decompressed size.
    pub fn decompressed_size(&self) -> u32 {
        self.image_size
    }

    /// Returns true if this block is uncompressed.
    pub fn is_uncompressed(&self) -> bool {
        self.storage_mode == ArtStorageMode::Uncompressed
    }

    /// Returns true if this block uses LZ4 compression.
    pub fn is_lz4(&self) -> bool {
        self.storage_mode == ArtStorageMode::Lz4
    }

    /// Returns true if this block uses LZ4HC compression.
    pub fn is_lz4hc(&self) -> bool {
        self.storage_mode == ArtStorageMode::Lz4hc
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uncompressed_block() {
        let mut data = vec![0u8; ArtBlock::SIZE];
        // storage_mode = 0 (Uncompressed)
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x100u32.to_le_bytes()); // data_offset
        data[8..12].copy_from_slice(&0x200u32.to_le_bytes()); // data_size
        data[12..16].copy_from_slice(&0x300u32.to_le_bytes()); // image_offset
        data[16..20].copy_from_slice(&0x400u32.to_le_bytes()); // image_size

        let block = ArtBlock::parse(&data).unwrap();
        assert!(block.is_uncompressed());
        assert!(!block.is_lz4());
        assert_eq!(block.data_offset, 0x100);
        assert_eq!(block.data_size, 0x200);
        assert_eq!(block.image_offset, 0x300);
        assert_eq!(block.image_size, 0x400);
        assert_eq!(block.compressed_offset(), 0x100);
        assert_eq!(block.decompressed_size(), 0x400);
    }

    #[test]
    fn test_parse_lz4_block() {
        let mut data = vec![0u8; ArtBlock::SIZE];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // LZ4

        let block = ArtBlock::parse(&data).unwrap();
        assert!(block.is_lz4());
        assert!(!block.is_lz4hc());
    }

    #[test]
    fn test_parse_lz4hc_block() {
        let mut data = vec![0u8; ArtBlock::SIZE];
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // LZ4HC

        let block = ArtBlock::parse(&data).unwrap();
        assert!(block.is_lz4hc());
    }

    #[test]
    fn test_parse_at_offset() {
        let mut data = vec![0u8; ArtBlock::SIZE + 32];
        let offset = 32;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        data[offset + 4..offset + 8].copy_from_slice(&0xABCDu32.to_le_bytes());
        data[offset + 8..offset + 12].copy_from_slice(&0x1234u32.to_le_bytes());

        let block = ArtBlock::parse_at(&data, offset).unwrap();
        assert_eq!(block.data_offset, 0xABCD);
        assert_eq!(block.data_size, 0x1234);
    }

    #[test]
    fn test_parse_truncated() {
        assert!(ArtBlock::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_parse_invalid_storage_mode() {
        let mut data = vec![0u8; ArtBlock::SIZE];
        data[0..4].copy_from_slice(&99u32.to_le_bytes()); // invalid
        assert!(ArtBlock::parse(&data).is_err());
    }
}
