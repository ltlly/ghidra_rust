//! Memory block entry for the trace database.
//!
//! Ported from Ghidra's `DBTraceMemoryBlockEntry` in
//! `ghidra.trace.database.memory`. Represents a single memory block
//! with copy-on-write semantics.

use serde::{Deserialize, Serialize};

/// A compressed memory block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedMemoryBlock {
    /// The block base offset.
    pub base_offset: u64,
    /// The snap at which this block was written.
    pub snap: i64,
    /// Compressed byte data (RLE or similar).
    pub data: Vec<u8>,
    /// Whether all bytes in this block are the same (uniform fill).
    pub is_uniform: bool,
    /// The fill byte if uniform.
    pub fill_byte: u8,
    /// The actual decompressed size.
    pub decompressed_size: u32,
}

impl CompressedMemoryBlock {
    /// Create a uniform fill block.
    pub fn uniform(base_offset: u64, snap: i64, fill: u8, size: u32) -> Self {
        Self {
            base_offset,
            snap,
            data: vec![fill],
            is_uniform: true,
            fill_byte: fill,
            decompressed_size: size,
        }
    }

    /// Create a compressed block from raw data.
    pub fn compressed(base_offset: u64, snap: i64, data: Vec<u8>, decompressed_size: u32) -> Self {
        Self {
            base_offset,
            snap,
            data,
            is_uniform: false,
            fill_byte: 0,
            decompressed_size,
        }
    }

    /// Decompress the block data.
    pub fn decompress(&self) -> Vec<u8> {
        if self.is_uniform {
            vec![self.fill_byte; self.decompressed_size as usize]
        } else {
            self.data.clone()
        }
    }

    /// Whether this block covers the given offset.
    pub fn covers_offset(&self, offset: u64, block_size: u64) -> bool {
        offset >= self.base_offset && offset < self.base_offset + block_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compressed_uniform() {
        let block = CompressedMemoryBlock::uniform(0x1000, 0, 0xFF, 4096);
        assert!(block.is_uniform);
        assert_eq!(block.fill_byte, 0xFF);
        let decompressed = block.decompress();
        assert_eq!(decompressed.len(), 4096);
        assert!(decompressed.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_compressed_raw() {
        let block = CompressedMemoryBlock::compressed(
            0x1000, 0, vec![1, 2, 3], 3,
        );
        assert!(!block.is_uniform);
        assert_eq!(block.decompress(), vec![1, 2, 3]);
    }

    #[test]
    fn test_compressed_covers_offset() {
        let block = CompressedMemoryBlock::uniform(0x1000, 0, 0, 4096);
        assert!(block.covers_offset(0x1000, 4096));
        assert!(block.covers_offset(0x1FFF, 4096));
        assert!(!block.covers_offset(0x2000, 4096));
        assert!(!block.covers_offset(0x0FFF, 4096));
    }
}
