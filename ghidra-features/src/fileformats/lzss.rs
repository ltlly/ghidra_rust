//! LZSS compression format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.lzss` package.
//! Implements the Apple variant of LZSS used in iOS/macOS kernels.
//!
//! References:
//! - Okazaki, "An Introduction to Data Compression"
//! - Apple's LZSS implementation used in XNU kernel

use nom::{
    bytes::complete::take,
    number::complete::{le_u32, le_u8},
    IResult,
};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// LZSS magic: `"complzss"` (for Apple kernel compression).
pub const LZSS_MAGIC: [u8; 8] = *b"complzss";

/// Default N for LZSS (ring buffer size = 2^N).
pub const LZSS_N: usize = 4096;

/// Default F for LZSS (maximum match length).
pub const LZSS_F: usize = 18;

/// Default threshold.
pub const LZSS_THRESHOLD: usize = 2;

/// N - 1 mask.
pub const LZSS_N_MASK: usize = LZSS_N - 1;

// ═══════════════════════════════════════════════════════════════════════════════════
// LZSS Compression Header (Apple variant)
// ═══════════════════════════════════════════════════════════════════════════════════

/// The LZSS compression header used by Apple's kernel compression.
#[derive(Debug, Clone, Copy)]
pub struct LzssHeader {
    /// Magic: `"complzss"`.
    pub magic: [u8; 8],
    /// Uncompressed size.
    pub uncompressed_size: u32,
    /// Compressed size.
    pub compressed_size: u32,
    /// Unknown/version field.
    pub unknown: u32,
}

impl LzssHeader {
    /// Total header size (20 bytes).
    pub const SIZE: usize = 20;

    /// Parse an LZSS header from a byte slice.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, magic_bytes) = take(8usize)(data)?;
        let mut magic = [0u8; 8];
        magic.copy_from_slice(magic_bytes);

        let (i, uncompressed_size) = le_u32(i)?;
        let (i, compressed_size) = le_u32(i)?;
        let (i, unknown) = le_u32(i)?;

        Ok((
            i,
            LzssHeader {
                magic,
                uncompressed_size,
                compressed_size,
                unknown,
            },
        ))
    }

    /// Whether the magic bytes match the LZSS magic.
    pub fn is_valid(&self) -> bool {
        self.magic == LZSS_MAGIC
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// LZSS Decompressor
// ═══════════════════════════════════════════════════════════════════════════════════

/// Decompress an LZSS-compressed data stream (Apple variant).
///
/// Returns the decompressed bytes, or an error string.
pub fn lzss_decompress(input: &[u8], uncompressed_size: usize) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(uncompressed_size);
    let mut ring_buffer = vec![0u8; LZSS_N];
    let mut r = LZSS_N - LZSS_F;
    let mut ip: usize = 0;

    while ip < input.len() && output.len() < uncompressed_size {
        let flags = input[ip];
        ip += 1;

        for bit in 0..8 {
            if ip >= input.len() || output.len() >= uncompressed_size {
                break;
            }

            if flags & (1 << bit) != 0 {
                // Literal byte
                let c = input[ip];
                ip += 1;
                output.push(c);
                ring_buffer[r] = c;
                r = (r + 1) & LZSS_N_MASK;
            } else {
                if ip + 1 >= input.len() {
                    break;
                }
                let b1 = input[ip] as usize;
                let b2 = input[ip + 1] as usize;
                ip += 2;

                let position = b1 | ((b2 & 0xF0) << 4);
                let length = (b2 & 0x0F) + LZSS_THRESHOLD + 1;

                for _ in 0..length {
                    if output.len() >= uncompressed_size {
                        break;
                    }
                    let c = ring_buffer[position & LZSS_N_MASK];
                    output.push(c);
                    ring_buffer[r] = c;
                    r = (r + 1) & LZSS_N_MASK;
                    // Advance position in the reference
                    // (this mimics the C implementation)
                }
            }
        }
    }

    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&LZSS_MAGIC);
        data.extend_from_slice(&1000u32.to_le_bytes()); // uncompressed
        data.extend_from_slice(&500u32.to_le_bytes());  // compressed
        data.extend_from_slice(&0u32.to_le_bytes());    // unknown

        let (_, header) = LzssHeader::parse(&data).unwrap();
        assert!(header.is_valid());
        assert_eq!(header.uncompressed_size, 1000);
        assert_eq!(header.compressed_size, 500);
        assert_eq!(header.unknown, 0);
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut data = vec![0u8; 20];
        data[..8].copy_from_slice(b"badmagic");
        let (_, header) = LzssHeader::parse(&data).unwrap();
        assert!(!header.is_valid());
    }

    #[test]
    fn test_decompress_literals_only() {
        // Create a stream that has all-literal bytes
        // flags = 0xFF means all 8 bits set => 8 literal bytes
        let mut input = vec![0xFFu8]; // all literals
        input.extend_from_slice(b"ABCDEFGH");

        let result = lzss_decompress(&input, 8).unwrap();
        assert_eq!(result, b"ABCDEFGH");
    }

    #[test]
    fn test_decompress_empty() {
        let result = lzss_decompress(&[], 0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_header_size() {
        assert_eq!(LzssHeader::SIZE, 20);
    }

    #[test]
    fn test_constants() {
        assert_eq!(LZSS_N, 4096);
        assert_eq!(LZSS_F, 18);
        assert_eq!(LZSS_THRESHOLD, 2);
        assert_eq!(LZSS_N_MASK, 0xFFF);
    }
}
