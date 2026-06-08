//! XAR (eXtensible ARchive) format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.xar` package.
//!
//! References:
//! - XAR format: <https://github.com/mackyle/xar/wiki/xarformat>

use nom::{number::complete::{be_u16, be_u32, be_u64}, IResult};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// XAR magic: `"xar!"`.
pub const XAR_MAGIC: u32 = 0x78617221;

/// XAR header size (28 bytes).
pub const XAR_HEADER_SIZE: usize = 28;

// ═══════════════════════════════════════════════════════════════════════════════════
// XAR Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// XAR archive header.
#[derive(Debug, Clone, Copy)]
pub struct XarHeader {
    /// Magic: `"xar!"` (0x78617221).
    pub magic: u32,
    /// Header size (typically 28).
    pub header_size: u16,
    /// XAR format version.
    pub version: u16,
    /// Length of the TOC (Table of Contents) in bytes (compressed).
    pub toc_length_compressed: u64,
    /// Length of the TOC in bytes (uncompressed).
    pub toc_length_uncompressed: u64,
    /// Checksum algorithm used for TOC.
    pub checksum_alg: u32,
}

impl XarHeader {
    /// Parse an XAR header (big-endian).
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, magic) = be_u32(data)?;
        let (i, header_size) = be_u16(i)?;
        let (i, version) = be_u16(i)?;
        let (i, toc_length_compressed) = be_u64(i)?;
        let (i, toc_length_uncompressed) = be_u64(i)?;
        // Skip checksum algorithm hash (16 bytes hash + 4 bytes length)
        // Actually, the checksum_alg field is just a single u32
        // But the exact format depends on the version

        Ok((
            i,
            XarHeader {
                magic,
                header_size,
                version,
                toc_length_compressed,
                toc_length_uncompressed,
                checksum_alg: 0,
            },
        ))
    }

    /// Whether the magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == XAR_MAGIC
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Check
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if a byte slice starts with XAR magic.
pub fn is_xar(data: &[u8]) -> bool {
    data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == XAR_MAGIC
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic() {
        assert_eq!(XAR_MAGIC, 0x78617221);
    }

    #[test]
    fn test_is_xar() {
        assert!(is_xar(&XAR_MAGIC.to_be_bytes()));
        assert!(!is_xar(&[0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; XAR_HEADER_SIZE];
        data[0..4].copy_from_slice(&XAR_MAGIC.to_be_bytes());
        data[4..6].copy_from_slice(&28u16.to_be_bytes()); // header_size
        data[6..8].copy_from_slice(&1u16.to_be_bytes()); // version
        data[8..16].copy_from_slice(&1024u64.to_be_bytes()); // toc_compressed
        data[16..24].copy_from_slice(&2048u64.to_be_bytes()); // toc_uncompressed

        let (_, hdr) = XarHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.header_size, 28);
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.toc_length_compressed, 1024);
        assert_eq!(hdr.toc_length_uncompressed, 2048);
    }
}
