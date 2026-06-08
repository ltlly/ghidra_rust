//! 7-Zip archive format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.sevenzip` package.
//!
//! References:
//! - 7z Format specification: <https://www.7-zip.org/7z.html>
//! - LZMA SDK

use nom::{bytes::complete::take, number::complete::{le_u32, le_u64, le_u8}, IResult};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// 7-Zip signature: `"7z\xbc\xaf\x27\x1c"`.
pub const SEVENZIP_SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// 7-Zip signature as a version byte (for validation).
pub const SEVENZIP_MAJOR_VERSION: u8 = 0;

// 7-Zip header IDs.
pub const SZ_HEADER_END: u8 = 0x00;
pub const SZ_HEADER_ARCHIVE_PROPERTIES: u8 = 0x02;
pub const SZ_HEADER_ADDITIONAL_STREAMS_INFO: u8 = 0x03;
pub const SZ_HEADER_MAIN_STREAMS_INFO: u8 = 0x04;
pub const SZ_HEADER_FILES_INFO: u8 = 0x05;
pub const SZ_HEADER_PACK_INFO: u8 = 0x06;
pub const SZ_HEADER_UNPACK_INFO: u8 = 0x07;
pub const SZ_HEADER_SUBSTREAMS_INFO: u8 = 0x08;
pub const SZ_HEADER_SIZE: u8 = 0x09;
pub const SZ_HEADER_CRC: u8 = 0x0A;
pub const SZ_HEADER_FOLDER: u8 = 0x0B;
pub const SZ_HEADER_CODERS_UNPACK_SIZE: u8 = 0x0C;
pub const SZ_HEADER_NUM_UNPACK_STREAM: u8 = 0x0D;
pub const SZ_HEADER_EMPTY_STREAM: u8 = 0x0E;
pub const SZ_HEADER_EMPTY_FILE: u8 = 0x0F;
pub const SZ_HEADER_ANTI: u8 = 0x10;
pub const SZ_HEADER_NAME: u8 = 0x11;
pub const SZ_HEADER_CREATION_TIME: u8 = 0x12;
pub const SZ_HEADER_ACCESS_TIME: u8 = 0x13;
pub const SZ_HEADER_MODIFICATION_TIME: u8 = 0x14;
pub const SZ_HEADER_WIN_ATTRIBUTE: u8 = 0x15;
pub const SZ_HEADER_COMMENT: u8 = 0x16;
pub const SZ_HEADER_ENCODED_HEADER: u8 = 0x17;
pub const SZ_HEADER_START_POS: u8 = 0x18;
pub const SZ_HEADER_DUMMY: u8 = 0x19;

// ═══════════════════════════════════════════════════════════════════════════════════
// 7-Zip Signature Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// 7-Zip archive signature header.
#[derive(Debug, Clone, Copy)]
pub struct SevenZipSignatureHeader {
    /// Signature bytes.
    pub signature: [u8; 6],
    /// Archive format version.
    pub version_major: u8,
    pub version_minor: u8,
    /// Start header (offset/size/CRC of the header stream).
    pub next_header_offset: u64,
    pub next_header_size: u64,
    pub next_header_crc: u32,
}

impl SevenZipSignatureHeader {
    /// Total size of the signature header (32 bytes).
    pub const SIZE: usize = 32;

    /// Parse a 7-Zip signature header.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, sig_bytes) = take(6usize)(data)?;
        let mut signature = [0u8; 6];
        signature.copy_from_slice(sig_bytes);

        let (i, version_major) = le_u8(i)?;
        let (i, version_minor) = le_u8(i)?;
        let (i, next_header_offset) = le_u64(i)?;
        let (i, next_header_size) = le_u64(i)?;
        let (i, next_header_crc) = le_u32(i)?;

        Ok((
            i,
            SevenZipSignatureHeader {
                signature,
                version_major,
                version_minor,
                next_header_offset,
                next_header_size,
                next_header_crc,
            },
        ))
    }

    /// Whether the signature is valid.
    pub fn is_valid(&self) -> bool {
        self.signature == SEVENZIP_SIGNATURE
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Check
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if a byte slice starts with the 7-Zip signature.
pub fn is_7zip(data: &[u8]) -> bool {
    data.len() >= 6 && data[..6] == SEVENZIP_SIGNATURE
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature() {
        assert!(is_7zip(&SEVENZIP_SIGNATURE));
        assert!(!is_7zip(&[0x50, 0x4B, 0x03, 0x04])); // ZIP
    }

    #[test]
    fn test_signature_header_parse() {
        let mut data = vec![0u8; SevenZipSignatureHeader::SIZE];
        data[0..6].copy_from_slice(&SEVENZIP_SIGNATURE);
        data[6] = 0; // major
        data[7] = 4; // minor
        // next_header_offset = 0x100
        data[8..16].copy_from_slice(&0x100u64.to_le_bytes());
        // next_header_size = 0x200
        data[16..24].copy_from_slice(&0x200u64.to_le_bytes());
        // next_header_crc = 0xABCDEF01
        data[24..28].copy_from_slice(&0xABCDEF01u32.to_le_bytes());

        let (_, hdr) = SevenZipSignatureHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.version_major, 0);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.next_header_offset, 0x100);
        assert_eq!(hdr.next_header_size, 0x200);
        assert_eq!(hdr.next_header_crc, 0xABCDEF01);
    }

    #[test]
    fn test_header_ids() {
        assert_eq!(SZ_HEADER_END, 0x00);
        assert_eq!(SZ_HEADER_ENCODED_HEADER, 0x17);
        assert_eq!(SZ_HEADER_FILES_INFO, 0x05);
    }
}
