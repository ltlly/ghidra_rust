//! ZLIB/DEFLATE format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.zlib` package.
//!
//! References:
//! - RFC 1950 (ZLIB Compressed Data Format)
//! - RFC 1951 (DEFLATE Compressed Data Format)

use nom::number::complete::{le_u8, be_u16};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// DEFLATE stored block type.
pub const DEFLATE_STORED: u8 = 0;
/// DEFLATE fixed Huffman codes block type.
pub const DEFLATE_FIXED: u8 = 1;
/// DEFLATE dynamic Huffman codes block type.
pub const DEFLATE_DYNAMIC: u8 = 2;
/// DEFLATE reserved block type.
pub const DEFLATE_RESERVED: u8 = 3;

/// ZLIB compression method (CM): deflate.
pub const ZLIB_CM_DEFLATE: u8 = 8;

/// ZLIB compression info (CINFO): window size = 2^(CINFO+8).
pub const ZLIB_CINFO_MAX: u8 = 7;

// ZLIB FLEVEL (compression level) values.
pub const ZLIB_FLEVEL_FASTEST: u8 = 0;
pub const ZLIB_FLEVEL_FAST: u8 = 1;
pub const ZLIB_FLEVEL_DEFAULT: u8 = 2;
pub const ZLIB_FLEVEL_SLOWEST: u8 = 3;

// ═══════════════════════════════════════════════════════════════════════════════════
// ZLIB Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// A ZLIB header (RFC 1950).
#[derive(Debug, Clone, Copy)]
pub struct ZlibHeader {
    /// Compression method (CMF & 0x0F).
    pub cm: u8,
    /// Compression info (CMF >> 4).
    pub cinfo: u8,
    /// FDICT flag (FLG & 0x20).
    pub fdict: bool,
    /// Compression level (FLG >> 6).
    pub flevel: u8,
    /// Window size = 2^(cinfo + 8).
    pub window_size: u32,
}

impl ZlibHeader {
    /// Parse a 2-byte ZLIB header.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 2 {
            return Err("Need at least 2 bytes for ZLIB header".to_string());
        }

        let cmf = data[0];
        let flg = data[1];

        // Check CMF*256 + FLG must be a multiple of 31
        if ((cmf as u16) * 256 + flg as u16) % 31 != 0 {
            return Err("ZLIB header check failed (not multiple of 31)".to_string());
        }

        let cm = cmf & 0x0F;
        let cinfo = cmf >> 4;
        let fdict = (flg & 0x20) != 0;
        let flevel = flg >> 6;
        let window_size = if cm == ZLIB_CM_DEFLATE {
            1u32 << (cinfo as u32 + 8)
        } else {
            0
        };

        Ok(ZlibHeader {
            cm,
            cinfo,
            fdict,
            flevel,
            window_size,
        })
    }

    /// Whether the compression method is deflate.
    pub fn is_deflate(&self) -> bool {
        self.cm == ZLIB_CM_DEFLATE
    }
}

/// Check if a byte slice starts with a valid ZLIB stream.
pub fn is_zlib(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let cmf = data[0];
    let flg = data[1];
    let cm = cmf & 0x0F;
    cm == ZLIB_CM_DEFLATE && ((cmf as u16) * 256 + flg as u16) % 31 == 0
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zlib_header_parse() {
        // CMF=0x78 (CM=8 deflate, CINFO=7 => window=32768)
        // FLG=0x01 => FCHECK such that (0x78*256+1) % 31 == 0
        // 0x7801 = 30721, 30721 % 31 = 0
        let data = [0x78u8, 0x01];
        let hdr = ZlibHeader::parse(&data).unwrap();
        assert!(hdr.is_deflate());
        assert_eq!(hdr.window_size, 32768);
        assert!(!hdr.fdict);
        assert_eq!(hdr.flevel, 0);
    }

    #[test]
    fn test_zlib_header_default_compression() {
        // 0x78 0x9C => standard deflate, default compression
        // 0x789C = 30876, 30876 % 31 = 0
        let data = [0x78u8, 0x9C];
        let hdr = ZlibHeader::parse(&data).unwrap();
        assert!(hdr.is_deflate());
        assert_eq!(hdr.flevel, ZLIB_FLEVEL_DEFAULT);
    }

    #[test]
    fn test_zlib_header_no_compression() {
        // 0x78 0x01 => deflate, no compression
        let data = [0x78u8, 0x01];
        let hdr = ZlibHeader::parse(&data).unwrap();
        assert!(hdr.is_deflate());
        assert_eq!(hdr.flevel, ZLIB_FLEVEL_FASTEST);
    }

    #[test]
    fn test_is_zlib() {
        assert!(is_zlib(&[0x78, 0x01]));
        assert!(is_zlib(&[0x78, 0x9C]));
        assert!(!is_zlib(&[0x78, 0x00])); // invalid checksum
        assert!(!is_zlib(&[0x00, 0x00]));
    }

    #[test]
    fn test_zlib_header_too_short() {
        assert!(ZlibHeader::parse(&[0x78]).is_err());
    }

    #[test]
    fn test_zlib_header_bad_checksum() {
        // 0x78 0x00 => not multiple of 31
        assert!(ZlibHeader::parse(&[0x78, 0x00]).is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFLATE_STORED, 0);
        assert_eq!(DEFLATE_FIXED, 1);
        assert_eq!(DEFLATE_DYNAMIC, 2);
        assert_eq!(ZLIB_CM_DEFLATE, 8);
    }
}
