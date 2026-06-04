//! CaRT (Cryptographic Artifact) format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.cart` package.
//! CaRT files contain encrypted/signed content with an ARc4 key.
//!
//! References:
//! - Apple's CaRT format used for provisioning profiles

use nom::{bytes::complete::take, number::complete::{le_u16, le_u32, le_u64}, IResult};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// CaRT magic: `"CaRT"`.
pub const CART_MAGIC: &[u8; 4] = b"CaRT";

/// CaRT version 1.
pub const CART_VERSION_1: u16 = 1;

// ═══════════════════════════════════════════════════════════════════════════════════
// CaRT Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// CaRT v1 header.
#[derive(Debug, Clone)]
pub struct CartV1Header {
    /// Magic: `"CaRT"`.
    pub magic: [u8; 4],
    /// Version (should be 1).
    pub version: u16,
    /// Reserved.
    pub reserved: u16,
    /// ARC4 encryption key (16 bytes).
    pub arc4_key: Vec<u8>,
    /// Optional header length.
    pub optional_header_length: u64,
}

impl CartV1Header {
    /// Minimum header size (magic + version + reserved + key + opt_hdr_len).
    pub const MIN_SIZE: usize = 32;

    /// Parse a CaRT v1 header.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::MIN_SIZE {
            return Err("Data too short for CaRT header".to_string());
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        if magic != *CART_MAGIC {
            return Err(format!(
                "Invalid CaRT magic: expected {:?}, got {:?}",
                CART_MAGIC, magic
            ));
        }

        let version = u16::from_le_bytes([data[4], data[5]]);
        if version != CART_VERSION_1 {
            return Err(format!("Unsupported CaRT version: {}", version));
        }

        let reserved = u16::from_le_bytes([data[6], data[7]]);
        let arc4_key = data[8..24].to_vec();
        let optional_header_length = u64::from_le_bytes([
            data[24], data[25], data[26], data[27],
            data[28], data[29], data[30], data[31],
        ]);

        Ok(CartV1Header {
            magic,
            version,
            reserved,
            arc4_key,
            optional_header_length,
        })
    }

    /// Whether the magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == *CART_MAGIC
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// CaRT Footer
// ═══════════════════════════════════════════════════════════════════════════════════

/// CaRT v1 footer hash entry.
#[derive(Debug, Clone)]
pub struct CartFooterHash {
    /// Hash algorithm name.
    pub algorithm: String,
    /// Hash value.
    pub hash: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Check
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if a byte slice starts with CaRT magic.
pub fn is_cart(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == CART_MAGIC
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_cart() {
        assert!(is_cart(b"CaRT"));
        assert!(!is_cart(b"not!"));
    }

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; CartV1Header::MIN_SIZE];
        data[0..4].copy_from_slice(b"CaRT");
        data[4..6].copy_from_slice(&1u16.to_le_bytes()); // version
        data[6..8].copy_from_slice(&0u16.to_le_bytes()); // reserved
        // 16 bytes of key data
        for i in 0..16 {
            data[8 + i] = i as u8;
        }
        // optional_header_length = 1024
        data[24..32].copy_from_slice(&1024u64.to_le_bytes());

        let hdr = CartV1Header::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.arc4_key.len(), 16);
        assert_eq!(hdr.optional_header_length, 1024);
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut data = vec![0u8; CartV1Header::MIN_SIZE];
        data[0..4].copy_from_slice(b"bad!");
        assert!(CartV1Header::parse(&data).is_err());
    }

    #[test]
    fn test_header_too_short() {
        assert!(CartV1Header::parse(&[0u8; 10]).is_err());
    }
}
