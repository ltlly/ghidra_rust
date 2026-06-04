//! Apple DMG (Disk Image) format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.ios.dmg` package.
//!
//! References:
//! - <https://en.wikipedia.org/wiki/Apple_Disk_Image>

use nom::number::complete::{be_u32, be_u64};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// DMG trailer magic: `"koly"`.
pub const DMG_TRAILER_MAGIC: u32 = 0x6B6F6C79;

/// DMG trailer size (512 bytes).
pub const DMG_TRAILER_SIZE: usize = 512;

// ═══════════════════════════════════════════════════════════════════════════════════
// DMG Header (koly block)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Apple DMG "koly" trailer header.
#[derive(Debug, Clone)]
pub struct DmgHeader {
    /// Magic: `"koly"` (0x6B6F6C79).
    pub magic: u32,
    /// Version.
    pub version: u32,
    /// Header size (512).
    pub header_size: u32,
    /// Flags.
    pub flags: u32,
    /// Running data fork offset.
    pub running_data_fork_offset: u64,
    /// Data fork offset.
    pub data_fork_offset: u64,
    /// Data fork length.
    pub data_fork_length: u64,
    /// Resource fork offset.
    pub rsrc_fork_offset: u64,
    /// Resource fork length.
    pub rsrc_fork_length: u64,
    /// Segment number.
    pub segment_number: u32,
    /// Segment count.
    pub segment_count: u32,
    /// Segment ID (UUID).
    pub segment_id: [u8; 16],
    /// Data checksum type.
    pub data_checksum_type: u32,
    /// Data checksum size.
    pub data_checksum_size: u32,
    /// Data checksum (variable, up to 128 bytes).
    pub data_checksum: Vec<u8>,
    /// XMLOffset (plist offset).
    pub xml_offset: u64,
    /// XMLLength (plist length).
    pub xml_length: u64,
    /// Checksum type.
    pub checksum_type: u32,
    /// Checksum size.
    pub checksum_size: u32,
    /// Checksum data.
    pub checksum: Vec<u8>,
}

impl DmgHeader {
    /// Parse a DMG header from big-endian bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < DMG_TRAILER_SIZE {
            return Err("Data too short for DMG header".to_string());
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != DMG_TRAILER_MAGIC {
            return Err(format!("Invalid DMG magic: expected 0x{:08X}, got 0x{:08X}", DMG_TRAILER_MAGIC, magic));
        }

        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let header_size = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let flags = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        let running_data_fork_offset = u64::from_be_bytes(data[16..24].try_into().unwrap());
        let data_fork_offset = u64::from_be_bytes(data[24..32].try_into().unwrap());
        let data_fork_length = u64::from_be_bytes(data[32..40].try_into().unwrap());
        let rsrc_fork_offset = u64::from_be_bytes(data[40..48].try_into().unwrap());
        let rsrc_fork_length = u64::from_be_bytes(data[48..56].try_into().unwrap());

        let segment_number = u32::from_be_bytes(data[56..60].try_into().unwrap());
        let segment_count = u32::from_be_bytes(data[60..64].try_into().unwrap());
        let segment_id: [u8; 16] = data[64..80].try_into().unwrap();

        let data_checksum_type = u32::from_be_bytes(data[80..84].try_into().unwrap());
        let data_checksum_size = u32::from_be_bytes(data[84..88].try_into().unwrap());

        // Skip data_checksum (128 bytes at offset 88)
        let xml_offset = u64::from_be_bytes(data[216..224].try_into().unwrap());
        let xml_length = u64::from_be_bytes(data[224..232].try_into().unwrap());

        let checksum_type = u32::from_be_bytes(data[480..484].try_into().unwrap());
        let checksum_size = u32::from_be_bytes(data[484..488].try_into().unwrap());
        let checksum: Vec<u8> = data[488..488 + 32].to_vec();

        Ok(DmgHeader {
            magic,
            version,
            header_size,
            flags,
            running_data_fork_offset,
            data_fork_offset,
            data_fork_length,
            rsrc_fork_offset,
            rsrc_fork_length,
            segment_number,
            segment_count,
            segment_id,
            data_checksum_type,
            data_checksum_size,
            data_checksum: Vec::new(),
            xml_offset,
            xml_length,
            checksum_type,
            checksum_size,
            checksum,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.magic == DMG_TRAILER_MAGIC
    }
}

/// Check if data ends with DMG koly magic (DMG trailer is at the end).
pub fn is_dmg(data: &[u8]) -> bool {
    if data.len() < DMG_TRAILER_SIZE {
        return false;
    }
    let offset = data.len() - DMG_TRAILER_SIZE;
    u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) == DMG_TRAILER_MAGIC
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic() {
        assert_eq!(DMG_TRAILER_MAGIC, 0x6B6F6C79);
    }

    #[test]
    fn test_is_dmg() {
        let mut data = vec![0u8; DMG_TRAILER_SIZE];
        data[0..4].copy_from_slice(&DMG_TRAILER_MAGIC.to_be_bytes());
        assert!(is_dmg(&data));
        assert!(!is_dmg(&[0u8; 100]));
    }

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; DMG_TRAILER_SIZE];
        data[0..4].copy_from_slice(&DMG_TRAILER_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&4u32.to_be_bytes()); // version
        data[8..12].copy_from_slice(&512u32.to_be_bytes()); // header_size

        let hdr = DmgHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.header_size, 512);
    }

    #[test]
    fn test_header_invalid() {
        let mut data = vec![0u8; DMG_TRAILER_SIZE];
        data[0..4].copy_from_slice(b"bad!");
        assert!(DmgHeader::parse(&data).is_err());
    }
}
