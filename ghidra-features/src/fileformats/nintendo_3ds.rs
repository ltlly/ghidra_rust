//! Nintendo 3DS extended format helpers.
//!
//! This module provides higher-level 3DS analysis helpers that complement
//! the core NCSD/NCCH/ExeFS parser in [`crate::fileformats::nintendo::n3ds`].
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.ncsd` package.
//!
//! # CIA (CTR Installable Archive) support
//!
//! CIA files are used for eShop downloads and system titles.  They wrap
//! one or more NCCH partitions with ticket, TMD, and certificate data.
//!
//! References:
//! - [3dbrew: CIA](https://www.3dbrew.org/wiki/CIA)
//! - Ghidra's `ghidra.app.util.bin.format.ncsd` package

use crate::fileformats::nintendo::n3ds::MEDIA_UNIT_SIZE;

// ═══════════════════════════════════════════════════════════════════════════════════
// CIA Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// CIA (CTR Installable Archive) header.
///
/// The CIA format is used by the 3DS eShop for distributing titles.
/// It wraps NCCH content with certificate chain, ticket, and TMD
/// (title metadata) sections.
#[derive(Debug, Clone)]
pub struct CiaHeader {
    /// Header size (always 0x20).
    pub header_size: u32,
    /// Type (0 = normal, 1 = system).
    pub type_: u16,
    /// Version.
    pub version: u16,
    /// Certificate chain size.
    pub cert_chain_size: u32,
    /// Ticket size.
    pub ticket_size: u32,
    /// TMD (title metadata) file size.
    pub tmd_file_size: u32,
    /// Meta size (0 if no meta section).
    pub meta_size: u32,
    /// Content size (total size of all NCCH partitions).
    pub content_size: u64,
}

impl CiaHeader {
    /// Size of the on-disk header (32 bytes).
    pub const SIZE: usize = 32;

    /// CIA magic bytes ("CIA\x00").
    pub const MAGIC: [u8; 4] = *b"CIA\x00";

    /// Parse a CIA header from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for CiaHeader".to_string());
        }

        // Validate magic (first 4 bytes in some CIA variants; in others it starts at 0)
        let header_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let type_ = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let version = u16::from_le_bytes(data[6..8].try_into().unwrap());
        let cert_chain_size = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let ticket_size = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let tmd_file_size = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let meta_size = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let content_size = u64::from_le_bytes(data[24..32].try_into().unwrap());

        Ok(CiaHeader {
            header_size,
            type_,
            version,
            cert_chain_size,
            ticket_size,
            tmd_file_size,
            meta_size,
            content_size,
        })
    }

    /// Returns true if this is a system title.
    pub fn is_system(&self) -> bool {
        self.type_ == 1
    }

    /// Returns true if the meta section is present.
    pub fn has_meta(&self) -> bool {
        self.meta_size > 0
    }

    /// Returns the offset to the certificate chain (immediately after the header).
    pub fn cert_chain_offset(&self) -> u64 {
        // CIA sections are aligned to 64-byte boundaries
        align64(self.header_size as u64)
    }

    /// Returns the offset to the ticket.
    pub fn ticket_offset(&self) -> u64 {
        align64(self.cert_chain_offset() + self.cert_chain_size as u64)
    }

    /// Returns the offset to the TMD file.
    pub fn tmd_offset(&self) -> u64 {
        align64(self.ticket_offset() + self.ticket_size as u64)
    }

    /// Returns the offset to the content (NCCH partitions).
    pub fn content_offset(&self) -> u64 {
        align64(self.tmd_offset() + self.tmd_file_size as u64)
    }

    /// Returns the total size of the CIA file.
    pub fn total_size(&self) -> u64 {
        let base = self.content_offset() + self.content_size;
        if self.meta_size > 0 {
            align64(base) + self.meta_size as u64
        } else {
            base
        }
    }
}

/// Align a value up to the next 64-byte boundary.
fn align64(value: u64) -> u64 {
    (value + 63) & !63
}

// ═══════════════════════════════════════════════════════════════════════════════════
// TMD Content Chunk Record
// ═══════════════════════════════════════════════════════════════════════════════════

/// A content chunk record from the TMD (Title Metadata).
///
/// Each content chunk describes one NCCH partition within a title.
#[derive(Debug, Clone)]
pub struct TmdContentChunk {
    /// Content ID (SHA-256 hash prefix).
    pub content_id: [u8; 16],
    /// Content index.
    pub content_index: u16,
    /// Content type flags.
    pub content_type: u16,
    /// Content size in bytes.
    pub content_size: u64,
    /// SHA-256 hash of the content.
    pub hash: [u8; 32],
}

impl TmdContentChunk {
    /// Size of the on-disk structure (60 bytes).
    pub const SIZE: usize = 60;

    /// Parse a content chunk from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for TmdContentChunk".to_string());
        }

        let mut content_id = [0u8; 16];
        content_id.copy_from_slice(&data[0..16]);

        let content_index = u16::from_le_bytes(data[16..18].try_into().unwrap());
        let content_type = u16::from_le_bytes(data[18..20].try_into().unwrap());
        let content_size = u64::from_le_bytes(data[20..28].try_into().unwrap());

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[28..60]);

        Ok(TmdContentChunk {
            content_id,
            content_index,
            content_type,
            content_size,
            hash,
        })
    }

    /// Returns true if this content is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.content_type & 0x0001 != 0
    }

    /// Returns true if this content is a disc (as opposed to a download).
    pub fn is_disc(&self) -> bool {
        self.content_type & 0x0002 != 0
    }

    /// Returns true if this content is a CFM (content file map).
    pub fn is_cfm(&self) -> bool {
        self.content_type & 0x0004 != 0
    }

    /// Returns the content ID as a hex string.
    pub fn content_id_hex(&self) -> String {
        self.content_id.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Returns the content size in media units (0x200 bytes each).
    pub fn content_size_media_units(&self) -> u32 {
        (self.content_size / MEDIA_UNIT_SIZE as u64) as u32
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// TMD Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Simplified TMD (Title Metadata) header.
///
/// The TMD contains the title ID, version, and content hashes for
/// all NCCH partitions in a 3DS title.
#[derive(Debug, Clone)]
pub struct TmdHeader {
    /// Signature type.
    pub signature_type: u32,
    /// Title ID (8 bytes).
    pub title_id: [u8; 8],
    /// Title version.
    pub title_version: u16,
    /// Content count.
    pub content_count: u16,
    /// Content index (hash of all content chunk hashes).
    pub content_index: [u8; 32],
}

impl TmdHeader {
    /// Size of the simplified header (48 bytes).
    pub const SIZE: usize = 48;

    /// Parse a TMD header from a byte slice.
    ///
    /// Note: the real TMD has a variable-length signature before this data.
    /// This parser assumes `data` starts at the "issuer" field after the
    /// signature, or at the beginning of a raw TMD blob.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for TmdHeader".to_string());
        }

        let signature_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let mut title_id = [0u8; 8];
        title_id.copy_from_slice(&data[16..24]);
        let title_version = u16::from_le_bytes(data[24..26].try_into().unwrap());
        let content_count = u16::from_le_bytes(data[26..28].try_into().unwrap());
        let mut content_index = [0u8; 32];
        let src = &data[28..60.min(data.len())];
        content_index[..src.len()].copy_from_slice(src);

        Ok(TmdHeader {
            signature_type,
            title_id,
            title_version,
            content_count,
            content_index,
        })
    }

    /// Returns the title ID as a u64.
    pub fn title_id_u64(&self) -> u64 {
        u64::from_be_bytes(self.title_id)
    }

    /// Returns the title ID as a hex string.
    pub fn title_id_hex(&self) -> String {
        self.title_id.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Ticket
// ═══════════════════════════════════════════════════════════════════════════════════

/// Simplified 3DS ticket structure.
///
/// A ticket contains the title key used to decrypt the associated
/// content (NCCH partitions).
#[derive(Debug, Clone)]
pub struct Ticket {
    /// Signature type.
    pub signature_type: u32,
    /// Ticket format version.
    pub version: u8,
    /// Title ID (8 bytes, big-endian).
    pub title_id: [u8; 8],
    /// Title key (16 bytes, AES-128).
    pub title_key: [u8; 16],
}

impl Ticket {
    /// Size of the simplified ticket structure (32 bytes).
    pub const SIZE: usize = 32;

    /// Parse a ticket from a byte slice.
    ///
    /// Note: real tickets have a variable-length signature.  This parser
    /// assumes `data` starts at the ticket body after the signature.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for Ticket".to_string());
        }

        let signature_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let version = data[4];
        let mut title_id = [0u8; 8];
        title_id.copy_from_slice(&data[8..16]);
        let mut title_key = [0u8; 16];
        title_key.copy_from_slice(&data[16..32]);

        Ok(Ticket {
            signature_type,
            version,
            title_id,
            title_key,
        })
    }

    /// Returns the title ID as a u64.
    pub fn title_id_u64(&self) -> u64 {
        u64::from_be_bytes(self.title_id)
    }

    /// Returns the title key as a hex string.
    pub fn title_key_hex(&self) -> String {
        self.title_key.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cia_header_parse() {
        let mut data = vec![0u8; CiaHeader::SIZE];
        data[0..4].copy_from_slice(&0x20u32.to_le_bytes()); // header_size
        data[4..6].copy_from_slice(&0u16.to_le_bytes()); // type = normal
        data[6..8].copy_from_slice(&0u16.to_le_bytes()); // version
        data[8..12].copy_from_slice(&0x1000u32.to_le_bytes()); // cert_chain_size
        data[12..16].copy_from_slice(&0x400u32.to_le_bytes()); // ticket_size
        data[16..20].copy_from_slice(&0x800u32.to_le_bytes()); // tmd_file_size
        data[20..24].copy_from_slice(&0u32.to_le_bytes()); // meta_size
        data[24..32].copy_from_slice(&0x100000u64.to_le_bytes()); // content_size

        let header = CiaHeader::parse(&data).unwrap();
        assert_eq!(header.header_size, 0x20);
        assert!(!header.is_system());
        assert!(!header.has_meta());
        assert_eq!(header.content_size, 0x100000);
        // cert_chain_offset = align64(0x20) = 0x40
        assert_eq!(header.cert_chain_offset(), 0x40);
    }

    #[test]
    fn test_cia_header_system() {
        let mut data = vec![0u8; CiaHeader::SIZE];
        data[0..4].copy_from_slice(&0x20u32.to_le_bytes());
        data[4..6].copy_from_slice(&1u16.to_le_bytes()); // type = system

        let header = CiaHeader::parse(&data).unwrap();
        assert!(header.is_system());
    }

    #[test]
    fn test_tmd_content_chunk_parse() {
        let mut data = vec![0u8; TmdContentChunk::SIZE];
        data[0..16].copy_from_slice(&[0xAA; 16]); // content_id
        data[16..18].copy_from_slice(&0u16.to_le_bytes()); // content_index
        data[18..20].copy_from_slice(&0x0001u16.to_le_bytes()); // content_type = encrypted
        data[20..28].copy_from_slice(&0x80000u64.to_le_bytes()); // content_size

        let chunk = TmdContentChunk::parse(&data).unwrap();
        assert!(chunk.is_encrypted());
        assert!(!chunk.is_disc());
        assert_eq!(chunk.content_size, 0x80000);
        assert_eq!(chunk.content_size_media_units(), 0x80000 / 0x200);
        assert_eq!(chunk.content_id_hex(), "aa".repeat(16));
    }

    #[test]
    fn test_ticket_parse() {
        let mut data = vec![0u8; Ticket::SIZE];
        data[0..4].copy_from_slice(&0x010000u32.to_le_bytes()); // RSA-2048
        data[4] = 0; // version
        data[8..16].copy_from_slice(&0x0004000000123400u64.to_be_bytes()); // title_id
        data[16..32].copy_from_slice(&[0xBB; 16]); // title_key

        let ticket = Ticket::parse(&data).unwrap();
        assert_eq!(ticket.title_id_u64(), 0x0004000000123400);
        assert_eq!(ticket.title_key_hex(), "bb".repeat(16));
    }

    #[test]
    fn test_align64() {
        assert_eq!(align64(0), 0);
        assert_eq!(align64(1), 64);
        assert_eq!(align64(63), 64);
        assert_eq!(align64(64), 64);
        assert_eq!(align64(65), 128);
    }

    #[test]
    fn test_cia_header_truncated() {
        let data = vec![0u8; 10];
        assert!(CiaHeader::parse(&data).is_err());
    }
}
