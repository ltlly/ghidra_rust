//! COFF file header ported from Ghidra's `ghidra.app.util.bin.format.coff.CoffFileHeader`.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::byte_provider::ByteProvider;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::coff_exception::CoffException;
use super::coff_machine_type;

/// COFF file header.
///
/// Ported from `ghidra.app.util.bin.format.coff.CoffFileHeader`. Represents the
/// file header at the beginning of a COFF object file or COFF archive member.
#[derive(Debug, Clone)]
pub struct CoffFileHeader {
    /// Magic number identifying the machine type.
    pub f_magic: u16,
    /// Number of sections.
    pub f_nscns: u16,
    /// Time and date stamp.
    pub f_timdat: u32,
    /// File pointer to symbol table.
    pub f_symptr: u32,
    /// Number of entries in symbol table.
    pub f_nsyms: u32,
    /// Size of optional header.
    pub f_opthdr: u16,
    /// Flags.
    pub f_flags: u16,
    /// Target ID (TI COFF Level 1/2 only).
    pub f_target_id: Option<u16>,
}

impl CoffFileHeader {
    /// Minimum byte length required for a valid COFF header.
    const MIN_BYTE_LENGTH: u64 = 22;

    /// Number of bytes to check for all-zeros when machine type is UNKNOWN.
    const COFF_NULL_SANITY_CHECK_LEN: usize = 64;

    /// Check if the given data might be a valid COFF file by testing both
    /// endiannesses. Returns the detected endianness (`true` = little-endian).
    pub fn detect_endianness(provider: &dyn ByteProvider) -> Option<bool> {
        if provider.length() < Self::MIN_BYTE_LENGTH {
            return None;
        }
        // Read the first 2 bytes and interpret as both LE and BE
        let mut buf = [0u8; 2];
        if provider.read_bytes(0, &mut buf).is_err() {
            return None;
        }
        let le_magic = u16::from_le_bytes(buf);
        let be_magic = u16::from_be_bytes(buf);

        // Check LE first
        if coff_machine_type::is_machine_type_defined(le_magic)
            || Self::passes_null_check(provider, le_magic)
        {
            return Some(true);
        }
        // Check BE
        if coff_machine_type::is_machine_type_defined(be_magic)
            || Self::passes_null_check(provider, be_magic)
        {
            return Some(false);
        }
        None
    }

    /// Returns true if the magic is UNKNOWN but the file passes the all-zeros sanity check.
    fn passes_null_check(provider: &dyn ByteProvider, magic: u16) -> bool {
        if magic != coff_machine_type::IMAGE_FILE_MACHINE_UNKNOWN {
            return false;
        }
        if provider.length() <= Self::COFF_NULL_SANITY_CHECK_LEN as u64 {
            return false;
        }
        // Check that the first COFF_NULL_SANITY_CHECK_LEN bytes are not all zeros
        match provider.read_slice(0, Self::COFF_NULL_SANITY_CHECK_LEN) {
            Ok(bytes) => bytes.iter().any(|&b| b != 0),
            Err(_) => false,
        }
    }

    /// Returns true if the given provider contains a valid COFF file.
    pub fn is_valid(provider: &dyn ByteProvider) -> bool {
        Self::detect_endianness(provider).is_some()
    }

    /// Parse a COFF file header from the given provider.
    ///
    /// Automatically detects endianness.
    pub fn read(provider: Box<dyn ByteProvider>) -> Result<Self, CoffException> {
        let is_le = Self::detect_endianness(provider.as_ref())
            .ok_or_else(|| CoffException::new("Not a valid COFF file"))?;

        let mut reader = BinaryReader::new(provider, is_le);

        let f_magic = reader.read_next_u16().map_err(CoffException::from)?;
        let f_nscns = reader.read_next_u16().map_err(CoffException::from)?;
        let f_timdat = reader.read_next_u32().map_err(CoffException::from)?;
        let f_symptr = reader.read_next_u32().map_err(CoffException::from)?;
        let f_nsyms = reader.read_next_u32().map_err(CoffException::from)?;
        let f_opthdr = reader.read_next_u16().map_err(CoffException::from)?;
        let f_flags = reader.read_next_u16().map_err(CoffException::from)?;

        let f_target_id = if coff_machine_type::is_ticoff(f_magic) {
            Some(reader.read_next_u16().map_err(CoffException::from)?)
        } else {
            None
        };

        Ok(Self {
            f_magic,
            f_nscns,
            f_timdat,
            f_symptr,
            f_nsyms,
            f_opthdr,
            f_flags,
            f_target_id,
        })
    }

    /// Returns true if this is a TI COFF Level 1 or Level 2 header.
    pub fn is_ticoff(&self) -> bool {
        coff_machine_type::is_ticoff(self.f_magic)
    }

    /// Returns the size in bytes of this COFF file header.
    pub fn sizeof(&self) -> u16 {
        if self.is_ticoff() {
            22
        } else {
            20
        }
    }

    /// Returns the machine type (magic or target_id for TI COFF).
    pub fn machine(&self) -> u16 {
        if self.is_ticoff() {
            self.f_target_id.unwrap_or(self.f_magic)
        } else {
            self.f_magic
        }
    }

    /// Returns a human-readable machine name.
    pub fn machine_name(&self) -> String {
        let m = self.machine();
        match coff_machine_type::machine_type_name(m) {
            Some(name) => name.to_string(),
            None => format!("0x{:04x}", m),
        }
    }

    /// Returns the image base address.
    pub fn image_base(&self, is_windows_platform: bool) -> u64 {
        if is_windows_platform && self.f_opthdr != 0 {
            0x80
        } else {
            0
        }
    }

    /// Returns the file offset where section headers begin.
    pub fn section_headers_offset(&self) -> u64 {
        (self.sizeof() + self.f_opthdr) as u64
    }
}

impl StructConverter for CoffFileHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        let mut fields = vec![
            ("f_magic".into(), DataTypeDescription::Word),
            ("f_nscns".into(), DataTypeDescription::Word),
            ("f_timdat".into(), DataTypeDescription::DWord),
            ("f_symptr".into(), DataTypeDescription::DWord),
            ("f_nsyms".into(), DataTypeDescription::DWord),
            ("f_opthdr".into(), DataTypeDescription::Word),
            ("f_flags".into(), DataTypeDescription::Word),
        ];
        if self.is_ticoff() {
            fields.push(("f_target_id".into(), DataTypeDescription::Word));
        }
        DataTypeDescription::Struct {
            name: "CoffFileHeader".into(),
            size: self.sizeof() as u32,
            fields,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_format::byte_provider::ByteArrayProvider;

    #[test]
    fn test_coff_file_header_read_le() {
        // Build a minimal COFF header for i386 (LE)
        // MIN_BYTE_LENGTH is 22, so we need at least 22 bytes
        let mut data = vec![0u8; 22];
        // f_magic = 0x014c (i386) LE
        data[0] = 0x4c;
        data[1] = 0x01;
        // f_nscns = 1
        data[2] = 0x01;
        data[3] = 0x00;
        // f_timdat = 0
        // f_symptr = 0
        // f_nsyms = 0
        // f_opthdr = 0
        // f_flags = 0

        let provider: Box<dyn ByteProvider> = Box::new(ByteArrayProvider::new(None, data));
        let header = CoffFileHeader::read(provider).unwrap();
        assert_eq!(header.f_magic, 0x014c);
        assert_eq!(header.f_nscns, 1);
        assert_eq!(header.sizeof(), 20);
        assert!(!header.is_ticoff());
        assert_eq!(header.machine(), 0x014c);
    }

    #[test]
    fn test_coff_file_header_invalid() {
        let data = vec![0xFFu8; 22];
        let provider: Box<dyn ByteProvider> = Box::new(ByteArrayProvider::new(None, data));
        assert!(CoffFileHeader::read(provider).is_err());
    }

    #[test]
    fn test_coff_file_header_too_short() {
        let data = vec![0u8; 10];
        let provider: Box<dyn ByteProvider> = Box::new(ByteArrayProvider::new(None, data));
        assert!(CoffFileHeader::read(provider).is_err());
    }

    #[test]
    fn test_coff_file_header_is_valid() {
        let mut data = vec![0u8; 22];
        data[0] = 0x4c; // i386 LE
        data[1] = 0x01;
        let provider = ByteArrayProvider::new(None, data);
        assert!(CoffFileHeader::is_valid(&provider));
    }
}
