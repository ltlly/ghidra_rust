//! MZ executable loader ported from Ghidra's `MzExecutable.java`.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::byte_provider::ByteProvider;

use super::mz_relocation::MzRelocation;
use super::old_dos_header::OldDOSHeader;

/// An old-style DOS MZ executable.
///
/// Ported from `ghidra.app.util.bin.format.mz.MzExecutable`. Parses the DOS
/// header and relocation table from a byte provider.
#[derive(Debug)]
pub struct MzExecutable {
    header: OldDOSHeader,
    relocations: Vec<MzRelocation>,
}

impl MzExecutable {
    /// Parse an MZ executable from a byte provider (always little-endian).
    pub fn parse(provider: Box<dyn ByteProvider>) -> io::Result<Self> {
        let mut reader = BinaryReader::new(provider, true);
        let header = OldDOSHeader::parse(&mut reader)?;

        if !header.is_dos_signature() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid DOS magic: expected 0x{:04X}, got 0x{:04X}",
                    super::old_dos_header::IMAGE_DOS_SIGNATURE,
                    header.e_magic
                ),
            ));
        }

        let relocations = MzRelocation::parse_all(
            &mut reader,
            header.e_lfarlc as u64,
            header.e_crlc as usize,
        )?;

        Ok(Self {
            header,
            relocations,
        })
    }

    /// Returns a reference to the DOS header.
    pub fn header(&self) -> &OldDOSHeader {
        &self.header
    }

    /// Returns the relocation entries.
    pub fn relocations(&self) -> &[MzRelocation] {
        &self.relocations
    }

    /// Returns the number of relocations.
    pub fn relocation_count(&self) -> usize {
        self.relocations.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_format::byte_provider::ByteArrayProvider;

    fn make_mz_bytes(reloc_count: u16) -> Vec<u8> {
        let header_size: usize = 28;
        let reloc_table_offset: u16 = 0x40;
        let reloc_table_size = reloc_count as usize * 4;
        let total_size = (reloc_table_offset as usize) + reloc_table_size + 16;
        let mut data = vec![0u8; total_size];

        // e_magic = 0x5A4D
        data[0] = 0x4D;
        data[1] = 0x5A;

        // e_crlc (relocation count) at offset 6
        data[6] = (reloc_count & 0xFF) as u8;
        data[7] = (reloc_count >> 8) as u8;

        // e_lfarlc (relocation table offset) at offset 24
        data[24] = (reloc_table_offset & 0xFF) as u8;
        data[25] = (reloc_table_offset >> 8) as u8;

        // Write relocation entries at offset 0x40
        let mut off = reloc_table_offset as usize;
        for i in 0..reloc_count {
            // offset
            data[off] = ((i * 0x10) & 0xFF) as u8;
            data[off + 1] = (((i * 0x10) >> 8) & 0xFF) as u8;
            // segment
            data[off + 2] = ((0x1000 + i as u32 * 0x100) & 0xFF) as u8;
            data[off + 3] = (((0x1000 + i as u32 * 0x100) >> 8) & 0xFF) as u8;
            off += 4;
        }

        data
    }

    #[test]
    fn test_parse_mz_executable() {
        let data = make_mz_bytes(3);
        let provider = Box::new(ByteArrayProvider::new(None, data));
        let exe = MzExecutable::parse(provider).unwrap();

        assert!(exe.header().is_dos_signature());
        assert_eq!(exe.relocation_count(), 3);

        let relocs = exe.relocations();
        assert_eq!(relocs[0].offset, 0x0000);
        assert_eq!(relocs[0].segment, 0x1000);
        assert_eq!(relocs[1].offset, 0x0010);
        assert_eq!(relocs[1].segment, 0x1100);
        assert_eq!(relocs[2].offset, 0x0020);
        assert_eq!(relocs[2].segment, 0x1200);
    }

    #[test]
    fn test_parse_mz_no_relocations() {
        let data = make_mz_bytes(0);
        let provider = Box::new(ByteArrayProvider::new(None, data));
        let exe = MzExecutable::parse(provider).unwrap();

        assert_eq!(exe.relocation_count(), 0);
        assert!(exe.relocations().is_empty());
    }

    #[test]
    fn test_parse_invalid_magic() {
        let data = vec![0u8; 64];
        let provider = Box::new(ByteArrayProvider::new(None, data));
        let result = MzExecutable::parse(provider);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_header_access() {
        let data = make_mz_bytes(1);
        let provider = Box::new(ByteArrayProvider::new(None, data));
        let exe = MzExecutable::parse(provider).unwrap();

        let hdr = exe.header();
        assert_eq!(hdr.e_magic, 0x5A4D);
        assert_eq!(hdr.e_crlc, 1);
        assert_eq!(hdr.e_lfarlc, 0x40);
    }
}
