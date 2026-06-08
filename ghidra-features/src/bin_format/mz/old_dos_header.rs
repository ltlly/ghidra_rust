//! DOS MZ executable header ported from Ghidra's `OldDOSHeader.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

/// The DOS MZ magic signature (`MZ` = 0x5A4D).
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

/// Old-style DOS header (14 words, 28 bytes).
///
/// Ported from `ghidra.app.util.bin.format.mz.OldDOSHeader`. Represents the
/// original DOS executable header with fields for segment/offset initialization
/// and relocation table metadata.
///
/// ```text
/// WORD   e_magic;      // Magic number (0x5A4D = "MZ")
/// WORD   e_cblp;       // Bytes on last page of file
/// WORD   e_cp;         // Pages in file
/// WORD   e_crlc;       // Relocations
/// WORD   e_cparhdr;    // Size of header in paragraphs
/// WORD   e_minalloc;   // Minimum extra paragraphs needed
/// WORD   e_maxalloc;   // Maximum extra paragraphs needed
/// WORD   e_ss;         // Initial (relative) SS value
/// WORD   e_sp;         // Initial SP value
/// WORD   e_csum;       // Checksum
/// WORD   e_ip;         // Initial IP value
/// WORD   e_cs;         // Initial (relative) CS value
/// WORD   e_lfarlc;     // File address of relocation table
/// WORD   e_ovno;       // Overlay number
/// ```
#[derive(Debug, Clone)]
pub struct OldDOSHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
}

impl OldDOSHeader {
    /// Size of the old DOS header in bytes (14 x u16 = 28 bytes).
    pub const SIZE: usize = 14 * 2;

    /// Parse an old DOS header from a binary reader at offset 0.
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        reader.set_cursor(0);

        let e_magic = reader.read_next_u16()?;

        let mut header = Self {
            e_magic,
            e_cblp: 0,
            e_cp: 0,
            e_crlc: 0,
            e_cparhdr: 0,
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0,
            e_ovno: 0,
        };

        if !header.is_dos_signature() {
            return Ok(header);
        }

        header.e_cblp = reader.read_next_u16()?;
        header.e_cp = reader.read_next_u16()?;
        header.e_crlc = reader.read_next_u16()?;
        header.e_cparhdr = reader.read_next_u16()?;
        header.e_minalloc = reader.read_next_u16()?;
        header.e_maxalloc = reader.read_next_u16()?;
        header.e_ss = reader.read_next_u16()?;
        header.e_sp = reader.read_next_u16()?;
        header.e_csum = reader.read_next_u16()?;
        header.e_ip = reader.read_next_u16()?;
        header.e_cs = reader.read_next_u16()?;
        header.e_lfarlc = reader.read_next_u16()?;
        header.e_ovno = reader.read_next_u16()?;

        Ok(header)
    }

    /// Returns the processor name for this header type.
    pub fn processor_name(&self) -> &'static str {
        "x86"
    }

    /// Returns true if the magic number matches `IMAGE_DOS_SIGNATURE`.
    pub fn is_dos_signature(&self) -> bool {
        self.e_magic == IMAGE_DOS_SIGNATURE
    }

    /// Returns true if a new EXE header exists (always false for old DOS).
    pub fn has_new_exe_header(&self) -> bool {
        false
    }

    /// Returns true if a PE header exists (always false for old DOS).
    pub fn has_pe_header(&self) -> bool {
        false
    }
}

impl StructConverter for OldDOSHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "OLD_IMAGE_DOS_HEADER".to_string(),
            size: 28,
            fields: vec![
                ("e_magic".into(), DataTypeDescription::Word),
                ("e_cblp".into(), DataTypeDescription::Word),
                ("e_cp".into(), DataTypeDescription::Word),
                ("e_crlc".into(), DataTypeDescription::Word),
                ("e_cparhdr".into(), DataTypeDescription::Word),
                ("e_minalloc".into(), DataTypeDescription::Word),
                ("e_maxalloc".into(), DataTypeDescription::Word),
                ("e_ss".into(), DataTypeDescription::Word),
                ("e_sp".into(), DataTypeDescription::Word),
                ("e_csum".into(), DataTypeDescription::Word),
                ("e_ip".into(), DataTypeDescription::Word),
                ("e_cs".into(), DataTypeDescription::Word),
                ("e_lfarlc".into(), DataTypeDescription::Word),
                ("e_ovno".into(), DataTypeDescription::Word),
            ],
        }
    }
}

impl BinaryWritable for OldDOSHeader {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_u16(self.e_magic);
        writer.write_u16(self.e_cblp);
        writer.write_u16(self.e_cp);
        writer.write_u16(self.e_crlc);
        writer.write_u16(self.e_cparhdr);
        writer.write_u16(self.e_minalloc);
        writer.write_u16(self.e_maxalloc);
        writer.write_u16(self.e_ss);
        writer.write_u16(self.e_sp);
        writer.write_u16(self.e_csum);
        writer.write_u16(self.e_ip);
        writer.write_u16(self.e_cs);
        writer.write_u16(self.e_lfarlc);
        writer.write_u16(self.e_ovno);
        Ok(())
    }
}

impl fmt::Display for OldDOSHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OldDOSHeader {{ magic=0x{:04X}, relocations={}, header_paragraphs={}, \
             overlay={} }}",
            self.e_magic, self.e_crlc, self.e_cparhdr, self.e_ovno
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_header_bytes() -> Vec<u8> {
        let mut data = vec![0u8; OldDOSHeader::SIZE];
        // e_magic = 0x5A4D
        data[0] = 0x4D;
        data[1] = 0x5A;
        // e_cblp = 0x0090
        data[2] = 0x90;
        data[3] = 0x00;
        // e_cp = 0x0003
        data[4] = 0x03;
        data[5] = 0x00;
        // e_crlc = 0x0004 (4 relocations)
        data[6] = 0x04;
        data[7] = 0x00;
        // e_cparhdr = 0x0004
        data[8] = 0x04;
        data[9] = 0x00;
        // e_lfarlc = 0x0040
        data[24] = 0x40;
        data[25] = 0x00;
        data
    }

    #[test]
    fn test_parse_valid_header() {
        let data = make_valid_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = OldDOSHeader::parse(&mut reader).unwrap();

        assert!(header.is_dos_signature());
        assert_eq!(header.e_magic, IMAGE_DOS_SIGNATURE);
        assert_eq!(header.e_cblp, 0x0090);
        assert_eq!(header.e_cp, 3);
        assert_eq!(header.e_crlc, 4);
        assert_eq!(header.e_cparhdr, 4);
        assert_eq!(header.e_lfarlc, 0x40);
        assert_eq!(header.processor_name(), "x86");
    }

    #[test]
    fn test_parse_invalid_magic() {
        let data = vec![0x00u8; OldDOSHeader::SIZE];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = OldDOSHeader::parse(&mut reader).unwrap();

        assert!(!header.is_dos_signature());
        // Fields after magic should remain at default (0)
        assert_eq!(header.e_cblp, 0);
    }

    #[test]
    fn test_old_dos_header_write() {
        let data = make_valid_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = OldDOSHeader::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        header.write_to(&mut writer).unwrap();
        let written = writer.into_vec();

        assert_eq!(written, data);
    }

    #[test]
    fn test_old_dos_header_struct_converter() {
        let data = make_valid_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = OldDOSHeader::parse(&mut reader).unwrap();

        let dt = header.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "OLD_IMAGE_DOS_HEADER");
                assert_eq!(fields.len(), 14);
                assert_eq!(fields[0].0, "e_magic");
                assert_eq!(fields[13].0, "e_ovno");
            }
            _ => panic!("Expected Struct"),
        }
        assert_eq!(dt.size(), Some(28));
    }

    #[test]
    fn test_has_new_exe_header_false() {
        let data = make_valid_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = OldDOSHeader::parse(&mut reader).unwrap();
        assert!(!header.has_new_exe_header());
        assert!(!header.has_pe_header());
    }

    #[test]
    fn test_display() {
        let data = make_valid_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = OldDOSHeader::parse(&mut reader).unwrap();
        let s = format!("{}", header);
        assert!(s.contains("0x5A4D"));
        assert!(s.contains("relocations=4"));
    }
}
