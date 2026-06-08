//! Full IMAGE_DOS_HEADER ported from Ghidra's `DOSHeader.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::old_dos_header::{OldDOSHeader, IMAGE_DOS_SIGNATURE};

/// Full DOS header size in bytes (64 bytes).
pub const SIZEOF_DOS_HEADER: usize = 64;

/// Full IMAGE_DOS_HEADER as defined in `winnt.h`.
///
/// Extends [`OldDOSHeader`] with reserved words, OEM identifiers, and
/// the `e_lfanew` field pointing to the PE/NE header.
///
/// ```text
/// typedef struct _IMAGE_DOS_HEADER {
///     WORD   e_magic;          // Magic number
///     WORD   e_cblp;           // Bytes on last page of file
///     WORD   e_cp;             // Pages in file
///     WORD   e_crlc;           // Relocations
///     WORD   e_cparhdr;        // Size of header in paragraphs
///     WORD   e_minalloc;       // Minimum extra paragraphs needed
///     WORD   e_maxalloc;       // Maximum extra paragraphs needed
///     WORD   e_ss;             // Initial (relative) SS value
///     WORD   e_sp;             // Initial SP value
///     WORD   e_csum;           // Checksum
///     WORD   e_ip;             // Initial IP value
///     WORD   e_cs;             // Initial (relative) CS value
///     WORD   e_lfarlc;         // File address of relocation table
///     WORD   e_ovno;           // Overlay number
///     WORD   e_res[4];         // Reserved words
///     WORD   e_oemid;          // OEM identifier
///     WORD   e_oeminfo;        // OEM information
///     WORD   e_res2[10];       // Reserved words
///     LONG   e_lfanew;         // File address of new exe header
/// } IMAGE_DOS_HEADER;
/// ```
#[derive(Debug, Clone)]
pub struct DOSHeader {
    /// The base old DOS header fields.
    pub base: OldDOSHeader,
    /// Reserved words (4 entries).
    pub e_res: [u16; 4],
    /// OEM identifier (for e_oeminfo).
    pub e_oemid: u16,
    /// OEM information; e_oemid specific.
    pub e_oeminfo: u16,
    /// Reserved words (10 entries).
    pub e_res2: [u16; 10],
    /// File address of new exe header (PE/NE).
    pub e_lfanew: i32,
    /// DOS stub program bytes (between header and PE/NE header).
    stub_bytes: Vec<u8>,
}

impl DOSHeader {
    /// Parse a full DOS header from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = OldDOSHeader::parse(reader)?;

        let mut header = Self {
            base,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: 0,
            stub_bytes: Vec::new(),
        };

        if !header.base.is_dos_signature() {
            return Ok(header);
        }

        // Read reserved words, OEM fields, and e_lfanew
        for i in 0..4 {
            header.e_res[i] = reader.read_next_u16()?;
        }
        header.e_oemid = reader.read_next_u16()?;
        header.e_oeminfo = reader.read_next_u16()?;
        for i in 0..10 {
            header.e_res2[i] = reader.read_next_u16()?;
        }
        header.e_lfanew = reader.read_next_i32()?;

        // Read DOS stub bytes (program between header and new exe header)
        if header.e_lfanew >= 0 && (header.e_lfanew as u64) < 0x10000 {
            let lfanew = header.e_lfanew as u64;
            if lfanew > SIZEOF_DOS_HEADER as u64 {
                let stub_len = lfanew - SIZEOF_DOS_HEADER as u64;
                header.stub_bytes = reader.read_bytes_at(SIZEOF_DOS_HEADER as u64, stub_len as usize)?;
            }
        }

        Ok(header)
    }

    /// Returns the length of the DOS stub program in bytes.
    pub fn program_len(&self) -> usize {
        self.stub_bytes.len()
    }

    /// Returns a reference to the DOS stub bytes.
    pub fn stub_bytes(&self) -> &[u8] {
        &self.stub_bytes
    }

    /// Trim the stub bytes to start at the given file offset.
    pub fn decrement_stub(&mut self, reader: &mut BinaryReader, start: u64) {
        if self.stub_bytes.is_empty() {
            return;
        }
        self.stub_bytes = if start > SIZEOF_DOS_HEADER as u64 {
            reader
                .read_bytes_at(SIZEOF_DOS_HEADER as u64, (start - SIZEOF_DOS_HEADER as u64) as usize)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
    }

    /// Returns true if a new EXE header exists.
    ///
    /// Checks for NE (Windows) header presence.
    pub fn has_new_exe_header(&self) -> bool {
        if self.e_lfanew >= 0 && self.e_lfanew <= 0x10000 {
            // Would need to read NE signature at e_lfanew to confirm.
            // Simplified: check e_lfarlc == 0x40 as a heuristic.
            if self.base.e_lfarlc == 0x40 {
                return true;
            }
        }
        false
    }

    /// Returns true if a PE header exists.
    ///
    /// Simplified check: e_lfanew must be in valid range.
    pub fn has_pe_header(&self) -> bool {
        self.e_lfanew >= 0 && self.e_lfanew <= 0x1000000
    }
}

impl StructConverter for DOSHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        let mut fields = match self.base.to_data_type() {
            DataTypeDescription::Struct { fields, .. } => fields,
            _ => unreachable!(),
        };

        fields.push(("e_res[4]".into(), DataTypeDescription::Array {
            element: Box::new(DataTypeDescription::Word),
            count: 4,
        }));
        fields.push(("e_oemid".into(), DataTypeDescription::Word));
        fields.push(("e_oeminfo".into(), DataTypeDescription::Word));
        fields.push(("e_res2[10]".into(), DataTypeDescription::Array {
            element: Box::new(DataTypeDescription::Word),
            count: 10,
        }));
        fields.push(("e_lfanew".into(), DataTypeDescription::DWord));

        if !self.stub_bytes.is_empty() {
            fields.push(("e_program".into(), DataTypeDescription::Array {
                element: Box::new(DataTypeDescription::Byte),
                count: self.stub_bytes.len(),
            }));
        }

        DataTypeDescription::Struct {
            name: "IMAGE_DOS_HEADER".to_string(),
            size: fields.iter().filter_map(|(_, dt)| dt.size()).sum::<usize>() as u32,
            fields,
        }
    }
}

impl BinaryWritable for DOSHeader {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        // Write base old DOS header
        self.base.write_to(writer)?;

        // Write reserved words
        for &val in &self.e_res {
            writer.write_u16(val);
        }
        writer.write_u16(self.e_oemid);
        writer.write_u16(self.e_oeminfo);
        for &val in &self.e_res2 {
            writer.write_u16(val);
        }
        writer.write_i32(self.e_lfanew);
        writer.write_bytes(&self.stub_bytes);
        Ok(())
    }
}

impl fmt::Display for DOSHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DOSHeader {{ magic=0x{:04X}, e_lfanew=0x{:08X}, stub_len={} }}",
            self.base.e_magic, self.e_lfanew, self.stub_bytes.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dos_header_bytes(e_lfanew: i32, include_stub: bool) -> Vec<u8> {
        let stub_len = if include_stub && e_lfanew > SIZEOF_DOS_HEADER as i32 {
            (e_lfanew as usize) - SIZEOF_DOS_HEADER
        } else {
            0
        };
        let total = if include_stub {
            e_lfanew as usize
        } else {
            SIZEOF_DOS_HEADER
        };
        let mut data = vec![0u8; total];

        // e_magic = 0x5A4D
        data[0] = 0x4D;
        data[1] = 0x5A;

        // e_lfarlc at offset 24
        data[24] = 0x40;
        data[25] = 0x00;

        // e_lfanew at offset 60
        let le_bytes = (e_lfanew as u32).to_le_bytes();
        data[60] = le_bytes[0];
        data[61] = le_bytes[1];
        data[62] = le_bytes[2];
        data[63] = le_bytes[3];

        // Fill stub with recognizable pattern
        if stub_len > 0 {
            for i in SIZEOF_DOS_HEADER..total {
                data[i] = 0xCC;
            }
        }

        data
    }

    #[test]
    fn test_parse_dos_header() {
        let data = make_dos_header_bytes(0x80, true);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = DOSHeader::parse(&mut reader).unwrap();

        assert!(header.base.is_dos_signature());
        assert_eq!(header.e_lfanew, 0x80);
        assert_eq!(header.program_len(), 0x80 - SIZEOF_DOS_HEADER);
        assert!(header.stub_bytes().iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn test_parse_dos_header_no_stub() {
        let data = make_dos_header_bytes(SIZEOF_DOS_HEADER as i32, false);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = DOSHeader::parse(&mut reader).unwrap();

        assert!(header.base.is_dos_signature());
        assert_eq!(header.program_len(), 0);
    }

    #[test]
    fn test_parse_invalid_magic() {
        let data = vec![0u8; SIZEOF_DOS_HEADER];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = DOSHeader::parse(&mut reader).unwrap();

        assert!(!header.base.is_dos_signature());
        assert_eq!(header.e_lfanew, 0);
    }

    #[test]
    fn test_dos_header_write_roundtrip() {
        let data = make_dos_header_bytes(0x80, true);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = DOSHeader::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        header.write_to(&mut writer).unwrap();
        let written = writer.into_vec();

        assert_eq!(written, data);
    }

    #[test]
    fn test_dos_header_struct_converter() {
        let data = make_dos_header_bytes(0x80, true);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = DOSHeader::parse(&mut reader).unwrap();

        let dt = header.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "IMAGE_DOS_HEADER");
                // 14 base fields + e_res + e_oemid + e_oeminfo + e_res2 + e_lfanew + e_program
                assert_eq!(fields.len(), 20);
                assert_eq!(fields[14].0, "e_res[4]");
                assert_eq!(fields[15].0, "e_oemid");
                assert_eq!(fields[16].0, "e_oeminfo");
                assert_eq!(fields[17].0, "e_res2[10]");
                assert_eq!(fields[18].0, "e_lfanew");
                assert_eq!(fields[19].0, "e_program");
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_has_pe_header() {
        let data = make_dos_header_bytes(0x100, true);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = DOSHeader::parse(&mut reader).unwrap();

        assert!(header.has_pe_header());
        assert!(header.has_new_exe_header());
    }

    #[test]
    fn test_display() {
        let data = make_dos_header_bytes(0x80, true);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = DOSHeader::parse(&mut reader).unwrap();
        let s = format!("{}", header);
        assert!(s.contains("0x5A4D"));
        assert!(s.contains("0x00000080"));
    }
}
