//! COFF symbol entry ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.CoffSymbol`.
//!
//! Each symbol in the COFF symbol table has a name, value, section number,
//! type, storage class, and optional auxiliary entries.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::coff_constants;
use super::coff_exception::CoffException;
use super::coff_file_header::CoffFileHeader;
use super::coff_symbol_storage_class as sc;
use super::coff_symbol_type as st;
use super::coff_symbol_section_number as sn;

/// COFF symbol table entry.
///
/// Ported from `ghidra.app.util.bin.format.coff.CoffSymbol`.
/// Represents a single symbol from the COFF symbol table.
#[derive(Debug, Clone)]
pub struct CoffSymbol {
    /// Symbol name (up to 8 characters, or looked up from string table).
    e_name: String,
    /// Value of the symbol (address or offset).
    e_value: i32,
    /// Section number (1-based, or a special N_* constant).
    e_scnum: i16,
    /// Symbol type (base type in low nibble, derived type above).
    e_type: i16,
    /// Storage class.
    e_sclass: u8,
    /// Number of auxiliary entries following this symbol.
    e_numaux: u8,
    /// Auxiliary symbols data (raw bytes, one entry per `e_numaux`).
    aux_data: Vec<Vec<u8>>,
}

impl CoffSymbol {
    /// Size of a single auxiliary symbol entry.
    pub const AUX_ENTRY_SIZE: usize = 18;

    /// Parse a symbol from the reader.
    ///
    /// If the first 4 bytes of the name field are zero, the name is resolved
    /// from the string table. The auxiliary entries are stored as raw byte
    /// vectors (each 18 bytes) for deferred parsing by the caller.
    pub fn read(reader: &mut BinaryReader, header: &CoffFileHeader) -> Result<Self, CoffException> {
        let e_name = Self::read_name(reader, header)?;
        let e_value = reader.read_next_i32().map_err(CoffException::from)?;
        let e_scnum = reader.read_next_i16().map_err(CoffException::from)?;
        let e_type = reader.read_next_i16().map_err(CoffException::from)?;
        let e_sclass = reader.read_next_u8().map_err(CoffException::from)?;
        let e_numaux = reader.read_next_u8().map_err(CoffException::from)?;

        let mut aux_data = Vec::with_capacity(e_numaux as usize);
        for _ in 0..e_numaux {
            let mut entry = vec![0u8; Self::AUX_ENTRY_SIZE];
            reader
                .read_exact_bytes(&mut entry)
                .map_err(CoffException::from)?;
            aux_data.push(entry);
        }

        Ok(Self {
            e_name,
            e_value,
            e_scnum,
            e_type,
            e_sclass,
            e_numaux,
            aux_data,
        })
    }

    /// Read the symbol name from the 8-byte name field.
    fn read_name(
        reader: &mut BinaryReader,
        header: &CoffFileHeader,
    ) -> Result<String, CoffException> {
        let peek = reader.peek_i32();
        if peek == 0 {
            // First 4 bytes are zero -- lookup in string table
            reader.advance(4);
            let name_index = reader.read_next_i32().map_err(CoffException::from)? as u64;
            let string_table_offset =
                header.f_symptr as u64 + (header.f_nsyms as u64 * coff_constants::SYMBOL_SIZEOF as u64);
            let abs_offset = string_table_offset + name_index;
            reader
                .read_cstring_at(abs_offset)
                .map_err(CoffException::from)
        } else {
            let bytes = reader
                .read_bytes_at(reader.cursor(), coff_constants::SYMBOL_NAME_LENGTH)
                .map_err(CoffException::from)?;
            reader.advance(coff_constants::SYMBOL_NAME_LENGTH as u64);
            Ok(trim_ascii(&bytes))
        }
    }

    // --- Accessors ---

    /// Returns the symbol name.
    pub fn name(&self) -> &str {
        &self.e_name
    }

    /// Returns the value of the symbol (as unsigned).
    pub fn value(&self) -> u32 {
        self.e_value as u32
    }

    /// Adds an offset to the value.
    ///
    /// This must be performed before relocations in order to achieve the proper result.
    pub fn move_by(&mut self, offset: i32) {
        self.e_value += offset;
    }

    /// Returns the section number.
    pub fn section_number(&self) -> i16 {
        self.e_scnum
    }

    /// Returns the basic (base) type of the symbol.
    pub fn basic_type(&self) -> i16 {
        st::get_base_type(self.e_type)
    }

    /// Returns a derived type at the given index (1-6).
    ///
    /// # Panics
    /// Panics if `derived_index` is not in the range 1..=6.
    pub fn derived_type(&self, derived_index: i32) -> i16 {
        if derived_index < 1 || derived_index > 6 {
            panic!("derived_index must be in 1..=6, got {}", derived_index);
        }
        let mut derived = (self.e_type as i32 & 0xffff) >> 4;
        if derived_index > 1 {
            derived >>= derived_index * 2;
        }
        (derived & 0x3) as i16
    }

    /// Returns the storage class.
    pub fn storage_class(&self) -> u8 {
        self.e_sclass
    }

    /// Returns the number of auxiliary entries.
    pub fn auxiliary_count(&self) -> u8 {
        self.e_numaux
    }

    /// Returns the raw auxiliary entry data.
    pub fn auxiliary_data(&self) -> &[Vec<u8>] {
        &self.aux_data
    }

    /// Returns the symbol type field as a raw i16.
    pub fn raw_type(&self) -> i16 {
        self.e_type
    }

    /// Returns true if this symbol represents a section.
    ///
    /// A section symbol has type T_NULL, value 0, storage class C_STAT,
    /// and at least one auxiliary entry.
    pub fn is_section(&self) -> bool {
        self.e_type == st::T_NULL
            && self.e_value == 0
            && self.e_sclass == sc::C_STAT
            && !self.aux_data.is_empty()
    }

    /// Returns true if this symbol is an external (public) symbol.
    pub fn is_external(&self) -> bool {
        sc::is_external(self.e_sclass)
    }

    /// Returns true if this symbol is a debug symbol.
    pub fn is_debug(&self) -> bool {
        sc::is_debug(self.e_sclass)
    }

    /// Returns true if this symbol references a special section (N_DEBUG, N_ABS, N_UNDEF).
    pub fn is_special_section(&self) -> bool {
        sn::is_special_section(self.e_scnum)
    }

    /// Returns the storage class name, if known.
    pub fn storage_class_name(&self) -> Option<&'static str> {
        sc::storage_class_name(self.e_sclass)
    }
}

impl StructConverter for CoffSymbol {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "CoffSymbol".into(),
            size: coff_constants::SYMBOL_SIZEOF as u32,
            fields: vec![
                (
                    "e_name".into(),
                    DataTypeDescription::Array {
                        element: Box::new(DataTypeDescription::Ascii),
                        count: coff_constants::SYMBOL_NAME_LENGTH,
                    },
                ),
                ("e_value".into(), DataTypeDescription::DWord),
                ("e_scnum".into(), DataTypeDescription::Word),
                ("e_type".into(), DataTypeDescription::Word),
                ("e_sclass".into(), DataTypeDescription::Byte),
                ("e_numaux".into(), DataTypeDescription::Byte),
            ],
        }
    }
}

impl fmt::Display for CoffSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} Value=0x{:08x} Section={} Type=0x{:04x} Class=0x{:02x}",
            self.e_name,
            self.e_value as u32,
            self.e_scnum,
            self.e_type as u16,
            self.e_sclass
        )
    }
}

/// Trim trailing ASCII whitespace/NUL bytes from a byte slice.
fn trim_ascii(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0 && !b.is_ascii_whitespace())
        .map(|p| p + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_symbol_bytes(name: &[u8; 8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(name);
        // e_value = 0x1000
        data.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
        // e_scnum = 1 (.text)
        data.extend_from_slice(&[0x01, 0x00]);
        // e_type = T_INT
        data.extend_from_slice(&[0x04, 0x00]);
        // e_sclass = C_EXT
        data.extend_from_slice(&[sc::C_EXT]);
        // e_numaux = 0
        data.extend_from_slice(&[0x00]);
        data
    }

    #[test]
    fn test_read_symbol() {
        let name: [u8; 8] = *b"main\0\0\0\0";
        let data = make_symbol_bytes(&name);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let sym = CoffSymbol::read(&mut reader, &header).unwrap();
        assert_eq!(sym.name(), "main");
        assert_eq!(sym.value(), 0x1000);
        assert_eq!(sym.section_number(), 1);
        assert_eq!(sym.basic_type(), st::T_INT);
        assert_eq!(sym.storage_class(), sc::C_EXT);
        assert_eq!(sym.auxiliary_count(), 0);
        assert!(sym.is_external());
        assert!(!sym.is_section());
        assert!(!sym.is_debug());
    }

    #[test]
    fn test_symbol_with_auxiliary() {
        let name: [u8; 8] = *b".text\0\0\0";
        let mut data = Vec::new();
        data.extend_from_slice(&name);
        // e_value = 0
        data.extend_from_slice(&[0u8; 4]);
        // e_scnum = 1
        data.extend_from_slice(&[0x01, 0x00]);
        // e_type = T_NULL
        data.extend_from_slice(&[0x00, 0x00]);
        // e_sclass = C_STAT
        data.extend_from_slice(&[sc::C_STAT]);
        // e_numaux = 1
        data.extend_from_slice(&[0x01]);
        // Auxiliary entry (18 bytes of zeros)
        data.extend_from_slice(&[0u8; 18]);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let sym = CoffSymbol::read(&mut reader, &header).unwrap();
        assert_eq!(sym.name(), ".text");
        assert_eq!(sym.auxiliary_count(), 1);
        assert_eq!(sym.auxiliary_data().len(), 1);
        assert_eq!(sym.auxiliary_data()[0].len(), 18);
        assert!(sym.is_section());
    }

    #[test]
    fn test_basic_type_and_derived_type() {
        // A pointer to int: DT_PTR << 4 | T_INT
        let type_val: i16 = (st::DT_PTR << 4) | st::T_INT;
        let name: [u8; 8] = *b"ptr_int\0";
        let mut data = make_symbol_bytes(&name);
        // Override e_type at offset 14..16
        data[14] = (type_val & 0xff) as u8;
        data[15] = ((type_val >> 8) & 0xff) as u8;

        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let sym = CoffSymbol::read(&mut reader, &header).unwrap();
        assert_eq!(sym.basic_type(), st::T_INT);
        assert_eq!(sym.derived_type(1), st::DT_PTR);
    }

    #[test]
    fn test_to_data_type() {
        let name: [u8; 8] = *b"main\0\0\0\0";
        let data = make_symbol_bytes(&name);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let sym = CoffSymbol::read(&mut reader, &header).unwrap();
        let dt = sym.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, size, fields } => {
                assert_eq!(name, "CoffSymbol");
                assert_eq!(*size, 18);
                assert_eq!(fields.len(), 6);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_display() {
        let name: [u8; 8] = *b"main\0\0\0\0";
        let data = make_symbol_bytes(&name);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let sym = CoffSymbol::read(&mut reader, &header).unwrap();
        let s = format!("{}", sym);
        assert!(s.contains("main"));
        assert!(s.contains("0x00001000"));
        assert!(s.contains("Section=1"));
    }

    #[test]
    fn test_is_special_section() {
        let name: [u8; 8] = *b"debug\0\0\0";
        let mut data = make_symbol_bytes(&name);
        // Set e_scnum = N_DEBUG (-2)
        data[12] = 0xFE; // -2 as i16 LE
        data[13] = 0xFF;

        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let sym = CoffSymbol::read(&mut reader, &header).unwrap();
        assert_eq!(sym.section_number(), sn::N_DEBUG);
        assert!(sym.is_special_section());
    }
}
