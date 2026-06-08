//! COFF relocation entry ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.CoffRelocation`.
//!
//! Each relocation entry describes how a reference to a symbol should be patched
//! when the section is loaded or linked.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::coff_machine_type;

/// COFF relocation entry.
///
/// Ported from `ghidra.app.util.bin.format.coff.CoffRelocation`.
/// Describes a single relocation that must be applied to a section's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffRelocation {
    /// Address of the relocation within the section.
    r_vaddr: i32,
    /// Symbol table index of the symbol being relocated to.
    r_symndx: i32,
    /// Extended address (COFF2 only). For COFF1 files this is 0.
    r_exa: i16,
    /// Relocation type.
    r_type: i16,
    /// The COFF magic number used to determine struct layout.
    magic: u16,
}

impl CoffRelocation {
    /// Size for standard COFF (non-TI).
    const SIZEOF: usize = 4 + 4 + 2; // 10 bytes
    /// Size for TI COFF (which includes the extended address field).
    const SIZEOF_TI: usize = 4 + 4 + 2 + 2; // 12 bytes

    /// Read a relocation entry from the reader at the current position.
    ///
    /// The `magic` value from the COFF file header determines whether the
    /// extended address field is present (TI COFF Level 1/2).
    pub fn read(reader: &mut BinaryReader, magic: u16) -> io::Result<Self> {
        let r_vaddr = reader.read_next_i32()?;
        let r_symndx = reader.read_next_i32()?;

        let r_exa = if magic == coff_machine_type::TICOFF2MAGIC {
            reader.read_next_i16()?
        } else {
            0
        };

        let r_type = reader.read_next_i16()?;

        Ok(Self {
            r_vaddr,
            r_symndx,
            r_exa,
            r_type,
            magic,
        })
    }

    /// Returns the size in bytes of this relocation entry.
    pub fn sizeof(&self) -> usize {
        if self.magic == coff_machine_type::TICOFF2MAGIC
            || self.magic == coff_machine_type::TICOFF1MAGIC
        {
            Self::SIZEOF_TI
        } else {
            Self::SIZEOF
        }
    }

    /// Returns the address where the relocation should be performed.
    pub fn address(&self) -> i32 {
        self.r_vaddr
    }

    /// Returns the symbol table index of the symbol being relocated to.
    pub fn symbol_index(&self) -> i32 {
        self.r_symndx
    }

    /// Returns the extended address value.
    ///
    /// This is only meaningful for COFF2 files (TI COFF Level 2).
    pub fn extended_address(&self) -> i16 {
        self.r_exa
    }

    /// Returns the relocation type.
    pub fn relocation_type(&self) -> i16 {
        self.r_type
    }
}

impl StructConverter for CoffRelocation {
    fn to_data_type(&self) -> DataTypeDescription {
        let mut fields = vec![
            ("r_vaddr".into(), DataTypeDescription::DWord),
            ("r_symndx".into(), DataTypeDescription::DWord),
        ];
        if self.magic == coff_machine_type::TICOFF2MAGIC
            || self.magic == coff_machine_type::TICOFF1MAGIC
        {
            fields.push(("r_exa".into(), DataTypeDescription::Word));
        }
        fields.push(("r_type".into(), DataTypeDescription::Word));

        DataTypeDescription::Struct {
            name: "CoffRelocation".into(),
            size: self.sizeof() as u32,
            fields,
        }
    }
}

impl fmt::Display for CoffRelocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoffRelocation(addr=0x{:08x}, symndx={}, type=0x{:04x})",
            self.r_vaddr as u32, self.r_symndx, self.r_type as u16
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reloc_data_ticoff2() -> Vec<u8> {
        // r_vaddr=0x100, r_symndx=3, r_exa=1, r_type=0x14
        vec![
            0x00, 0x01, 0x00, 0x00, // r_vaddr = 0x100
            0x03, 0x00, 0x00, 0x00, // r_symndx = 3
            0x01, 0x00, // r_exa = 1
            0x14, 0x00, // r_type = 0x14
        ]
    }

    fn make_reloc_data_standard() -> Vec<u8> {
        // r_vaddr=0x200, r_symndx=7, r_type=0x06 (standard COFF)
        vec![
            0x00, 0x02, 0x00, 0x00, // r_vaddr = 0x200
            0x07, 0x00, 0x00, 0x00, // r_symndx = 7
            0x06, 0x00, // r_type = 0x06
        ]
    }

    #[test]
    fn test_read_ticoff2() {
        let data = make_reloc_data_ticoff2();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let reloc = CoffRelocation::read(&mut reader, coff_machine_type::TICOFF2MAGIC).unwrap();
        assert_eq!(reloc.address(), 0x100);
        assert_eq!(reloc.symbol_index(), 3);
        assert_eq!(reloc.extended_address(), 1);
        assert_eq!(reloc.relocation_type(), 0x14);
        assert_eq!(reloc.sizeof(), 12);
    }

    #[test]
    fn test_read_standard() {
        let data = make_reloc_data_standard();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let reloc = CoffRelocation::read(&mut reader, 0x014c).unwrap();
        assert_eq!(reloc.address(), 0x200);
        assert_eq!(reloc.symbol_index(), 7);
        assert_eq!(reloc.extended_address(), 0); // not read for standard COFF
        assert_eq!(reloc.relocation_type(), 0x06);
        assert_eq!(reloc.sizeof(), 10);
    }

    #[test]
    fn test_to_data_type_standard() {
        let data = make_reloc_data_standard();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let reloc = CoffRelocation::read(&mut reader, 0x014c).unwrap();
        let dt = reloc.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "CoffRelocation");
                assert_eq!(fields.len(), 3); // r_vaddr, r_symndx, r_type (no r_exa)
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_to_data_type_ticoff2() {
        let data = make_reloc_data_ticoff2();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let reloc = CoffRelocation::read(&mut reader, coff_machine_type::TICOFF2MAGIC).unwrap();
        let dt = reloc.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "CoffRelocation");
                assert_eq!(fields.len(), 4); // r_vaddr, r_symndx, r_exa, r_type
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_display() {
        let data = make_reloc_data_standard();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let reloc = CoffRelocation::read(&mut reader, 0x014c).unwrap();
        let s = format!("{}", reloc);
        assert!(s.contains("0x00000200"));
        assert!(s.contains("symndx=7"));
    }
}
