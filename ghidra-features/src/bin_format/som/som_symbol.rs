//! SOM symbol_dictionary_record structure ported from Ghidra's `SomSymbol.java`.
//!
//! Represents a SOM `symbol_dictionary_record` structure.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_constants::{symbol_scope_name, symbol_type_name};
use super::som_exception::SomException;

/// The size in bytes of a `SomSymbol`.
pub const SOM_SYMBOL_SIZE: usize = 0x14;

/// Represents a SOM `symbol_dictionary_record` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomSymbol`.
#[derive(Debug, Clone)]
pub struct SomSymbol {
    /// Whether the symbol is hidden from the loader for resolving external references.
    pub hidden: bool,
    /// Whether the symbol is a secondary definition.
    pub secondary_def: bool,
    /// The symbol type (see `SomConstants::SYMBOL_*`).
    pub symbol_type: u8,
    /// The symbol scope (see `SomConstants::SYMBOL_SCOPE_*`).
    pub symbol_scope: u8,
    /// Check level (3 bits).
    pub check_level: u8,
    /// Whether the qualifier name must be used to fully qualify the symbol.
    pub must_qualify: bool,
    /// Whether the code importing/exporting this symbol is locked in memory during OS boot.
    pub initially_frozen: bool,
    /// Whether the code importing/exporting this symbol is frozen in memory.
    pub memory_resident: bool,
    /// Whether this symbol is an initialized common data block.
    pub is_common: bool,
    /// Whether this symbol name may conflict with another symbol of the same name.
    pub dup_common: bool,
    /// Execution level required to call this entry point (2 bits).
    pub xleast: u8,
    /// Location of the first four words of the parameter list and return value.
    pub arg_reloc: u16,
    /// The symbol name (read from the symbol strings area).
    pub name: String,
    /// The symbol qualifier name (read from the symbol strings area).
    pub qualifier_name: String,
    /// Whether the called entry point will have a long return sequence.
    pub has_long_return: bool,
    /// Whether the called entry point will not require any parameter relocation.
    pub no_relocation: bool,
    /// Whether this symbol identifies as the key symbol for a set of COMDAT subspaces.
    pub is_comdat: bool,
    /// Reserved value (5 bits).
    pub reserved: u8,
    /// Symbol info (24 bits).
    pub symbol_info: u32,
    /// The symbol value (address).
    pub symbol_value: u32,
}

impl SomSymbol {
    /// Parse a `SomSymbol` from a binary reader at the current position.
    ///
    /// # Arguments
    /// * `reader` - A binary reader positioned at the start of the record.
    /// * `symbol_strings_location` - The starting index of the symbol strings in the file.
    ///
    /// # Errors
    ///
    /// Returns `SomException` if an I/O error occurs.
    pub fn parse(
        reader: &mut BinaryReader,
        symbol_strings_location: u64,
    ) -> Result<Self, SomException> {
        let bitfield = reader.read_next_i32().map_err(SomException::from)?;
        let arg_reloc = (bitfield & 0x3ff) as u16;
        let xleast = ((bitfield >> 10) & 0x3) as u8;
        let dup_common = ((bitfield >> 12) & 0x1) != 0;
        let is_common = ((bitfield >> 13) & 0x1) != 0;
        let memory_resident = ((bitfield >> 14) & 0x1) != 0;
        let initially_frozen = ((bitfield >> 15) & 0x1) != 0;
        let must_qualify = ((bitfield >> 16) & 0x1) != 0;
        let check_level = ((bitfield >> 17) & 0x7) as u8;
        let symbol_scope = ((bitfield >> 20) & 0xf) as u8;
        let symbol_type = ((bitfield >> 24) & 0x3f) as u8;
        let secondary_def = ((bitfield >> 30) & 0x1) != 0;
        let hidden = ((bitfield >> 31) & 0x1) != 0;

        let name_offset = reader.read_next_u32().map_err(SomException::from)? as u64;
        let name = reader.read_cstring_at(symbol_strings_location + name_offset)?;

        let qualifier_offset = reader.read_next_u32().map_err(SomException::from)? as u64;
        let qualifier_name = reader.read_cstring_at(symbol_strings_location + qualifier_offset)?;

        let bitfield2 = reader.read_next_i32().map_err(SomException::from)?;
        let symbol_info = (bitfield2 & 0xffffff) as u32;
        let reserved = ((bitfield2 >> 24) & 0x1f) as u8;
        let is_comdat = ((bitfield2 >> 29) & 0x1) != 0;
        let no_relocation = ((bitfield2 >> 30) & 0x1) != 0;
        let has_long_return = ((bitfield2 >> 31) & 0x1) != 0;

        let symbol_value = reader.read_next_u32().map_err(SomException::from)?;

        Ok(Self {
            hidden,
            secondary_def,
            symbol_type,
            symbol_scope,
            check_level,
            must_qualify,
            initially_frozen,
            memory_resident,
            is_common,
            dup_common,
            xleast,
            arg_reloc,
            name,
            qualifier_name,
            has_long_return,
            no_relocation,
            is_comdat,
            reserved,
            symbol_info,
            symbol_value,
        })
    }

    /// Returns the type name of this symbol.
    pub fn type_name(&self) -> &'static str {
        symbol_type_name(self.symbol_type)
    }

    /// Returns the scope name of this symbol.
    pub fn scope_name(&self) -> &'static str {
        symbol_scope_name(self.symbol_scope)
    }
}

impl StructConverter for SomSymbol {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "symbol_dictionary_record".to_string(),
            size: SOM_SYMBOL_SIZE as u32,
            fields: vec![
                ("bitfield1".into(), DataTypeDescription::DWord),
                ("name".into(), DataTypeDescription::DWord),
                ("qualifier_name".into(), DataTypeDescription::DWord),
                ("bitfield2".into(), DataTypeDescription::DWord),
                ("symbol_value".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomSymbol {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        let mut bitfield: u32 = self.arg_reloc as u32 & 0x3ff;
        bitfield |= (self.xleast as u32 & 0x3) << 10;
        if self.dup_common {
            bitfield |= 1 << 12;
        }
        if self.is_common {
            bitfield |= 1 << 13;
        }
        if self.memory_resident {
            bitfield |= 1 << 14;
        }
        if self.initially_frozen {
            bitfield |= 1 << 15;
        }
        if self.must_qualify {
            bitfield |= 1 << 16;
        }
        bitfield |= (self.check_level as u32 & 0x7) << 17;
        bitfield |= (self.symbol_scope as u32 & 0xf) << 20;
        bitfield |= (self.symbol_type as u32 & 0x3f) << 24;
        if self.secondary_def {
            bitfield |= 1 << 30;
        }
        if self.hidden {
            bitfield |= 1 << 31;
        }
        writer.write_u32(bitfield);

        // Write name/qualifier offsets as 0 (caller must resolve string table)
        writer.write_u32(0);
        writer.write_u32(0);

        let mut bitfield2: u32 = self.symbol_info & 0xffffff;
        bitfield |= (self.reserved as u32 & 0x1f) << 24;
        if self.is_comdat {
            bitfield2 |= 1 << 29;
        }
        if self.no_relocation {
            bitfield2 |= 1 << 30;
        }
        if self.has_long_return {
            bitfield2 |= 1 << 31;
        }
        writer.write_u32(bitfield2);

        writer.write_u32(self.symbol_value);
        Ok(())
    }
}

impl fmt::Display for SomSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "name={}, type={}, scope={}, value=0x{:x}",
            self.name, self.symbol_type, self.symbol_scope, self.symbol_value
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_symbol_data(
        bitfield1: u32,
        name_offset: u32,
        qualifier_offset: u32,
        bitfield2: u32,
        symbol_value: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&bitfield1.to_le_bytes());
        data.extend_from_slice(&name_offset.to_le_bytes());
        data.extend_from_slice(&qualifier_offset.to_le_bytes());
        data.extend_from_slice(&bitfield2.to_le_bytes());
        data.extend_from_slice(&symbol_value.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_symbol_basic() {
        let mut buf = vec![0u8; 0x300];
        let name = b"main\0";
        let qual = b"\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0x200..0x200 + qual.len()].copy_from_slice(qual);

        // symbol_type = 3 (CODE) at bits 24-29
        // symbol_scope = 1 (EXTERNAL) at bits 20-23
        let bitfield1: u32 = (3 << 24) | (1 << 20);
        let sym_data = make_symbol_data(bitfield1, 0x100, 0x200, 0, 0x4000);
        buf[0..sym_data.len()].copy_from_slice(&sym_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let symbol = SomSymbol::parse(&mut reader, 0).unwrap();

        assert_eq!(symbol.name, "main");
        assert_eq!(symbol.symbol_type, 3);
        assert_eq!(symbol.symbol_scope, 1);
        assert_eq!(symbol.symbol_value, 0x4000);
        assert_eq!(symbol.type_name(), "Code");
        assert_eq!(symbol.scope_name(), "External");
    }

    #[test]
    fn test_parse_symbol_with_flags() {
        let mut buf = vec![0u8; 0x300];
        let name = b"sym\0";
        let qual = b"qual\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0x200..0x200 + qual.len()].copy_from_slice(qual);

        // Set hidden (bit 31), secondary_def (bit 30)
        let bitfield1: u32 = (1 << 31) | (1 << 30);
        // Set has_long_return (bit 31 of bitfield2), no_relocation (bit 30), is_comdat (bit 29)
        let bitfield2: u32 = (1 << 31) | (1 << 30) | (1 << 29);
        let sym_data = make_symbol_data(bitfield1, 0x100, 0x200, bitfield2, 0x8000);
        buf[0..sym_data.len()].copy_from_slice(&sym_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let symbol = SomSymbol::parse(&mut reader, 0).unwrap();

        assert!(symbol.hidden);
        assert!(symbol.secondary_def);
        assert!(symbol.has_long_return);
        assert!(symbol.no_relocation);
        assert!(symbol.is_comdat);
    }

    #[test]
    fn test_parse_symbol_with_arg_reloc() {
        let mut buf = vec![0u8; 0x300];
        let name = b"f\0";
        let qual = b"\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0x200..0x200 + qual.len()].copy_from_slice(qual);

        // arg_reloc = 0x3FF (10 bits all set), xleast = 3
        let bitfield1: u32 = 0x3FF | (3 << 10);
        let sym_data = make_symbol_data(bitfield1, 0x100, 0x200, 0, 0);
        buf[0..sym_data.len()].copy_from_slice(&sym_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let symbol = SomSymbol::parse(&mut reader, 0).unwrap();

        assert_eq!(symbol.arg_reloc, 0x3FF);
        assert_eq!(symbol.xleast, 3);
    }

    #[test]
    fn test_symbol_struct_converter() {
        let mut buf = vec![0u8; 0x300];
        let name = b"s\0";
        let qual = b"\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0x200..0x200 + qual.len()].copy_from_slice(qual);

        let sym_data = make_symbol_data(0, 0x100, 0x200, 0, 0);
        buf[0..sym_data.len()].copy_from_slice(&sym_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let symbol = SomSymbol::parse(&mut reader, 0).unwrap();

        let dt = symbol.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "symbol_dictionary_record");
                assert_eq!(fields.len(), 5);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_symbol_display() {
        let mut buf = vec![0u8; 0x300];
        let name = b"main\0";
        let qual = b"\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0x200..0x200 + qual.len()].copy_from_slice(qual);

        let bitfield1: u32 = (3 << 24) | (1 << 20);
        let sym_data = make_symbol_data(bitfield1, 0x100, 0x200, 0, 0x4000);
        buf[0..sym_data.len()].copy_from_slice(&sym_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let symbol = SomSymbol::parse(&mut reader, 0).unwrap();

        let s = format!("{}", symbol);
        assert!(s.contains("name=main"));
        assert!(s.contains("type=3"));
        assert!(s.contains("scope=1"));
        assert!(s.contains("value=0x4000"));
    }

    #[test]
    fn test_symbol_truncated() {
        let data = vec![0u8; 10]; // too short
        let mut reader = BinaryReader::from_bytes(&data, true);
        let result = SomSymbol::parse(&mut reader, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_symbol_size() {
        assert_eq!(SOM_SYMBOL_SIZE, 0x14);
    }
}
