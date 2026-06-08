//! COFF line number ported from Ghidra's `ghidra.app.util.bin.format.coff.CoffLineNumber`.
//!
//! Each line number entry maps a source line to an address within a section.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

/// COFF line number entry.
///
/// Ported from `ghidra.app.util.bin.format.coff.CoffLineNumber`.
/// When `l_lnno` is 0, `l_addr` is a symbol table index for the function name.
/// When `l_lnno` is non-zero, `l_addr` is the code address and `l_lnno` is the
/// source line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffLineNumber {
    /// Address of line number, or function name symbol index when `l_lnno == 0`.
    l_addr: i32,
    /// Line number (0 means this entry contains a function name reference).
    l_lnno: i16,
}

impl CoffLineNumber {
    /// Size in bytes of a `CoffLineNumber` entry.
    pub const SIZEOF: usize = 4 + 2; // i32 + i16 = 6 bytes

    /// Read a line number entry from the reader at the current position.
    pub fn read(reader: &mut BinaryReader) -> io::Result<Self> {
        let l_addr = reader.read_next_i32()?;
        let l_lnno = reader.read_next_i16()?;
        Ok(Self { l_addr, l_lnno })
    }

    /// Returns the address of the line number.
    ///
    /// When `line_number() == 0`, this is actually the symbol table index
    /// of the function name (use `function_name_symbol_index()` instead).
    pub fn address(&self) -> i32 {
        self.l_addr
    }

    /// Returns the function name symbol index.
    ///
    /// Only meaningful when `line_number() == 0`.
    pub fn function_name_symbol_index(&self) -> u32 {
        self.l_addr as u32
    }

    /// Returns the line number.
    ///
    /// A value of 0 indicates this entry contains a function name reference
    /// rather than a line mapping.
    pub fn line_number(&self) -> i16 {
        self.l_lnno
    }

    /// Returns true if this entry is a function name reference (line number == 0).
    pub fn is_function_name(&self) -> bool {
        self.l_lnno == 0
    }
}

impl StructConverter for CoffLineNumber {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "CoffLineNumber".into(),
            size: Self::SIZEOF as u32,
            fields: vec![
                ("l_addr".into(), DataTypeDescription::DWord),
                ("l_lnno".into(), DataTypeDescription::Word),
            ],
        }
    }
}

impl fmt::Display for CoffLineNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_function_name() {
            write!(
                f,
                "CoffLineNumber(func_symndx=0x{:08x})",
                self.l_addr as u32
            )
        } else {
            write!(
                f,
                "CoffLineNumber(addr=0x{:08x}, line={})",
                self.l_addr as u32, self.l_lnno
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_line_number() {
        // l_addr = 0x00401000, l_lnno = 42
        let data: Vec<u8> = vec![0x00, 0x10, 0x40, 0x00, 0x2a, 0x00];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let ln = CoffLineNumber::read(&mut reader).unwrap();
        assert_eq!(ln.address(), 0x00401000);
        assert_eq!(ln.line_number(), 42);
        assert!(!ln.is_function_name());
    }

    #[test]
    fn test_read_function_name_reference() {
        // l_addr = symbol index 5, l_lnno = 0
        let data: Vec<u8> = vec![0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let ln = CoffLineNumber::read(&mut reader).unwrap();
        assert!(ln.is_function_name());
        assert_eq!(ln.function_name_symbol_index(), 5);
        assert_eq!(ln.line_number(), 0);
    }

    #[test]
    fn test_to_data_type() {
        let ln = CoffLineNumber {
            l_addr: 0x1000,
            l_lnno: 10,
        };
        let dt = ln.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, size, fields } => {
                assert_eq!(name, "CoffLineNumber");
                assert_eq!(*size, 6);
                assert_eq!(fields.len(), 2);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_display() {
        let ln = CoffLineNumber {
            l_addr: 0x1000,
            l_lnno: 10,
        };
        let s = format!("{}", ln);
        assert!(s.contains("0x00001000"));
        assert!(s.contains("10"));

        let ln_func = CoffLineNumber {
            l_addr: 3,
            l_lnno: 0,
        };
        let s = format!("{}", ln_func);
        assert!(s.contains("func_symndx"));
    }
}
