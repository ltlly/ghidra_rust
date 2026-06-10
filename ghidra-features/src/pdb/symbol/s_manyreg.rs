//! S_MANYREG -- Multiple-register variable symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ManyRegisterMSSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A multiple-register variable symbol (`S_MANYREG` / `S_MANYREG2`).
///
/// This symbol describes a variable whose value is distributed across more
/// than one CPU register. It records the type index, a count, and an array
/// of register indices, followed by the variable name.
///
/// # PDB Binary Layout (S_MANYREG2 / S_MANYREG_ST)
///
/// ```text
/// type_record : u16
/// count       : u8
/// registers   : u16[count]
/// name        : NT string
/// ```
///
/// # PDB Binary Layout (S_MANYREG -- original)
///
/// ```text
/// type_record : u32
/// count       : u8
/// registers   : u16[count]
/// name        : NT string
/// ```
///
/// This corresponds to `S_MANYREG` (0x000C), `S_MANYREG2` (0x1014), and
/// `S_MANYREG_ST` (0x1005) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SManyReg {
    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// The number of registers holding this variable.
    pub count: u8,

    /// The register indices (architecture-specific register numbers).
    pub registers: Vec<u16>,

    /// The variable name.
    pub name: String,
}

impl SManyReg {
    /// Create a new multiple-register variable symbol.
    pub fn new(
        type_record_number: RecordNumber,
        count: u8,
        registers: Vec<u16>,
        name: String,
    ) -> Self {
        Self {
            type_record_number,
            count,
            registers,
            name,
        }
    }

    /// Parse an S_MANYREG2 symbol from a byte slice (16-bit type index).
    ///
    /// Expects the layout: `type_record(u16) + count(u8) + registers(u16[count]) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 16);
        let count = data[2];
        let mut registers = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let off = 3 + i * 2;
            if off + 2 <= data.len() {
                registers.push(u16::from_le_bytes([data[off], data[off + 1]]));
            }
        }
        let name_off = 3 + count as usize * 2;
        let name = if name_off < data.len() {
            parse_nt_string(&data[name_off..])
        } else {
            String::new()
        };
        Some(Self {
            type_record_number: trn,
            count,
            registers,
            name,
        })
    }

    /// Parse an S_MANYREG symbol from a byte slice (32-bit type index).
    ///
    /// Expects the layout: `type_record(u32) + count(u8) + registers(u16[count]) + name(NT)`.
    pub fn parse_32(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let count = data[4];
        let mut registers = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let off = 5 + i * 2;
            if off + 2 <= data.len() {
                registers.push(u16::from_le_bytes([data[off], data[off + 1]]));
            }
        }
        let name_off = 5 + count as usize * 2;
        let name = if name_off < data.len() {
            parse_nt_string(&data[name_off..])
        } else {
            String::new()
        };
        Some(Self {
            type_record_number: trn,
            count,
            registers,
            name,
        })
    }
}

impl AbstractMsSymbol for SManyReg {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_MANYREG2
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_MANYREG2"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ManyRegister: Type: {}, Count: {}, Regs: {:?}, {}",
            self.type_record_number, self.count, self.registers, self.name
        )
    }
}

impl NameMsSymbol for SManyReg {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SManyReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// Parse a null-terminated UTF-8 string from a byte slice.
fn parse_nt_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_manyreg_bytes(type_index: u16, registers: &[u16], name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.push(registers.len() as u8);
        for reg in registers {
            data.extend_from_slice(&reg.to_le_bytes());
        }
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    fn make_manyreg32_bytes(type_index: u32, registers: &[u16], name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.push(registers.len() as u8);
        for reg in registers {
            data.extend_from_slice(&reg.to_le_bytes());
        }
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_manyreg_bytes(0x1020, &[17, 18], b"split_var");
        let sym = SManyReg::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.count, 2);
        assert_eq!(sym.registers, vec![17, 18]);
        assert_eq!(sym.name, "split_var");
    }

    #[test]
    fn test_parse_single_register() {
        let data = make_manyreg_bytes(0x1000, &[6], b"bp_only");
        let sym = SManyReg::parse(&data).unwrap();
        assert_eq!(sym.count, 1);
        assert_eq!(sym.registers, vec![6]);
        assert_eq!(sym.name, "bp_only");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SManyReg::parse(&data).is_none());
    }

    #[test]
    fn test_parse_no_registers() {
        let data = make_manyreg_bytes(0x1000, &[], b"empty");
        let sym = SManyReg::parse(&data).unwrap();
        assert_eq!(sym.count, 0);
        assert!(sym.registers.is_empty());
        assert_eq!(sym.name, "empty");
    }

    #[test]
    fn test_parse32_basic() {
        let data = make_manyreg32_bytes(0x1020, &[17, 18, 19], b"wide_split");
        let sym = SManyReg::parse_32(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.count, 3);
        assert_eq!(sym.registers, vec![17, 18, 19]);
        assert_eq!(sym.name, "wide_split");
    }

    #[test]
    fn test_parse32_truncated() {
        let data = [0x00, 0x01, 0x02, 0x03]; // too short for 32-bit type + count
        assert!(SManyReg::parse_32(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SManyReg::new(
            RecordNumber::type_record_number(0x1020),
            2,
            vec![17, 18],
            "split_var".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1014);
        assert_eq!(sym.symbol_type_name(), "S_MANYREG2");
        assert_eq!(sym.name(), "split_var");
        assert_eq!(sym.count, 2);
    }

    #[test]
    fn test_display() {
        let sym = SManyReg::new(
            RecordNumber::type_record_number(0x1000),
            2,
            vec![17, 18],
            "my_pair".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("ManyRegister"));
        assert!(s.contains("my_pair"));
        assert!(s.contains("17"));
        assert!(s.contains("18"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SManyReg::new(
            RecordNumber::type_record_number(0x1020),
            2,
            vec![17, 18],
            "test".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
