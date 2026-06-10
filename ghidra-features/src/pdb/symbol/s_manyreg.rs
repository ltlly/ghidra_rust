//! S_MANYREG -- Multiple-register variable symbol.
//!
//! Ports Ghidra's:
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ManyRegisterVariableMsSymbol`
//!   (S_MANYREG, 0x000C) -- u8 count, u8 register indices
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ManyRegisterVariable2MsSymbol`
//!   (S_MANYREG2, 0x1014) -- u16 count, u16 register indices
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ManyRegisterVariableStMsSymbol`
//!   (S_MANYREG_ST, 0x1005) -- u8 count, u8 register indices, ST string
//!
//! The key difference between the v1 (S_MANYREG) and v2 (S_MANYREG2) formats
//! is the width of the count and register fields.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// Which variant of the many-register symbol was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManyRegVariant {
    /// `S_MANYREG` (0x000C) -- 32-bit type index, u8 count, u8 registers, NT string.
    ManyReg,
    /// `S_MANYREG2` (0x1014) -- 16-bit type index, u16 count, u16 registers, NT string.
    ManyReg2,
    /// `S_MANYREG_ST` (0x1005) -- 32-bit type index, u8 count, u8 registers, ST string.
    ManyRegSt,
}

/// A multiple-register variable symbol (`S_MANYREG` / `S_MANYREG2` / `S_MANYREG_ST`).
///
/// This symbol describes a variable whose value is distributed across more
/// than one CPU register. It records the type index, a count, and an array
/// of register indices, followed by the variable name.
///
/// # PDB Binary Layout (S_MANYREG, 0x000C)
///
/// ```text
/// type_record : u32
/// count       : u8
/// registers   : u8[count]
/// name        : NT string
/// ```
///
/// # PDB Binary Layout (S_MANYREG2, 0x1014)
///
/// ```text
/// type_record : u16
/// count       : u16
/// registers   : u16[count]
/// name        : NT string
/// ```
///
/// # PDB Binary Layout (S_MANYREG_ST, 0x1005)
///
/// ```text
/// type_record : u32
/// count       : u8
/// registers   : u8[count]
/// name        : ST string (16-bit length prefix)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SManyReg {
    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// The number of registers holding this variable.
    pub count: u16,

    /// The register indices (architecture-specific register numbers).
    pub registers: Vec<u16>,

    /// The variable name.
    pub name: String,

    /// Which variant was parsed.
    variant: ManyRegVariant,
}

impl SManyReg {
    /// Create a new multiple-register variable symbol (S_MANYREG2 variant).
    pub fn new(
        type_record_number: RecordNumber,
        count: u16,
        registers: Vec<u16>,
        name: String,
    ) -> Self {
        Self {
            type_record_number,
            count,
            registers,
            name,
            variant: ManyRegVariant::ManyReg2,
        }
    }

    /// Parse an S_MANYREG2 symbol from a byte slice (16-bit type index, u16 count, u16 registers).
    ///
    /// Expects the layout: `type_record(u16) + count(u16) + registers(u16[count]) + name(NT)`.
    ///
    /// This handles `S_MANYREG2` (0x1014).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 16);
        let count = u16::from_le_bytes([data[2], data[3]]);
        let mut registers = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let off = 4 + i * 2;
            if off + 2 <= data.len() {
                registers.push(u16::from_le_bytes([data[off], data[off + 1]]));
            }
        }
        let name_off = 4 + count as usize * 2;
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
            variant: ManyRegVariant::ManyReg2,
        })
    }

    /// Parse an S_MANYREG symbol from a byte slice (32-bit type index, u8 count, u8 registers).
    ///
    /// Expects the layout: `type_record(u32) + count(u8) + registers(u8[count]) + name(NT)`.
    ///
    /// Per the Java `AbstractManyRegisterVariableMsSymbol`, the count is u8
    /// and each register index is a single byte (u8), not u16.
    ///
    /// This handles `S_MANYREG` (0x000C).
    pub fn parse_manyreg(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let count = data[4];
        let mut registers = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let off = 5 + i;
            if off < data.len() {
                registers.push(data[off] as u16);
            }
        }
        let name_off = 5 + count as usize;
        let name = if name_off < data.len() {
            parse_nt_string(&data[name_off..])
        } else {
            String::new()
        };
        Some(Self {
            type_record_number: trn,
            count: count as u16,
            registers,
            name,
            variant: ManyRegVariant::ManyReg,
        })
    }

    /// Parse an S_MANYREG_ST symbol from a byte slice (32-bit type index,
    /// u8 count, u8 registers, ST string).
    ///
    /// Expects the layout: `type_record(u32) + count(u8) + registers(u8[count]) + name(ST)`.
    ///
    /// This handles `S_MANYREG_ST` (0x1005).
    pub fn parse_st(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let count = data[4];
        let mut registers = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let off = 5 + i;
            if off < data.len() {
                registers.push(data[off] as u16);
            }
        }
        let name_off = 5 + count as usize;
        let name = if name_off < data.len() {
            parse_st_string(&data[name_off..])
        } else {
            String::new()
        };
        Some(Self {
            type_record_number: trn,
            count: count as u16,
            registers,
            name,
            variant: ManyRegVariant::ManyRegSt,
        })
    }

    /// Return the variant of this many-register symbol.
    pub fn variant(&self) -> ManyRegVariant {
        self.variant
    }
}

impl AbstractMsSymbol for SManyReg {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            ManyRegVariant::ManyReg => super::super::symbol_kind::S_MANYREG,
            ManyRegVariant::ManyReg2 => super::super::symbol_kind::S_MANYREG2,
            ManyRegVariant::ManyRegSt => super::super::symbol_kind::S_MANYREG_ST,
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            ManyRegVariant::ManyReg => "S_MANYREG",
            ManyRegVariant::ManyReg2 => "S_MANYREG2",
            ManyRegVariant::ManyRegSt => "S_MANYREG_ST",
        }
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

/// Parse an ST-format UTF-8 string (16-bit length prefix followed by that
/// many bytes of UTF-8 data).
fn parse_st_string(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let end = 2 + len;
    if end > data.len() {
        return String::from_utf8_lossy(&data[2..]).to_string();
    }
    String::from_utf8_lossy(&data[2..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_manyreg2_bytes(type_index: u16, registers: &[u16], name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.extend_from_slice(&(registers.len() as u16).to_le_bytes());
        for reg in registers {
            data.extend_from_slice(&reg.to_le_bytes());
        }
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    fn make_manyreg_bytes(type_index: u32, registers: &[u8], name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.push(registers.len() as u8);
        for reg in registers {
            data.push(*reg);
        }
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    fn make_manyreg_st_bytes(type_index: u32, registers: &[u8], name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.push(registers.len() as u8);
        for reg in registers {
            data.push(*reg);
        }
        // ST string: 16-bit length prefix + raw bytes
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);
        data
    }

    // ---- S_MANYREG2 tests ----

    #[test]
    fn test_parse_basic() {
        let data = make_manyreg2_bytes(0x1020, &[17, 18], b"split_var");
        let sym = SManyReg::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.count, 2);
        assert_eq!(sym.registers, vec![17, 18]);
        assert_eq!(sym.name, "split_var");
        assert_eq!(sym.variant, ManyRegVariant::ManyReg2);
    }

    #[test]
    fn test_parse_single_register() {
        let data = make_manyreg2_bytes(0x1000, &[6], b"bp_only");
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
        let data = make_manyreg2_bytes(0x1000, &[], b"empty");
        let sym = SManyReg::parse(&data).unwrap();
        assert_eq!(sym.count, 0);
        assert!(sym.registers.is_empty());
        assert_eq!(sym.name, "empty");
    }

    // ---- S_MANYREG tests (u8 registers) ----

    #[test]
    fn test_parse_manyreg_basic() {
        let data = make_manyreg_bytes(0x1020, &[17, 18], b"split_var");
        let sym = SManyReg::parse_manyreg(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.count, 2);
        assert_eq!(sym.registers, vec![17, 18]);
        assert_eq!(sym.name, "split_var");
        assert_eq!(sym.variant, ManyRegVariant::ManyReg);
        assert_eq!(sym.pdb_id(), 0x000C);
    }

    #[test]
    fn test_parse_manyreg_truncated() {
        let data = [0x00, 0x01, 0x02, 0x03]; // too short for 32-bit type + count
        assert!(SManyReg::parse_manyreg(&data).is_none());
    }

    #[test]
    fn test_parse_manyreg_no_registers() {
        let data = make_manyreg_bytes(0x1000, &[], b"empty");
        let sym = SManyReg::parse_manyreg(&data).unwrap();
        assert_eq!(sym.count, 0);
        assert!(sym.registers.is_empty());
        assert_eq!(sym.name, "empty");
    }

    #[test]
    fn test_parse_manyreg_u8_range() {
        // S_MANYREG registers are u8, so max value is 255
        let data = make_manyreg_bytes(0x1000, &[0xFF], b"max_reg");
        let sym = SManyReg::parse_manyreg(&data).unwrap();
        assert_eq!(sym.registers, vec![0xFF]);
    }

    // ---- S_MANYREG_ST tests ----

    #[test]
    fn test_parse_st_basic() {
        let data = make_manyreg_st_bytes(0x1020, &[17, 18], b"st_split");
        let sym = SManyReg::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.count, 2);
        assert_eq!(sym.registers, vec![17, 18]);
        assert_eq!(sym.name, "st_split");
        assert_eq!(sym.variant, ManyRegVariant::ManyRegSt);
        assert_eq!(sym.pdb_id(), 0x1005);
    }

    #[test]
    fn test_parse_st_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SManyReg::parse_st(&data).is_none());
    }

    #[test]
    fn test_parse_st_empty_name() {
        let data = make_manyreg_st_bytes(0x1000, &[6], b"");
        let sym = SManyReg::parse_st(&data).unwrap();
        assert_eq!(sym.registers, vec![6]);
        assert_eq!(sym.name, "");
    }

    // ---- Trait implementation tests ----

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

    #[test]
    fn test_variant_consistency() {
        // S_MANYREG2
        let data = make_manyreg2_bytes(0x1000, &[17], b"a");
        let sym = SManyReg::parse(&data).unwrap();
        assert_eq!(sym.variant(), ManyRegVariant::ManyReg2);
        assert_eq!(sym.symbol_type_name(), "S_MANYREG2");

        // S_MANYREG
        let data = make_manyreg_bytes(0x1000, &[17], b"b");
        let sym = SManyReg::parse_manyreg(&data).unwrap();
        assert_eq!(sym.variant(), ManyRegVariant::ManyReg);
        assert_eq!(sym.symbol_type_name(), "S_MANYREG");

        // S_MANYREG_ST
        let data = make_manyreg_st_bytes(0x1000, &[17], b"c");
        let sym = SManyReg::parse_st(&data).unwrap();
        assert_eq!(sym.variant(), ManyRegVariant::ManyRegSt);
        assert_eq!(sym.symbol_type_name(), "S_MANYREG_ST");
    }
}
