//! S_LABEL32 -- Label symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_Label32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// A label symbol (`S_LABEL32`).
///
/// This symbol represents a code label (an address within a procedure or at
/// global scope) that has a name. Labels are used to mark targets of goto
/// statements and other jump targets.
///
/// # PDB Binary Layout (32-bit)
///
/// ```text
/// offset : u32
/// segment: u16
/// flags  : u8
/// name   : NT string
/// ```
///
/// This corresponds to `S_LABEL32` (0x0209) and `S_LABEL16` (0x0109) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLabel32 {
    /// Offset of the label within the segment.
    pub offset: u64,

    /// The PE section/segment containing this label.
    pub segment: u16,

    /// Label flags (e.g., whether the label is a procedure-local label).
    pub flags: u8,

    /// The label name.
    pub name: String,
}

impl SLabel32 {
    /// Create a new label symbol.
    pub fn new(offset: u64, segment: u16, flags: u8, name: String) -> Self {
        Self {
            offset,
            segment,
            flags,
            name,
        }
    }

    /// Parse an S_LABEL32 symbol from a byte slice.
    ///
    /// Expects the layout: `offset(u32) + segment(u16) + flags(u8) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let segment = u16::from_le_bytes([data[4], data[5]]);
        let flags = data[6];
        let name = parse_nt_string(&data[7..]);
        Some(Self {
            offset,
            segment,
            flags,
            name,
        })
    }
}

impl AbstractMsSymbol for SLabel32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_LABEL32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_LABEL32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Label: [{:04X}:{:08X}], Flags: 0x{:02X}, {}",
            self.segment, self.offset, self.flags, self.name
        )
    }
}

impl AddressMsSymbol for SLabel32 {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SLabel32 {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SLabel32 {
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

    fn make_label32_bytes(offset: u32, segment: u16, flags: u8, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.push(flags);
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_label32_bytes(0x2000, 1, 0, b"loop_top");
        let sym = SLabel32::parse(&data).unwrap();
        assert_eq!(sym.offset, 0x2000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.name, "loop_top");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SLabel32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.push(0);
        data.push(0); // empty name

        let sym = SLabel32::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SLabel32::new(0x2000, 1, 0, "L1".to_string());
        assert_eq!(sym.pdb_id(), 0x0209);
        assert_eq!(sym.symbol_type_name(), "S_LABEL32");
        assert_eq!(sym.name(), "L1");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_display() {
        let sym = SLabel32::new(0x3000, 2, 0x01, "exit_label".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("Label"));
        assert!(s.contains("exit_label"));
        assert!(s.contains("3000"));
        assert!(s.contains("0x01"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SLabel32::new(0x4000, 3, 0, "L2".to_string());
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x4000);
    }
}
