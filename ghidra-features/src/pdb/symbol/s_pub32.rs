//! S_PUB32 -- Public symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_Pub32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// A public symbol (`S_PUB32`).
///
/// This symbol describes a globally-visible label in the PDB. Public symbols
/// are emitted by the linker for exported functions and data, and are used by
/// debuggers to resolve names to addresses.
///
/// # PDB Binary Layout (32-bit)
///
/// ```text
/// flags   : u32
/// offset  : u32
/// segment : u16
/// name    : NT string
/// ```
///
/// This corresponds to `S_PUB32` (0x0203) and `S_PUB32_ST` (0x1009) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SPub32 {
    /// Public symbol flags (e.g., `cvpsfFunction` for code, `cvpsfData` for data).
    pub flags: u32,

    /// Offset of the symbol within the segment.
    pub offset: u64,

    /// The PE section/segment containing this symbol.
    pub segment: u16,

    /// The symbol name.
    pub name: String,
}

impl SPub32 {
    /// Create a new public symbol.
    pub fn new(flags: u32, offset: u64, segment: u16, name: String) -> Self {
        Self {
            flags,
            offset,
            segment,
            name,
        }
    }

    /// Parse an S_PUB32 symbol from a byte slice.
    ///
    /// Expects the layout: `flags(u32) + offset(u32) + segment(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let flags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
        let segment = u16::from_le_bytes([data[8], data[9]]);
        let name = parse_nt_string(&data[10..]);
        Some(Self {
            flags,
            offset,
            segment,
            name,
        })
    }

    /// Return `true` if this public symbol represents a function (code).
    pub fn is_function(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

impl AbstractMsSymbol for SPub32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_PUB32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_PUB32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_function() { "Function" } else { "Data" };
        write!(
            f,
            "Public {}: [{:04X}:{:08X}], Flags: 0x{:08X}, {}",
            kind, self.segment, self.offset, self.flags, self.name
        )
    }
}

impl AddressMsSymbol for SPub32 {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SPub32 {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SPub32 {
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

    fn make_pub32_bytes(flags: u32, offset: u32, segment: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_pub32_bytes(0x01, 0x1000, 1, b"printf");
        let sym = SPub32::parse(&data).unwrap();
        assert_eq!(sym.flags, 0x01);
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.name, "printf");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SPub32::parse(&data).is_none());
    }

    #[test]
    fn test_is_function() {
        let sym = SPub32::new(0x01, 0x1000, 1, "f".to_string());
        assert!(sym.is_function());

        let sym = SPub32::new(0x02, 0x1000, 1, "d".to_string());
        assert!(!sym.is_function());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SPub32::new(0x01, 0x2000, 2, "my_global".to_string());
        assert_eq!(sym.pdb_id(), 0x0203);
        assert_eq!(sym.symbol_type_name(), "S_PUB32");
        assert_eq!(sym.name(), "my_global");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 2);
    }

    #[test]
    fn test_display() {
        let sym = SPub32::new(0x01, 0x3000, 1, "main".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("Public Function"));
        assert!(s.contains("main"));
        assert!(s.contains("3000"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SPub32::new(0x00, 0x4000, 3, "v".to_string());
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x4000);
    }

    #[test]
    fn test_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());  // flags
        data.extend_from_slice(&0x100u32.to_le_bytes()); // offset
        data.extend_from_slice(&1u16.to_le_bytes());  // segment
        data.push(0); // empty name

        let sym = SPub32::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }
}
