//! S_COFFGROUP -- COFF group symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.CoffGroupMsSymbol`
//! and `PeCoffGroupMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// A COFF group symbol (`S_COFFGROUP`).
///
/// This symbol describes a COFF group -- a logical grouping of sections
/// or section fragments. COFF groups are used by the Microsoft linker to
/// aggregate related code or data (e.g., all `.text$mn` fragments for a
/// specific function class) into contiguous regions of the image.
///
/// # PDB Binary Layout
///
/// ```text
/// size            : u32
/// characteristics : u32
/// offset          : u32
/// segment         : u16
/// name            : NT string
/// ```
///
/// This corresponds to `S_COFFGROUP` (0x102A) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SCoffGroup {
    /// Size of the COFF group in bytes.
    pub size: u32,

    /// COFF group characteristics flags (same semantics as PE section flags).
    pub characteristics: u32,

    /// Offset of the group within its segment.
    pub offset: u64,

    /// The PE section/segment containing this group.
    pub segment: u16,

    /// The COFF group name (e.g., `.text$mn`).
    pub name: String,
}

impl SCoffGroup {
    /// Create a new COFF group symbol.
    pub fn new(
        size: u32,
        characteristics: u32,
        offset: u64,
        segment: u16,
        name: String,
    ) -> Self {
        Self {
            size,
            characteristics,
            offset,
            segment,
            name,
        }
    }

    /// Parse an S_COFFGROUP symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `size(u32) + characteristics(u32) + offset(u32) + segment(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        let size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let characteristics = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as u64;
        let segment = u16::from_le_bytes([data[12], data[13]]);
        let name = parse_nt_string(&data[14..]);
        Some(Self {
            size,
            characteristics,
            offset,
            segment,
            name,
        })
    }
}

impl AbstractMsSymbol for SCoffGroup {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_COFFGROUP
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_COFFGROUP"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoffGroup: [{:04X}:{:08X}], Length = {:08X}, Characteristics = {:08X}, {}",
            self.segment, self.offset, self.size, self.characteristics, self.name,
        )
    }
}

impl AddressMsSymbol for SCoffGroup {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SCoffGroup {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SCoffGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// A PE COFF group symbol (`S_PE_COFFGROUP`).
///
/// This is a newer variant of the COFF group symbol with PDB ID 0x1137.
/// Its binary layout is identical to [`SCoffGroup`] but uses a different
/// symbol kind to distinguish PE COFF groups from legacy COFF groups.
///
/// Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.PeCoffGroupMsSymbol`.
///
/// # PDB Binary Layout
///
/// ```text
/// length          : u32
/// characteristics : u32
/// offset          : u32
/// segment         : u16
/// name            : NT string
/// ```
///
/// This corresponds to `S_PE_COFFGROUP` (0x1137) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SPeCoffGroup {
    /// Length of the PE COFF group in bytes.
    pub length: u32,

    /// PE COFF group characteristics flags (same semantics as PE section flags).
    pub characteristics: u32,

    /// Offset of the group within its segment.
    pub offset: u64,

    /// The PE section/segment containing this group.
    pub segment: u16,

    /// The PE COFF group name.
    pub name: String,
}

impl SPeCoffGroup {
    /// Create a new PE COFF group symbol.
    pub fn new(
        length: u32,
        characteristics: u32,
        offset: u64,
        segment: u16,
        name: String,
    ) -> Self {
        Self {
            length,
            characteristics,
            offset,
            segment,
            name,
        }
    }

    /// Parse an S_PE_COFFGROUP symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `length(u32) + characteristics(u32) + offset(u32) + segment(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let characteristics = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as u64;
        let segment = u16::from_le_bytes([data[12], data[13]]);
        let name = parse_nt_string(&data[14..]);
        Some(Self {
            length,
            characteristics,
            offset,
            segment,
            name,
        })
    }
}

impl AbstractMsSymbol for SPeCoffGroup {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_PE_COFFGROUP
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_PE_COFFGROUP"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoffGroup: [{:04X}:{:08X}], Length = {:08X}, Characteristics = {:08X}, {}",
            self.segment, self.offset, self.length, self.characteristics, self.name,
        )
    }
}

impl AddressMsSymbol for SPeCoffGroup {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SPeCoffGroup {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SPeCoffGroup {
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

    fn make_coffgroup_bytes(
        size: u32,
        characteristics: u32,
        offset: u32,
        segment: u16,
        name: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(&characteristics.to_le_bytes());
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_coffgroup_bytes(0x1000, 0x60000020, 0x2000, 1, b".text$mn");
        let sym = SCoffGroup::parse(&data).unwrap();
        assert_eq!(sym.size, 0x1000);
        assert_eq!(sym.characteristics, 0x60000020);
        assert_eq!(sym.offset, 0x2000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.name, ".text$mn");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SCoffGroup::parse(&data).is_none());
    }

    #[test]
    fn test_parse_data_group() {
        let data = make_coffgroup_bytes(0x500, 0xC0000040, 0x6000, 2, b".data$bss");
        let sym = SCoffGroup::parse(&data).unwrap();
        assert_eq!(sym.name, ".data$bss");
        assert_eq!(sym.characteristics, 0xC0000040);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SCoffGroup::new(0x1000, 0x60000020, 0x2000, 1, ".text$mn".to_string());
        assert_eq!(sym.pdb_id(), 0x102A);
        assert_eq!(sym.symbol_type_name(), "S_COFFGROUP");
        assert_eq!(sym.name(), ".text$mn");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_display() {
        let sym = SCoffGroup::new(0x800, 0x60000020, 0x3000, 1, ".text$x".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("CoffGroup"));
        assert!(s.contains(".text$x"));
        assert!(s.contains("3000"));
        assert!(s.contains("800"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SCoffGroup::new(0x100, 0, 0x4000, 3, ".rdata".to_string());
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x4000);
    }

    #[test]
    fn test_name_trait() {
        let sym = SCoffGroup::new(0, 0, 0, 0, ".CRT$XCA".to_string());
        assert_eq!(sym.name(), ".CRT$XCA");
    }

    #[test]
    fn test_clone_eq() {
        let a = SCoffGroup::new(0x1000, 0x60000020, 0x2000, 1, ".text".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }

    // SPeCoffGroup tests

    #[test]
    fn test_pe_coffgroup_parse_basic() {
        let data = make_coffgroup_bytes(0x2000, 0x40000040, 0x3000, 2, b".pdata");
        let sym = SPeCoffGroup::parse(&data).unwrap();
        assert_eq!(sym.length, 0x2000);
        assert_eq!(sym.characteristics, 0x40000040);
        assert_eq!(sym.offset, 0x3000);
        assert_eq!(sym.segment, 2);
        assert_eq!(sym.name, ".pdata");
    }

    #[test]
    fn test_pe_coffgroup_parse_truncated() {
        let data = [0x00; 5];
        assert!(SPeCoffGroup::parse(&data).is_none());
    }

    #[test]
    fn test_pe_coffgroup_trait_impls() {
        let sym = SPeCoffGroup::new(
            0x1000,
            0x60000020,
            0x2000,
            1,
            ".text$mn".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1137);
        assert_eq!(sym.symbol_type_name(), "S_PE_COFFGROUP");
        assert_eq!(sym.name(), ".text$mn");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_pe_coffgroup_display() {
        let sym = SPeCoffGroup::new(
            0x800,
            0x60000020,
            0x3000,
            1,
            ".rdata".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("CoffGroup"));
        assert!(s.contains(".rdata"));
        assert!(s.contains("3000"));
    }

    #[test]
    fn test_pe_coffgroup_address_trait() {
        let sym = SPeCoffGroup::new(0x100, 0, 0x4000, 3, ".pdata".to_string());
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x4000);
    }

    #[test]
    fn test_pe_coffgroup_clone_eq() {
        let a = SPeCoffGroup::new(0x1000, 0x60000020, 0x2000, 1, ".text".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }
}
