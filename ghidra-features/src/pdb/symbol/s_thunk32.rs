//! S_THUNK32 -- Thunk symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_Thunk32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// A thunk symbol (`S_THUNK32`).
///
/// This symbol describes a thunk -- a small piece of code that performs an
/// indirection or adjustment before transferring control to another function.
/// Thunks are commonly used for vtable dispatch, incremental linking, and
/// DLL import stubs.
///
/// # PDB Binary Layout (32-bit)
///
/// ```text
/// parent       : u32
/// end          : u32
/// next         : u32
/// offset       : u32
/// segment      : u16
/// length       : u16
/// thunk_type   : u8
/// name         : NT string
/// variant_data : varies by thunk_type
/// ```
///
/// This corresponds to `S_THUNK32` (0x0206) and `S_THUNK16` (0x0106) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SThunk32 {
    /// Offset of the enclosing scope (parent block or procedure).
    pub parent: u32,

    /// Offset where this thunk's scope ends.
    pub end: u32,

    /// Offset of the next thunk in the thunk chain (0 if last).
    pub next: u32,

    /// Offset of the thunk entry point within the segment.
    pub offset: u64,

    /// The PE section/segment containing this thunk.
    pub segment: u16,

    /// Length of the thunk code in bytes.
    pub length: u16,

    /// The thunk type ordinal (e.g., 0 = standard, 1 = branch island, etc.).
    pub thunk_type: u8,

    /// The thunk name.
    pub name: String,

    /// Variant-specific data whose interpretation depends on `thunk_type`.
    ///
    /// For standard thunks this is empty. For branch-island thunks this
    /// contains the target offset.
    pub variant_data: Vec<u8>,
}

impl SThunk32 {
    /// Create a new thunk symbol.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: u32,
        end: u32,
        next: u32,
        offset: u64,
        segment: u16,
        length: u16,
        thunk_type: u8,
        name: String,
        variant_data: Vec<u8>,
    ) -> Self {
        Self {
            parent,
            end,
            next,
            offset,
            segment,
            length,
            thunk_type,
            name,
            variant_data,
        }
    }

    /// Parse an S_THUNK32 symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `parent(u32) + end(u32) + next(u32) + offset(u32) + segment(u16) +
    /// length(u16) + thunk_type(u8) + name(NT) + variant_data(...)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 21 {
            return None;
        }
        let parent = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let next = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as u64;
        let segment = u16::from_le_bytes([data[16], data[17]]);
        let length = u16::from_le_bytes([data[18], data[19]]);
        let thunk_type = data[20];
        let name = parse_nt_string(&data[21..]);
        let name_end = 21 + name.len() + 1; // +1 for null terminator
        let variant_data = if name_end < data.len() {
            data[name_end..].to_vec()
        } else {
            Vec::new()
        };
        Some(Self {
            parent,
            end,
            next,
            offset,
            segment,
            length,
            thunk_type,
            name,
            variant_data,
        })
    }
}

impl AbstractMsSymbol for SThunk32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_THUNK32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_THUNK32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Thunk: [{:04X}:{:08X}], Length: {}, Type: {}, Parent: {:08X}, End: {:08X}, {}",
            self.segment, self.offset, self.length, self.thunk_type,
            self.parent, self.end, self.name
        )
    }
}

impl AddressMsSymbol for SThunk32 {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SThunk32 {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SThunk32 {
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

    fn make_thunk32_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());         // parent
        data.extend_from_slice(&0x100u32.to_le_bytes());     // end
        data.extend_from_slice(&0u32.to_le_bytes());         // next
        data.extend_from_slice(&0x5000u32.to_le_bytes());    // offset
        data.extend_from_slice(&1u16.to_le_bytes());         // segment
        data.extend_from_slice(&6u16.to_le_bytes());         // length
        data.push(0);                                         // thunk_type (standard)
        data.extend_from_slice(b"__imp_main\0");             // name
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_thunk32_bytes();
        let sym = SThunk32::parse(&data).unwrap();
        assert_eq!(sym.parent, 0);
        assert_eq!(sym.end, 0x100);
        assert_eq!(sym.next, 0);
        assert_eq!(sym.offset, 0x5000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.length, 6);
        assert_eq!(sym.thunk_type, 0);
        assert_eq!(sym.name, "__imp_main");
        assert!(sym.variant_data.is_empty());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SThunk32::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 1, 6, 0, "thunk_func".to_string(), Vec::new(),
        );
        assert_eq!(sym.pdb_id(), 0x0206);
        assert_eq!(sym.symbol_type_name(), "S_THUNK32");
        assert_eq!(sym.name(), "thunk_func");
        assert_eq!(sym.offset(), 0x5000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_display() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 1, 6, 0, "__imp_foo".to_string(), Vec::new(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Thunk"));
        assert!(s.contains("__imp_foo"));
        assert!(s.contains("5000"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 3, 6, 0, "t".to_string(), Vec::new(),
        );
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x5000);
    }

    #[test]
    fn test_with_variant_data() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 1, 6, 1, "island".to_string(),
            vec![0x78, 0x56, 0x34, 0x12],
        );
        assert_eq!(sym.thunk_type, 1);
        assert_eq!(sym.variant_data, vec![0x78, 0x56, 0x34, 0x12]);
    }
}
