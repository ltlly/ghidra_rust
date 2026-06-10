//! S_WITH32 -- WITH statement scope symbol (32-bit).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_With32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// A WITH statement scope symbol (`S_WITH32`).
///
/// This symbol marks the beginning of a WITH statement scope (as found in
/// languages like BASIC or Pascal). It records the parent scope offset, the
/// block end offset, the segment, and the WITH expression string. The scope
/// is terminated by a matching `S_END` symbol.
///
/// In terms of binary layout, `S_WITH32` is identical to `S_BLOCK32` except
/// that the "name" field is interpreted as an expression rather than a block
/// name.
///
/// # PDB Binary Layout
///
/// ```text
/// parent_offset : u32
/// end_offset    : u32
/// segment       : u16
/// expression    : NT string
/// ```
///
/// This corresponds to `S_WITH32` (0x0208) and `S_WITH16` (0x0108) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SWith32 {
    /// Offset of the enclosing parent scope.
    pub parent_offset: u32,

    /// Offset where this WITH scope ends.
    pub end_offset: u32,

    /// The PE section/segment containing this scope.
    pub segment: u16,

    /// The WITH expression (e.g., variable name or record field path).
    pub expression: String,
}

impl SWith32 {
    /// Create a new S_WITH32 symbol.
    pub fn new(
        parent_offset: u32,
        end_offset: u32,
        segment: u16,
        expression: String,
    ) -> Self {
        Self {
            parent_offset,
            end_offset,
            segment,
            expression,
        }
    }

    /// Parse an S_WITH32 symbol from a byte slice.
    ///
    /// Expects the layout: `parent_offset(u32) + end_offset(u32) + segment(u16) + expression(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let parent_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let segment = u16::from_le_bytes([data[8], data[9]]);
        let expression = parse_nt_string(&data[10..]);
        Some(Self {
            parent_offset,
            end_offset,
            segment,
            expression,
        })
    }

    /// Return the offset of the enclosing parent scope.
    pub fn parent_offset(&self) -> u32 {
        self.parent_offset
    }

    /// Return the offset where this scope ends.
    pub fn end_offset(&self) -> u32 {
        self.end_offset
    }
}

impl AbstractMsSymbol for SWith32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_WITH32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_WITH32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "With: [{:04X}], Parent: {:08X}, End: {:08X}, {}",
            self.segment, self.parent_offset, self.end_offset, self.expression
        )
    }
}

impl AddressMsSymbol for SWith32 {
    fn offset(&self) -> u64 {
        self.end_offset as u64
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SWith32 {
    fn name(&self) -> &str {
        &self.expression
    }
}

impl fmt::Display for SWith32 {
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

    fn make_with32_bytes(
        parent: u32,
        end: u32,
        segment: u16,
        expression: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&parent.to_le_bytes());
        data.extend_from_slice(&end.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.extend_from_slice(expression);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_with32_bytes(0x1000, 0x2000, 1, b"myRecord");
        let sym = SWith32::parse(&data).unwrap();
        assert_eq!(sym.parent_offset(), 0x1000);
        assert_eq!(sym.end_offset(), 0x2000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.expression, "myRecord");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SWith32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_expression() {
        let data = make_with32_bytes(0, 0x100, 2, b"");
        let sym = SWith32::parse(&data).unwrap();
        assert_eq!(sym.expression, "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SWith32::new(0x1000, 0x2000, 1, "obj.field".to_string());
        assert_eq!(sym.pdb_id(), 0x0208);
        assert_eq!(sym.symbol_type_name(), "S_WITH32");
        assert_eq!(sym.name(), "obj.field");
        assert_eq!(sym.parent_offset(), 0x1000);
        assert_eq!(sym.end_offset(), 0x2000);
    }

    #[test]
    fn test_display() {
        let sym = SWith32::new(0x1000, 0x2000, 1, "myObj".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("With"));
        assert!(s.contains("myObj"));
        assert!(s.contains("1000"));
        assert!(s.contains("2000"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SWith32::new(0x1000, 0x2000, 3, "e".to_string());
        assert_eq!(sym.segment(), 3);
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x2000);
    }

    #[test]
    fn test_clone_eq() {
        let a = SWith32::new(0x100, 0x200, 1, "expr".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }
}
