//! S_WITH32 -- WITH statement scope symbol (32-bit).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.With32MsSymbol`
//! and `With32StMsSymbol`.
//!
//! The WITH statement scope symbol marks the beginning of a WITH expression
//! scope (as found in languages like BASIC or Pascal). The scope is terminated
//! by a matching `S_END` symbol.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// Which variant of the WITH symbol was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithVariant {
    /// `S_WITH32` (0x0208) -- 32-bit offset, NT string (v5 PDB).
    With32,
    /// `S_WITH32_V2` (0x1104) -- 32-bit offset, NT string (v7 PDB).
    With32V2,
    /// `S_WITH32_ST` -- 32-bit offset, ST string (16-bit length prefix).
    With32St,
}

/// A WITH statement scope symbol (`S_WITH32`).
///
/// This symbol marks the beginning of a WITH statement scope (as found in
/// languages like BASIC or Pascal). It records the parent scope offset, the
/// block end offset, the length, the segment offset, the segment, and the
/// WITH expression string. The scope is terminated by a matching `S_END`
/// symbol.
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
/// length        : u32
/// offset        : u32
/// segment       : u16
/// expression    : NT string
/// ```
///
/// This corresponds to `S_WITH32` (0x0208 / 0x1104) and `S_WITH16`
/// (0x0108) in the CodeView symbol set. After the expression the stream is
/// 4-byte aligned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SWith32 {
    /// Offset of the enclosing parent scope.
    pub parent_offset: u32,

    /// Offset where this WITH scope ends.
    pub end_offset: u32,

    /// Length of the WITH scope in bytes.
    pub length: u32,

    /// Offset of the WITH scope within its segment.
    pub offset: u32,

    /// The PE section/segment containing this scope.
    pub segment: u16,

    /// The WITH expression (e.g., variable name or record field path).
    pub expression: String,

    /// Which variant was parsed.
    variant: WithVariant,
}

impl SWith32 {
    /// Create a new S_WITH32 symbol (v7 / v2 variant).
    pub fn new(
        parent_offset: u32,
        end_offset: u32,
        length: u32,
        offset: u32,
        segment: u16,
        expression: String,
    ) -> Self {
        Self {
            parent_offset,
            end_offset,
            length,
            offset,
            segment,
            expression,
            variant: WithVariant::With32V2,
        }
    }

    /// Create an S_WITH32 symbol with a specific variant tag.
    pub fn with_variant(
        parent_offset: u32,
        end_offset: u32,
        length: u32,
        offset: u32,
        segment: u16,
        expression: String,
        variant: WithVariant,
    ) -> Self {
        Self {
            parent_offset,
            end_offset,
            length,
            offset,
            segment,
            expression,
            variant,
        }
    }

    /// Parse an S_WITH32 symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `parent_offset(u32) + end_offset(u32) + length(u32) + offset(u32) + segment(u16) + expression(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        Self::parse_as(data, WithVariant::With32V2)
    }

    /// Parse with an explicit variant tag.
    pub fn parse_as(data: &[u8], variant: WithVariant) -> Option<Self> {
        if data.len() < 18 {
            return None;
        }
        let parent_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let length = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let segment = u16::from_le_bytes([data[16], data[17]]);
        let expression = parse_nt_string(&data[18..]);
        Some(Self {
            parent_offset,
            end_offset,
            length,
            offset,
            segment,
            expression,
            variant,
        })
    }

    /// Parse an S_WITH32 symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the expression).
    ///
    /// This matches the Java `reader.align4()` call after parsing.
    pub fn parse_aligned(data: &[u8]) -> Option<(Self, usize)> {
        Self::parse_aligned_as(data, WithVariant::With32V2)
    }

    /// Parse with alignment and an explicit variant tag.
    pub fn parse_aligned_as(data: &[u8], variant: WithVariant) -> Option<(Self, usize)> {
        let sym = Self::parse_as(data, variant)?;
        let name_data = &data[18..];
        let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
        let name_len = end + 1; // include null terminator
        let total = 18 + name_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }

    /// Return the variant of this WITH symbol.
    pub fn variant(&self) -> WithVariant {
        self.variant
    }

    /// Return the offset of the enclosing parent scope.
    pub fn parent_offset(&self) -> u32 {
        self.parent_offset
    }

    /// Return the offset where this scope ends.
    pub fn end_offset(&self) -> u32 {
        self.end_offset
    }

    /// Return the length of the WITH scope in bytes.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Return the offset of the WITH scope within its segment.
    pub fn scope_offset(&self) -> u32 {
        self.offset
    }

    /// Return the WITH expression string.
    ///
    /// This is the expression that the WITH statement operates on, typically
    /// a variable name or a record field path.
    pub fn expression(&self) -> &str {
        &self.expression
    }
}

impl AbstractMsSymbol for SWith32 {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            WithVariant::With32 => super::super::symbol_kind::S_WITH32,
            WithVariant::With32V2 => super::super::symbol_kind::S_WITH32_V2,
            WithVariant::With32St => 0x1115, // S_WITH32_ST (if defined)
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            WithVariant::With32St => "S_WITH32_ST",
            _ => "S_WITH32",
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WITH32: [{:04X}:{:08X}], Length: {:08X}, {}\n   Parent: {:08X}, End: {:08X}",
            self.segment, self.offset, self.length, self.expression,
            self.parent_offset, self.end_offset
        )
    }
}

impl AddressMsSymbol for SWith32 {
    fn offset(&self) -> u64 {
        self.offset as u64
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
        length: u32,
        offset: u32,
        segment: u16,
        expression: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&parent.to_le_bytes());
        data.extend_from_slice(&end.to_le_bytes());
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.extend_from_slice(expression);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_with32_bytes(0x1000, 0x2000, 0x100, 0x50, 1, b"myRecord");
        let sym = SWith32::parse(&data).unwrap();
        assert_eq!(sym.parent_offset(), 0x1000);
        assert_eq!(sym.end_offset(), 0x2000);
        assert_eq!(sym.length(), 0x100);
        assert_eq!(sym.scope_offset(), 0x50);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.expression, "myRecord");
        assert_eq!(sym.variant(), WithVariant::With32V2);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SWith32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_expression() {
        let data = make_with32_bytes(0, 0x100, 0x100, 0, 2, b"");
        let sym = SWith32::parse(&data).unwrap();
        assert_eq!(sym.expression, "");
    }

    #[test]
    fn test_parse_aligned() {
        // name "ab" = 2 chars + 1 null = 3 bytes, 18+3=21, aligned to 24
        let data = make_with32_bytes(0x1000, 0x2000, 0x100, 0x50, 1, b"ab");
        let (sym, consumed) = SWith32::parse_aligned(&data).unwrap();
        assert_eq!(sym.expression, "ab");
        assert_eq!(consumed, 24);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SWith32::new(0x1000, 0x2000, 0x100, 0x50, 1, "obj.field".to_string());
        assert_eq!(sym.pdb_id(), 0x1104);
        assert_eq!(sym.symbol_type_name(), "S_WITH32");
        assert_eq!(sym.name(), "obj.field");
        assert_eq!(sym.expression(), "obj.field");
        assert_eq!(sym.parent_offset(), 0x1000);
        assert_eq!(sym.end_offset(), 0x2000);
        assert_eq!(sym.length(), 0x100);
        assert_eq!(sym.scope_offset(), 0x50);
    }

    #[test]
    fn test_display() {
        let sym = SWith32::new(0x1000, 0x2000, 0x100, 0x50, 1, "myObj".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("WITH32"));
        assert!(s.contains("myObj"));
        assert!(s.contains("Parent"));
        assert!(s.contains("End"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SWith32::new(0x1000, 0x2000, 0x100, 0x50, 3, "e".to_string());
        assert_eq!(sym.segment(), 3);
        assert_eq!(sym.offset(), 0x50);
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x50);
    }

    #[test]
    fn test_clone_eq() {
        let a = SWith32::new(0x100, 0x200, 0x100, 0x50, 1, "expr".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_variant_with32() {
        let sym = SWith32::with_variant(
            0x100, 0x200, 0x100, 0x50, 1, "e".to_string(),
            WithVariant::With32,
        );
        assert_eq!(sym.pdb_id(), 0x0208);
        assert_eq!(sym.variant(), WithVariant::With32);
    }

    #[test]
    fn test_variant_with32_v2() {
        let sym = SWith32::new(0x100, 0x200, 0x100, 0x50, 1, "e".to_string());
        assert_eq!(sym.pdb_id(), 0x1104);
        assert_eq!(sym.variant(), WithVariant::With32V2);
    }

    #[test]
    fn test_expression_accessor() {
        let sym = SWith32::new(0x100, 0x200, 0x100, 0x50, 1, "record.field".to_string());
        assert_eq!(sym.expression(), "record.field");
    }

    #[test]
    fn test_parse_as_variant() {
        let data = make_with32_bytes(0x100, 0x200, 0x100, 0x50, 1, b"e");
        let sym = SWith32::parse_as(&data, WithVariant::With32).unwrap();
        assert_eq!(sym.variant(), WithVariant::With32);
        assert_eq!(sym.pdb_id(), 0x0208);
    }
}
