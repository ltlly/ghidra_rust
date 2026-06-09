//! AbstractBlock -- abstract base for block symbols.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractBlockMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// Abstract base for PDB block symbols.
///
/// These symbols correspond to `S_BLOCK16` and `S_BLOCK32` in the CodeView
/// symbol set. They mark the beginning of a lexical block (scope) within a
/// procedure, delineated by a parent offset and an end offset.
///
/// # Fields
///
/// - `parent_offset` — Offset of the enclosing scope (parent block or procedure).
/// - `end_offset` — Offset where this block ends.
/// - `segment` — The PE section/segment containing this block.
/// - `name` — Optional block name (often empty for anonymous blocks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractBlock {
    /// Offset of the enclosing parent scope.
    pub parent_offset: u32,

    /// Offset where this block ends.
    pub end_offset: u32,

    /// The segment (PE section) containing this block.
    pub segment: u16,

    /// The block name (may be empty for anonymous blocks).
    pub name: String,
}

impl AbstractBlock {
    /// Create a new block symbol.
    pub fn new(parent_offset: u32, end_offset: u32, segment: u16, name: String) -> Self {
        Self {
            parent_offset,
            end_offset,
            segment,
            name,
        }
    }

    /// Parse a block symbol from a byte slice.
    ///
    /// Expects the layout: `parent_offset(u32) + end_offset(u32) + segment(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let parent_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let segment = u16::from_le_bytes([data[8], data[9]]);
        let name = parse_nt_string(&data[10..]);
        Some(Self {
            parent_offset,
            end_offset,
            segment,
            name,
        })
    }
}

impl AbstractMsSymbol for AbstractBlock {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_BLOCK32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_BLOCK32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block: [{:04X}], Parent: {:08X}, End: {:08X}, {}",
            self.segment, self.parent_offset, self.end_offset, self.name
        )
    }
}

impl NameMsSymbol for AbstractBlock {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for AbstractBlock {
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

    #[test]
    fn test_parse_basic() {
        // parent_offset(u32) + end_offset(u32) + segment(u16) + name("block\0")
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // parent_offset
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // end_offset
        data.extend_from_slice(&1u16.to_le_bytes());       // segment
        data.extend_from_slice(b"block\0");

        let sym = AbstractBlock::parse(&data).unwrap();
        assert_eq!(sym.parent_offset, 0x1000);
        assert_eq!(sym.end_offset, 0x2000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.name, "block");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04]; // too short
        assert!(AbstractBlock::parse(&data).is_none());
    }

    #[test]
    fn test_parse_anonymous_block() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x100u32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.push(0); // empty name

        let sym = AbstractBlock::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = AbstractBlock::new(0x1000, 0x2000, 1, "my_block".to_string());
        assert_eq!(sym.pdb_id(), 0x0207);
        assert_eq!(sym.symbol_type_name(), "S_BLOCK32");
        assert_eq!(sym.name(), "my_block");
    }

    #[test]
    fn test_display() {
        let sym = AbstractBlock::new(0x1000, 0x2000, 1, "scope".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("Block"));
        assert!(s.contains("scope"));
        assert!(s.contains("1000"));
        assert!(s.contains("2000"));
    }
}
