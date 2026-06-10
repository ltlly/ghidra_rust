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
/// - `length` — Length of the block in bytes (variable-sized offset field in PDB).
/// - `offset` — Offset of the block within its segment (variable-sized offset field in PDB).
/// - `segment` — The PE section/segment containing this block.
/// - `name` — Optional block name (often empty for anonymous blocks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractBlock {
    /// Offset of the enclosing parent scope.
    pub parent_offset: u32,

    /// Offset where this block ends.
    pub end_offset: u32,

    /// Length of the block in bytes.
    pub length: u32,

    /// Offset of the block within its segment.
    pub offset: u32,

    /// The segment (PE section) containing this block.
    pub segment: u16,

    /// The block name (may be empty for anonymous blocks).
    pub name: String,
}

impl AbstractBlock {
    /// Create a new block symbol.
    pub fn new(
        parent_offset: u32,
        end_offset: u32,
        length: u32,
        offset: u32,
        segment: u16,
        name: String,
    ) -> Self {
        Self {
            parent_offset,
            end_offset,
            length,
            offset,
            segment,
            name,
        }
    }

    /// Parse a block symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `parent_offset(u32) + end_offset(u32) + length(u32) + offset(u32) + segment(u16) + name(NT)`.
    ///
    /// After the name the stream should be 4-byte aligned (caller's responsibility).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 18 {
            return None;
        }
        let parent_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let length = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let segment = u16::from_le_bytes([data[16], data[17]]);
        let name = parse_nt_string(&data[18..]);
        Some(Self {
            parent_offset,
            end_offset,
            length,
            offset,
            segment,
            name,
        })
    }

    /// Return the number of bytes consumed by the name string (including null
    /// terminator) starting at byte offset 18.
    fn name_byte_len(data: &[u8]) -> usize {
        let name_data = &data[18..];
        let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
        end + 1 // include null terminator
    }

    /// Parse a block symbol and return it along with the total bytes consumed
    /// (including 4-byte alignment padding after the name).
    ///
    /// This matches the Java `reader.align4()` call after parsing.
    pub fn parse_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = Self::parse(data)?;
        let name_len = Self::name_byte_len(data);
        let total = 18 + name_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
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
            "Block: [{:04X}:{:08X}], Length: {:08X}, {}\n   Parent: {:08X}, End: {:08X}",
            self.segment, self.offset, self.length, self.name,
            self.parent_offset, self.end_offset
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

    fn make_block_bytes(
        parent: u32,
        end: u32,
        length: u32,
        offset: u32,
        segment: u16,
        name: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&parent.to_le_bytes());
        data.extend_from_slice(&end.to_le_bytes());
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_block_bytes(0x1000, 0x2000, 0x100, 0x50, 1, b"block");
        let sym = AbstractBlock::parse(&data).unwrap();
        assert_eq!(sym.parent_offset, 0x1000);
        assert_eq!(sym.end_offset, 0x2000);
        assert_eq!(sym.length, 0x100);
        assert_eq!(sym.offset, 0x50);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.name, "block");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04]; // too short (need 18 bytes)
        assert!(AbstractBlock::parse(&data).is_none());
    }

    #[test]
    fn test_parse_anonymous_block() {
        let data = make_block_bytes(0, 0x100, 0x100, 0, 2, b"");
        let sym = AbstractBlock::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_aligned() {
        // name "ab" = 2 chars + 1 null = 3 bytes, 18+3=21, aligned to 24
        let data = make_block_bytes(0x1000, 0x2000, 0x100, 0x50, 1, b"ab");
        let (sym, consumed) = AbstractBlock::parse_aligned(&data).unwrap();
        assert_eq!(sym.name, "ab");
        assert_eq!(consumed, 24); // 18 + 3 = 21, aligned to 24
    }

    #[test]
    fn test_parse_aligned_already_aligned() {
        // name "abc" = 3 chars + 1 null = 4 bytes, 18+4=22, aligned to 24
        let data = make_block_bytes(0x1000, 0x2000, 0x100, 0x50, 1, b"abc");
        let (sym, consumed) = AbstractBlock::parse_aligned(&data).unwrap();
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 24); // 18 + 4 = 22, aligned to 24 -- wait, 22 align4 = 24
    }

    #[test]
    fn test_trait_impls() {
        let sym = AbstractBlock::new(0x1000, 0x2000, 0x100, 0x50, 1, "my_block".to_string());
        assert_eq!(sym.pdb_id(), 0x0207);
        assert_eq!(sym.symbol_type_name(), "S_BLOCK32");
        assert_eq!(sym.name(), "my_block");
    }

    #[test]
    fn test_display() {
        let sym = AbstractBlock::new(0x1000, 0x2000, 0x100, 0x50, 1, "scope".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("Block"));
        assert!(s.contains("scope"));
        assert!(s.contains("Parent"));
        assert!(s.contains("End"));
    }
}
