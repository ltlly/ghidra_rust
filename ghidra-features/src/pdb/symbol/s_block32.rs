//! S_BLOCK32 -- Block symbol (32-bit).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.Block32MsSymbol`
//! and `Block32StMsSymbol`.
//!
//! The block symbol marks the beginning of a lexical scope within a procedure.
//! The scope is terminated by a matching `S_END` symbol.

use std::fmt;

use super::abstract_block::AbstractBlock;
use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// Which variant of the block symbol was parsed.
///
/// The v7 (32-bit NT string) variant uses PDB ID 0x1103. The older v5 variant
/// uses PDB ID 0x0207 with identical binary layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockVariant {
    /// `S_BLOCK32` (0x0207) -- 32-bit offset, NT string.
    Block32,
    /// `S_BLOCK32_V2` (0x1103) -- 32-bit offset, NT string (v7 PDB).
    Block32V2,
    /// `S_BLOCK32_ST` -- 32-bit offset, ST string (16-bit length prefix).
    Block32St,
}

/// A block symbol (`S_BLOCK32`).
///
/// This symbol marks the beginning of a lexical block (scope) within a
/// procedure. It records the parent scope offset, the block end offset,
/// the length, the segment offset, the segment, and an optional name. The
/// block's extent is terminated by a matching `S_END` symbol.
///
/// Internally this wraps [`AbstractBlock`] which holds the shared fields.
///
/// # PDB Binary Layout
///
/// ```text
/// parent_offset : u32
/// end_offset    : u32
/// length        : u32
/// offset        : u32
/// segment       : u16
/// name          : NT string
/// ```
///
/// This corresponds to `S_BLOCK32` (0x0207 / 0x1103) and `S_BLOCK16`
/// (0x0107) in the CodeView symbol set. After the name the stream is
/// 4-byte aligned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SBlock32 {
    /// The underlying block data.
    pub inner: AbstractBlock,

    /// Which variant was parsed.
    variant: BlockVariant,
}

impl SBlock32 {
    /// Create a new S_BLOCK32 symbol (v7 / v2 variant).
    pub fn new(
        parent_offset: u32,
        end_offset: u32,
        length: u32,
        offset: u32,
        segment: u16,
        name: String,
    ) -> Self {
        Self {
            inner: AbstractBlock::new(parent_offset, end_offset, length, offset, segment, name),
            variant: BlockVariant::Block32V2,
        }
    }

    /// Create an S_BLOCK32 symbol with a specific variant tag.
    pub fn with_variant(
        parent_offset: u32,
        end_offset: u32,
        length: u32,
        offset: u32,
        segment: u16,
        name: String,
        variant: BlockVariant,
    ) -> Self {
        Self {
            inner: AbstractBlock::new(parent_offset, end_offset, length, offset, segment, name),
            variant,
        }
    }

    /// Parse an S_BLOCK32 symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `parent_offset(u32) + end_offset(u32) + length(u32) + offset(u32) + segment(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        Self::parse_as(data, BlockVariant::Block32V2)
    }

    /// Parse with an explicit variant tag.
    pub fn parse_as(data: &[u8], variant: BlockVariant) -> Option<Self> {
        let inner = AbstractBlock::parse(data)?;
        Some(Self { inner, variant })
    }

    /// Parse an S_BLOCK32 symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    ///
    /// This matches the Java `reader.align4()` call after parsing.
    pub fn parse_aligned(data: &[u8]) -> Option<(Self, usize)> {
        Self::parse_aligned_as(data, BlockVariant::Block32V2)
    }

    /// Parse with alignment and an explicit variant tag.
    pub fn parse_aligned_as(data: &[u8], variant: BlockVariant) -> Option<(Self, usize)> {
        let (inner, consumed) = AbstractBlock::parse_aligned(data)?;
        Some((Self { inner, variant }, consumed))
    }

    /// Return the variant of this block symbol.
    pub fn variant(&self) -> BlockVariant {
        self.variant
    }

    /// Return the offset of the enclosing parent scope.
    pub fn parent_offset(&self) -> u32 {
        self.inner.parent_offset
    }

    /// Return the offset where this block ends.
    pub fn end_offset(&self) -> u32 {
        self.inner.end_offset
    }

    /// Return the length of the block in bytes.
    pub fn length(&self) -> u32 {
        self.inner.length
    }

    /// Return the offset of the block within its segment.
    pub fn block_offset(&self) -> u32 {
        self.inner.offset
    }

    /// Compute the byte size of this block from its start to end offset.
    ///
    /// Returns `None` if `end_offset <= block_offset` (degenerate range).
    pub fn byte_size(&self) -> Option<u32> {
        if self.inner.end_offset >= self.inner.offset {
            Some(self.inner.end_offset - self.inner.offset)
        } else {
            None
        }
    }

    /// Return `true` if this is an anonymous block (empty name).
    pub fn is_anonymous(&self) -> bool {
        self.inner.name.is_empty()
    }
}

impl AbstractMsSymbol for SBlock32 {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            BlockVariant::Block32 => super::super::symbol_kind::S_BLOCK32,
            BlockVariant::Block32V2 => super::super::symbol_kind::S_BLOCK32_V2,
            BlockVariant::Block32St => 0x1114, // S_BLOCK32_ST (if defined)
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            BlockVariant::Block32St => "S_BLOCK32_ST",
            _ => "S_BLOCK32",
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BLOCK32: [{:04X}:{:08X}], Length: {:08X}, {}\n   Parent: {:08X}, End: {:08X}",
            self.inner.segment, self.inner.offset, self.inner.length, self.inner.name,
            self.inner.parent_offset, self.inner.end_offset
        )
    }
}

impl AddressMsSymbol for SBlock32 {
    fn offset(&self) -> u64 {
        self.inner.offset as u64
    }

    fn segment(&self) -> u16 {
        self.inner.segment
    }
}

impl NameMsSymbol for SBlock32 {
    fn name(&self) -> &str {
        &self.inner.name
    }
}

impl fmt::Display for SBlock32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block32_bytes(
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
        let data = make_block32_bytes(0x1000, 0x2000, 0x100, 0x50, 1, b"scope");
        let sym = SBlock32::parse(&data).unwrap();
        assert_eq!(sym.parent_offset(), 0x1000);
        assert_eq!(sym.end_offset(), 0x2000);
        assert_eq!(sym.length(), 0x100);
        assert_eq!(sym.block_offset(), 0x50);
        assert_eq!(sym.inner.segment, 1);
        assert_eq!(sym.name(), "scope");
        assert_eq!(sym.variant(), BlockVariant::Block32V2);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SBlock32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_anonymous_block() {
        let data = make_block32_bytes(0, 0x100, 0x100, 0, 2, b"");
        let sym = SBlock32::parse(&data).unwrap();
        assert_eq!(sym.name(), "");
        assert!(sym.is_anonymous());
    }

    #[test]
    fn test_parse_aligned() {
        // name "ab" = 2 chars + 1 null = 3 bytes, 18+3=21, aligned to 24
        let data = make_block32_bytes(0x1000, 0x2000, 0x100, 0x50, 1, b"ab");
        let (sym, consumed) = SBlock32::parse_aligned(&data).unwrap();
        assert_eq!(sym.name(), "ab");
        assert_eq!(consumed, 24);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SBlock32::new(0x1000, 0x2000, 0x100, 0x50, 1, "my_block".to_string());
        assert_eq!(sym.pdb_id(), 0x1103);
        assert_eq!(sym.symbol_type_name(), "S_BLOCK32");
        assert_eq!(sym.name(), "my_block");
        assert_eq!(sym.parent_offset(), 0x1000);
        assert_eq!(sym.end_offset(), 0x2000);
        assert_eq!(sym.length(), 0x100);
        assert_eq!(sym.block_offset(), 0x50);
    }

    #[test]
    fn test_display() {
        let sym = SBlock32::new(0x1000, 0x2000, 0x100, 0x50, 1, "scope".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("BLOCK32"));
        assert!(s.contains("scope"));
        assert!(s.contains("Parent"));
        assert!(s.contains("End"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SBlock32::new(0x1000, 0x2000, 0x100, 0x50, 3, "b".to_string());
        assert_eq!(sym.segment(), 3);
        assert_eq!(sym.offset(), 0x50);
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x50);
    }

    #[test]
    fn test_clone_eq() {
        let a = SBlock32::new(0x100, 0x200, 0x100, 0x50, 1, "a".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_variant_block32() {
        let sym = SBlock32::with_variant(
            0x100, 0x200, 0x100, 0x50, 1, "b".to_string(),
            BlockVariant::Block32,
        );
        assert_eq!(sym.pdb_id(), 0x0207);
        assert_eq!(sym.variant(), BlockVariant::Block32);
    }

    #[test]
    fn test_variant_block32_v2() {
        let sym = SBlock32::new(0x100, 0x200, 0x100, 0x50, 1, "b".to_string());
        assert_eq!(sym.pdb_id(), 0x1103);
        assert_eq!(sym.variant(), BlockVariant::Block32V2);
    }

    #[test]
    fn test_byte_size() {
        let sym = SBlock32::new(0x1000, 0x2000, 0x100, 0x50, 1, "b".to_string());
        // end_offset(0x2000) - block_offset(0x50) = 0x1FB0
        assert_eq!(sym.byte_size(), Some(0x1FB0));
    }

    #[test]
    fn test_byte_size_degenerate() {
        let sym = SBlock32::new(0x1000, 0x0010, 0x100, 0x50, 1, "b".to_string());
        assert_eq!(sym.byte_size(), None);
    }

    #[test]
    fn test_is_anonymous_false() {
        let sym = SBlock32::new(0x100, 0x200, 0x100, 0x50, 1, "named".to_string());
        assert!(!sym.is_anonymous());
    }

    #[test]
    fn test_parse_as_variant() {
        let data = make_block32_bytes(0x100, 0x200, 0x100, 0x50, 1, b"b");
        let sym = SBlock32::parse_as(&data, BlockVariant::Block32).unwrap();
        assert_eq!(sym.variant(), BlockVariant::Block32);
        assert_eq!(sym.pdb_id(), 0x0207);
    }
}
