//! S_BPREL32 -- Base pointer relative symbol (32-bit).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.BasePointerRelative32MsSymbol`.

use std::fmt;

use super::abstract_base_pointer_relative::AbstractBasePointerRelative;
use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::RecordNumber;

/// A base pointer relative symbol (`S_BPREL32`).
///
/// This symbol describes a local variable or parameter whose address is
/// computed as a signed offset from the base/frame pointer register (e.g.,
/// `EBP` on x86). It is the 32-bit, NT-string flavor of the base-pointer-
/// relative symbol family.
///
/// Internally this wraps [`AbstractBasePointerRelative`] which holds the
/// shared fields (offset, type record number, name).
///
/// # PDB Binary Layout
///
/// ```text
/// offset       : i32
/// type_record  : u32
/// name         : NT string
/// ```
///
/// This corresponds to `S_BPREL32` (0x0200) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SBpRel32 {
    /// The underlying base-pointer-relative data.
    pub inner: AbstractBasePointerRelative,
}

impl SBpRel32 {
    /// Create a new S_BPREL32 symbol.
    pub fn new(type_record_number: RecordNumber, offset: i32, name: String) -> Self {
        Self {
            inner: AbstractBasePointerRelative::new(type_record_number, offset, name),
        }
    }

    /// Parse an S_BPREL32 symbol from a byte slice.
    ///
    /// Expects the layout: `offset(i32) + type_record(u32) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let inner = AbstractBasePointerRelative::parse(data)?;
        Some(Self { inner })
    }

    /// Return the signed offset from the base pointer.
    pub fn offset(&self) -> i32 {
        self.inner.offset
    }

    /// Return the type record number describing this variable's type.
    pub fn type_record_number(&self) -> &RecordNumber {
        &self.inner.type_record_number
    }
}

impl AbstractMsSymbol for SBpRel32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_BPREL32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_BPREL32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BpRel32: Offset: {}, Type: {}, {}",
            self.inner.offset, self.inner.type_record_number, self.inner.name
        )
    }
}

impl NameMsSymbol for SBpRel32 {
    fn name(&self) -> &str {
        &self.inner.name
    }
}

impl fmt::Display for SBpRel32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_bprel32_bytes(offset: i32, type_index: u32, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&type_index.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_bprel32_bytes(-4, 0x1020, b"local_x");
        let sym = SBpRel32::parse(&data).unwrap();
        assert_eq!(sym.offset(), -4);
        assert_eq!(sym.type_record_number().number(), 0x1020);
        assert_eq!(sym.name(), "local_x");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SBpRel32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let data = make_bprel32_bytes(8, 0x1000, b"");
        let sym = SBpRel32::parse(&data).unwrap();
        assert_eq!(sym.offset(), 8);
        assert_eq!(sym.name(), "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            -8,
            "param1".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x0200);
        assert_eq!(sym.symbol_type_name(), "S_BPREL32");
        assert_eq!(sym.name(), "param1");
        assert_eq!(sym.offset(), -8);
    }

    #[test]
    fn test_display() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            12,
            "arg0".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("BpRel32"));
        assert!(s.contains("12"));
        assert!(s.contains("arg0"));
    }

    #[test]
    fn test_negative_offset() {
        let data = make_bprel32_bytes(-16, 0x2000, b"buf");
        let sym = SBpRel32::parse(&data).unwrap();
        assert_eq!(sym.offset(), -16);
    }

    #[test]
    fn test_positive_offset() {
        let data = make_bprel32_bytes(4, 0x3000, b"ret_addr");
        let sym = SBpRel32::parse(&data).unwrap();
        assert_eq!(sym.offset(), 4);
        assert_eq!(sym.name(), "ret_addr");
    }
}
