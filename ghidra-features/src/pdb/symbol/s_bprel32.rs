//! S_BPREL32 -- Base pointer relative symbol (32-bit).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.BasePointerRelative32MsSymbol`
//! and `BasePointerRelative32StMsSymbol`.
//!
//! # Binary Format
//!
//! The 32-bit base-pointer-relative symbol has the layout:
//!
//! ```text
//! offset       : i32       (signed offset from base/frame pointer)
//! type_record  : u32       (type index into TPI stream)
//! name         : NT string (null-terminated UTF-8)
//! ```
//!
//! After the name, the stream is 4-byte aligned (the `align4` step in Java).
//!
//! # Register
//!
//! On x86, the base pointer register is `EBP` (index 6). On x86-64 it is
//! `RBP` (index 33). The register is implicit -- determined by the
//! architecture, not stored in the record.

use std::fmt;

use super::abstract_base_pointer_relative::AbstractBasePointerRelative;
use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::RecordNumber;

/// Which variant of the base-pointer-relative symbol was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpRelVariant {
    /// `S_BPREL32` (0x0200) -- 32-bit offset, 32-bit type index, NT string (v5).
    BpRel32,
    /// `S_BPREL32_V2` (0x110B) -- 32-bit offset, 32-bit type index, NT string (v7).
    BpRel32V2,
    /// `S_BPREL32_ST` -- 32-bit offset, 32-bit type index, ST string.
    BpRel32St,
}

/// A base pointer relative symbol (`S_BPREL32`).
///
/// This symbol describes a local variable or parameter whose address is
/// computed as a signed offset from the base/frame pointer register (e.g.,
/// `EBP` on x86, `RBP` on x86-64). It is the 32-bit, NT-string flavor of
/// the base-pointer-relative symbol family.
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
/// This corresponds to `S_BPREL32` (0x0200 / 0x110B) in the CodeView
/// symbol set. After the name the stream is 4-byte aligned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SBpRel32 {
    /// The underlying base-pointer-relative data.
    pub inner: AbstractBasePointerRelative,

    /// Which variant was parsed.
    variant: BpRelVariant,
}

impl SBpRel32 {
    /// Create a new S_BPREL32 symbol (v7 / v2 variant).
    pub fn new(type_record_number: RecordNumber, offset: i32, name: String) -> Self {
        Self {
            inner: AbstractBasePointerRelative::new(type_record_number, offset, name),
            variant: BpRelVariant::BpRel32V2,
        }
    }

    /// Create an S_BPREL32 symbol with a specific variant tag.
    pub fn with_variant(
        type_record_number: RecordNumber,
        offset: i32,
        name: String,
        variant: BpRelVariant,
    ) -> Self {
        Self {
            inner: AbstractBasePointerRelative::new(type_record_number, offset, name),
            variant,
        }
    }

    /// Parse an S_BPREL32 symbol from a byte slice.
    ///
    /// Expects the layout: `offset(i32) + type_record(u32) + name(NT)`.
    /// The stream should be 4-byte aligned after the name (handled by the
    /// caller or via [`parse_aligned`](Self::parse_aligned)).
    pub fn parse(data: &[u8]) -> Option<Self> {
        Self::parse_as(data, BpRelVariant::BpRel32V2)
    }

    /// Parse with an explicit variant tag.
    pub fn parse_as(data: &[u8], variant: BpRelVariant) -> Option<Self> {
        let inner = AbstractBasePointerRelative::parse(data)?;
        Some(Self { inner, variant })
    }

    /// Parse an S_BPREL32 symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    ///
    /// This matches the Java `reader.align4()` call in
    /// `BasePointerRelative32MsSymbol`.
    pub fn parse_aligned(data: &[u8]) -> Option<(Self, usize)> {
        Self::parse_aligned_as(data, BpRelVariant::BpRel32V2)
    }

    /// Parse with alignment and an explicit variant tag.
    pub fn parse_aligned_as(data: &[u8], variant: BpRelVariant) -> Option<(Self, usize)> {
        let sym = Self::parse_as(data, variant)?;
        // Compute aligned consumed length:
        // offset(4) + type_record(4) + name_len + null terminator, aligned to 4
        let name_data = &data[8..];
        let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
        let name_len = end + 1; // include null terminator
        let total = 8 + name_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }

    /// Return the variant of this base-pointer-relative symbol.
    pub fn variant(&self) -> BpRelVariant {
        self.variant
    }

    /// Return the signed offset from the base pointer.
    pub fn offset(&self) -> i32 {
        self.inner.offset
    }

    /// Return the type record number describing this variable's type.
    pub fn type_record_number(&self) -> &RecordNumber {
        &self.inner.type_record_number
    }

    /// Return the name of the base pointer register for the given
    /// architecture.
    ///
    /// On x86 this is `"EBP"` (register index 6), on x86-64 this is
    /// `"RBP"` (register index 33). The register is implicit in the symbol
    /// record -- this helper returns the conventional name for the most
    /// common architectures.
    pub fn base_pointer_register_name(&self) -> &'static str {
        // The register is architecture-dependent and not stored in the
        // record. Return the conventional x86 name as a default.
        "EBP"
    }

    /// Compute the absolute address offset from the base pointer.
    ///
    /// Given a base pointer value, returns the address of this variable.
    /// This is a convenience for consumers that know the frame pointer
    /// value at runtime.
    pub fn address_from_frame_pointer(&self, frame_pointer: u64) -> u64 {
        (frame_pointer as i64 + self.inner.offset as i64) as u64
    }

    /// Return `true` if the offset is negative (i.e., the variable is above
    /// the frame pointer, typical for local variables).
    pub fn is_above_frame_pointer(&self) -> bool {
        self.inner.offset < 0
    }

    /// Return `true` if the offset is positive (i.e., the variable is below
    /// the frame pointer, typical for function parameters).
    pub fn is_below_frame_pointer(&self) -> bool {
        self.inner.offset > 0
    }

    /// Return `true` if the offset is zero (at the frame pointer itself).
    pub fn is_at_frame_pointer(&self) -> bool {
        self.inner.offset == 0
    }

    /// Return `true` if the variable has no type information.
    pub fn is_no_type(&self) -> bool {
        self.inner.type_record_number.is_no_type()
    }
}

impl AbstractMsSymbol for SBpRel32 {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            BpRelVariant::BpRel32 => super::super::symbol_kind::S_BPREL32,
            BpRelVariant::BpRel32V2 => super::super::symbol_kind::S_BPREL32_V2,
            BpRelVariant::BpRel32St => super::super::symbol_kind::S_BPREL32_ST,
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            BpRelVariant::BpRel32St => "S_BPREL32_ST",
            _ => "S_BPREL32",
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BPREL32: [{:+08X}], Type: {}, {}",
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
        assert_eq!(sym.variant(), BpRelVariant::BpRel32V2);
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
    fn test_parse_aligned() {
        // name "ab" = 2 chars + 1 null = 3 bytes, 8+3=11, aligned to 12
        let data = make_bprel32_bytes(-4, 0x1020, b"ab");
        let (sym, consumed) = SBpRel32::parse_aligned(&data).unwrap();
        assert_eq!(sym.offset(), -4);
        assert_eq!(sym.name(), "ab");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_aligned_already_aligned() {
        // name "abc" = 3 chars + 1 null = 4 bytes, 8+4=12, aligned to 12
        let data = make_bprel32_bytes(-4, 0x1020, b"abc");
        let (sym, consumed) = SBpRel32::parse_aligned(&data).unwrap();
        assert_eq!(sym.name(), "abc");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            -8,
            "param1".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x110B);
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
        assert!(s.contains("BPREL32"));
        assert!(s.contains("arg0"));
    }

    #[test]
    fn test_display_negative_offset() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            -8,
            "param".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("BPREL32"));
        assert!(s.contains("param"));
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

    #[test]
    fn test_base_pointer_register_name() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            -4,
            "x".to_string(),
        );
        assert_eq!(sym.base_pointer_register_name(), "EBP");
    }

    #[test]
    fn test_address_from_frame_pointer() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            -8,
            "local".to_string(),
        );
        // Frame pointer at 0x1000, offset -8 => address 0x0FF8
        assert_eq!(sym.address_from_frame_pointer(0x1000), 0x0FF8);
    }

    #[test]
    fn test_address_from_frame_pointer_positive() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            16,
            "arg".to_string(),
        );
        assert_eq!(sym.address_from_frame_pointer(0x2000), 0x2010);
    }

    #[test]
    fn test_clone_eq() {
        let a = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            -8,
            "x".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_variant_bprel32() {
        let sym = SBpRel32::with_variant(
            RecordNumber::type_record_number(0x1020),
            -4,
            "v".to_string(),
            BpRelVariant::BpRel32,
        );
        assert_eq!(sym.pdb_id(), 0x0200);
        assert_eq!(sym.variant(), BpRelVariant::BpRel32);
    }

    #[test]
    fn test_variant_bprel32_v2() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            -4,
            "v".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x110B);
        assert_eq!(sym.variant(), BpRelVariant::BpRel32V2);
    }

    #[test]
    fn test_is_above_frame_pointer() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            -8,
            "local".to_string(),
        );
        assert!(sym.is_above_frame_pointer());
        assert!(!sym.is_below_frame_pointer());
        assert!(!sym.is_at_frame_pointer());
    }

    #[test]
    fn test_is_below_frame_pointer() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            8,
            "param".to_string(),
        );
        assert!(!sym.is_above_frame_pointer());
        assert!(sym.is_below_frame_pointer());
        assert!(!sym.is_at_frame_pointer());
    }

    #[test]
    fn test_is_at_frame_pointer() {
        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            0,
            "fp".to_string(),
        );
        assert!(!sym.is_above_frame_pointer());
        assert!(!sym.is_below_frame_pointer());
        assert!(sym.is_at_frame_pointer());
    }

    #[test]
    fn test_is_no_type() {
        let sym = SBpRel32::new(
            RecordNumber::NO_TYPE,
            -4,
            "x".to_string(),
        );
        assert!(sym.is_no_type());

        let sym = SBpRel32::new(
            RecordNumber::type_record_number(0x1020),
            -4,
            "x".to_string(),
        );
        assert!(!sym.is_no_type());
    }

    #[test]
    fn test_parse_as_variant() {
        let data = make_bprel32_bytes(-4, 0x1020, b"v");
        let sym = SBpRel32::parse_as(&data, BpRelVariant::BpRel32).unwrap();
        assert_eq!(sym.variant(), BpRelVariant::BpRel32);
        assert_eq!(sym.pdb_id(), 0x0200);
    }
}
