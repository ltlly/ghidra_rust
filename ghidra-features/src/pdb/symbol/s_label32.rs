//! S_LABEL32 -- Label symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.Label32MsSymbol`,
//! `Label32StMsSymbol`, and `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ProcedureFlags`.
//!
//! A label symbol represents a code label (an address within a procedure or at
//! global scope) that has a name. Labels are used to mark targets of goto
//! statements and other jump targets.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

// ---------------------------------------------------------------------------
// ProcedureFlags -- mirrors Java ProcedureFlags
// ---------------------------------------------------------------------------

/// Procedure/label flags byte parsed from the PDB symbol stream.
///
/// This mirrors Ghidra's `ProcedureFlags` class. Each bit has a specific
/// meaning describing properties of the procedure or label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcedureFlags {
    /// Raw flag byte.
    byte: u8,
}

impl ProcedureFlags {
    /// Frame pointer is present.
    const HAS_FRAME_POINTER_PRESENT: u8 = 0x01;
    /// Function has an interrupt return.
    const HAS_INTERRUPT_RETURN: u8 = 0x02;
    /// Function has a far return.
    const HAS_FAR_RETURN: u8 = 0x04;
    /// Function does not return (e.g., `noreturn`).
    const DOES_NOT_RETURN: u8 = 0x08;
    /// Label is never reached.
    const LABEL_NOT_REACHED: u8 = 0x10;
    /// Function uses a custom calling convention.
    const HAS_CUSTOM_CALLING_CONVENTION: u8 = 0x20;
    /// Function is marked as `noinline`.
    const MARKED_AS_NO_INLINE: u8 = 0x40;
    /// Debug information is present for optimized code.
    const HAS_DEBUG_INFO_FOR_OPTIMIZED_CODE: u8 = 0x80;

    /// All function-related flag bits combined.
    ///
    /// This is used by [`has_function_indication`](Self::has_function_indication).
    const FUNCTION_INDICATION: u8 = Self::HAS_FRAME_POINTER_PRESENT
        | Self::HAS_INTERRUPT_RETURN
        | Self::HAS_FAR_RETURN
        | Self::DOES_NOT_RETURN
        | Self::LABEL_NOT_REACHED
        | Self::HAS_CUSTOM_CALLING_CONVENTION
        | Self::MARKED_AS_NO_INLINE
        | Self::HAS_DEBUG_INFO_FOR_OPTIMIZED_CODE;

    /// Create from a raw byte.
    pub fn new(byte: u8) -> Self {
        Self { byte }
    }

    /// Parse a ProcedureFlags from a byte slice, consuming one byte.
    ///
    /// Returns `None` if the slice is empty.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        Some(Self { byte: data[0] })
    }

    /// Return the raw flag byte.
    pub fn raw(&self) -> u8 {
        self.byte
    }

    /// Returns `true` if the frame pointer is present.
    pub fn has_frame_pointer_present(&self) -> bool {
        self.byte & Self::HAS_FRAME_POINTER_PRESENT != 0
    }

    /// Returns `true` if the function has an interrupt return.
    pub fn has_interrupt_return(&self) -> bool {
        self.byte & Self::HAS_INTERRUPT_RETURN != 0
    }

    /// Returns `true` if the function has a far return.
    pub fn has_far_return(&self) -> bool {
        self.byte & Self::HAS_FAR_RETURN != 0
    }

    /// Returns `true` if the function does not return.
    pub fn does_not_return(&self) -> bool {
        self.byte & Self::DOES_NOT_RETURN != 0
    }

    /// Returns `true` if the label is never reached.
    pub fn label_not_reached(&self) -> bool {
        self.byte & Self::LABEL_NOT_REACHED != 0
    }

    /// Returns `true` if the function uses a custom calling convention.
    pub fn has_custom_calling_convention(&self) -> bool {
        self.byte & Self::HAS_CUSTOM_CALLING_CONVENTION != 0
    }

    /// Returns `true` if the function is marked as `noinline`.
    pub fn marked_as_no_inline(&self) -> bool {
        self.byte & Self::MARKED_AS_NO_INLINE != 0
    }

    /// Returns `true` if debug information is present for optimized code.
    pub fn has_debug_info_for_optimized_code(&self) -> bool {
        self.byte & Self::HAS_DEBUG_INFO_FOR_OPTIMIZED_CODE != 0
    }

    /// Returns `true` if any procedure-related flag is set, suggesting the
    /// label is associated with a function.
    ///
    /// This is a Ghidra heuristic, not part of the PDB specification. It
    /// checks whether any of the 8 defined flag bits are set.
    pub fn has_function_indication(&self) -> bool {
        self.byte & Self::FUNCTION_INDICATION != 0
    }
}

impl fmt::Display for ProcedureFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flags: ")?;
        let mut first = true;
        let mut emit = |name: &str, val: bool, f: &mut fmt::Formatter<'_>| -> fmt::Result {
            if val {
                if !first {
                    write!(f, ", ")?;
                }
                write!(f, "{}", name)?;
                first = false;
            }
            Ok(())
        };
        emit("Frame Ptr Present", self.has_frame_pointer_present(), f)?;
        emit("Interrupt", self.has_interrupt_return(), f)?;
        emit("FAR", self.has_far_return(), f)?;
        emit("Never Return", self.does_not_return(), f)?;
        emit("Not Reached", self.label_not_reached(), f)?;
        emit("Custom Calling Convention", self.has_custom_calling_convention(), f)?;
        emit("Do Not Inline", self.marked_as_no_inline(), f)?;
        emit("Optimized Debug Info", self.has_debug_info_for_optimized_code(), f)?;
        Ok(())
    }
}

impl Default for ProcedureFlags {
    fn default() -> Self {
        Self { byte: 0 }
    }
}

// ---------------------------------------------------------------------------
// LabelVariant
// ---------------------------------------------------------------------------

/// Which variant of the label symbol was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelVariant {
    /// `S_LABEL32` (0x0209) -- 32-bit offset, NT string (v5 PDB).
    Label32,
    /// `S_LABEL32_V2` (0x1105) -- 32-bit offset, NT string (v7 PDB).
    Label32V2,
    /// `S_LABEL32_ST` -- 32-bit offset, ST string (16-bit length prefix).
    Label32St,
}

// ---------------------------------------------------------------------------
// SLabel32
// ---------------------------------------------------------------------------

/// A label symbol (`S_LABEL32`).
///
/// This symbol represents a code label (an address within a procedure or at
/// global scope) that has a name. Labels are used to mark targets of goto
/// statements and other jump targets.
///
/// # PDB Binary Layout (32-bit)
///
/// ```text
/// offset : u32
/// segment: u16
/// flags  : u8 (ProcedureFlags)
/// name   : NT string
/// ```
///
/// This corresponds to `S_LABEL32` (0x0209 / 0x1105) and `S_LABEL16`
/// (0x0109) in the CodeView symbol set. After the name the stream is
/// 4-byte aligned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLabel32 {
    /// Offset of the label within the segment.
    pub offset: u64,

    /// The PE section/segment containing this label.
    pub segment: u16,

    /// Parsed procedure/label flags.
    pub flags: ProcedureFlags,

    /// The label name.
    pub name: String,

    /// Which variant was parsed.
    variant: LabelVariant,
}

impl SLabel32 {
    /// Create a new label symbol (v7 / v2 variant).
    pub fn new(offset: u64, segment: u16, flags: ProcedureFlags, name: String) -> Self {
        Self {
            offset,
            segment,
            flags,
            name,
            variant: LabelVariant::Label32V2,
        }
    }

    /// Create a label symbol with a specific variant tag.
    pub fn with_variant(
        offset: u64,
        segment: u16,
        flags: ProcedureFlags,
        name: String,
        variant: LabelVariant,
    ) -> Self {
        Self {
            offset,
            segment,
            flags,
            name,
            variant,
        }
    }

    /// Parse an S_LABEL32 symbol from a byte slice.
    ///
    /// Expects the layout: `offset(u32) + segment(u16) + flags(u8) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        Self::parse_as(data, LabelVariant::Label32V2)
    }

    /// Parse with an explicit variant tag.
    pub fn parse_as(data: &[u8], variant: LabelVariant) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let segment = u16::from_le_bytes([data[4], data[5]]);
        let flags = ProcedureFlags::new(data[6]);
        let name = parse_nt_string(&data[7..]);
        Some(Self {
            offset,
            segment,
            flags,
            name,
            variant,
        })
    }

    /// Parse an S_LABEL32 symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    ///
    /// This matches the Java `reader.align4()` call after parsing.
    pub fn parse_aligned(data: &[u8]) -> Option<(Self, usize)> {
        Self::parse_aligned_as(data, LabelVariant::Label32V2)
    }

    /// Parse with alignment and an explicit variant tag.
    pub fn parse_aligned_as(data: &[u8], variant: LabelVariant) -> Option<(Self, usize)> {
        let sym = Self::parse_as(data, variant)?;
        let name_data = &data[7..];
        let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
        let name_len = end + 1; // include null terminator
        let total = 7 + name_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }

    /// Return the variant of this label symbol.
    pub fn variant(&self) -> LabelVariant {
        self.variant
    }

    /// Return `true` if the flags suggest this label is associated with a
    /// function (Ghidra heuristic).
    pub fn has_function_indication(&self) -> bool {
        self.flags.has_function_indication()
    }
}

impl AbstractMsSymbol for SLabel32 {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            LabelVariant::Label32 => super::super::symbol_kind::S_LABEL32,
            LabelVariant::Label32V2 => super::super::symbol_kind::S_LABEL32_V2,
            LabelVariant::Label32St => 0x1116, // S_LABEL32_ST (if defined)
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            LabelVariant::Label32St => "S_LABEL32_ST",
            _ => "S_LABEL32",
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LABEL32: [{:04X}:{:08X}], {} {}",
            self.segment, self.offset, self.name, self.flags
        )
    }
}

impl AddressMsSymbol for SLabel32 {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SLabel32 {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SLabel32 {
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

    fn make_label32_bytes(offset: u32, segment: u16, flags: u8, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.push(flags);
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    // --- ProcedureFlags tests ---

    #[test]
    fn test_procedure_flags_default() {
        let f = ProcedureFlags::default();
        assert_eq!(f.raw(), 0);
        assert!(!f.has_frame_pointer_present());
        assert!(!f.has_interrupt_return());
        assert!(!f.has_far_return());
        assert!(!f.does_not_return());
        assert!(!f.label_not_reached());
        assert!(!f.has_custom_calling_convention());
        assert!(!f.marked_as_no_inline());
        assert!(!f.has_debug_info_for_optimized_code());
        assert!(!f.has_function_indication());
    }

    #[test]
    fn test_procedure_flags_parse() {
        let data = [0x09u8];
        let f = ProcedureFlags::parse(&data).unwrap();
        assert_eq!(f.raw(), 0x09);
        assert!(f.has_frame_pointer_present());
        assert!(f.does_not_return());
    }

    #[test]
    fn test_procedure_flags_parse_empty() {
        let data: [u8; 0] = [];
        assert!(ProcedureFlags::parse(&data).is_none());
    }

    #[test]
    fn test_procedure_flags_individual_bits() {
        let f = ProcedureFlags::new(0x01);
        assert!(f.has_frame_pointer_present());
        assert!(!f.has_interrupt_return());

        let f = ProcedureFlags::new(0x02);
        assert!(f.has_interrupt_return());
        assert!(!f.has_frame_pointer_present());

        let f = ProcedureFlags::new(0x04);
        assert!(f.has_far_return());

        let f = ProcedureFlags::new(0x08);
        assert!(f.does_not_return());

        let f = ProcedureFlags::new(0x10);
        assert!(f.label_not_reached());

        let f = ProcedureFlags::new(0x20);
        assert!(f.has_custom_calling_convention());

        let f = ProcedureFlags::new(0x40);
        assert!(f.marked_as_no_inline());

        let f = ProcedureFlags::new(0x80);
        assert!(f.has_debug_info_for_optimized_code());
    }

    #[test]
    fn test_procedure_flags_combined() {
        let f = ProcedureFlags::new(0x09); // does_not_return | has_frame_pointer
        assert!(f.has_frame_pointer_present());
        assert!(f.does_not_return());
        assert!(!f.has_far_return());
        assert!(f.has_function_indication());
    }

    #[test]
    fn test_procedure_flags_display() {
        let f = ProcedureFlags::new(0x09);
        let s = format!("{}", f);
        assert!(s.contains("Frame Ptr Present"));
        assert!(s.contains("Never Return"));
    }

    // --- SLabel32 tests ---

    #[test]
    fn test_parse_basic() {
        let data = make_label32_bytes(0x2000, 1, 0, b"loop_top");
        let sym = SLabel32::parse(&data).unwrap();
        assert_eq!(sym.offset, 0x2000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.flags.raw(), 0);
        assert_eq!(sym.name, "loop_top");
        assert_eq!(sym.variant(), LabelVariant::Label32V2);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SLabel32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.push(0);
        data.push(0); // empty name

        let sym = SLabel32::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_with_flags() {
        let data = make_label32_bytes(0x3000, 2, 0x01, b"exit_label");
        let sym = SLabel32::parse(&data).unwrap();
        assert!(sym.flags.has_frame_pointer_present());
        assert_eq!(sym.name, "exit_label");
    }

    #[test]
    fn test_parse_aligned() {
        // name "ab" = 2 chars + 1 null = 3 bytes, 7+3=10, aligned to 12
        let data = make_label32_bytes(0x2000, 1, 0, b"ab");
        let (sym, consumed) = SLabel32::parse_aligned(&data).unwrap();
        assert_eq!(sym.name, "ab");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_trait_impls() {
        let flags = ProcedureFlags::new(0x00);
        let sym = SLabel32::new(0x2000, 1, flags, "L1".to_string());
        assert_eq!(sym.pdb_id(), 0x1105);
        assert_eq!(sym.symbol_type_name(), "S_LABEL32");
        assert_eq!(sym.name(), "L1");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_display() {
        let flags = ProcedureFlags::new(0x01);
        let sym = SLabel32::new(0x3000, 2, flags, "exit_label".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("LABEL32"));
        assert!(s.contains("exit_label"));
        assert!(s.contains("3000"));
        assert!(s.contains("Frame Ptr Present"));
    }

    #[test]
    fn test_address_trait() {
        let flags = ProcedureFlags::new(0x00);
        let sym = SLabel32::new(0x4000, 3, flags, "L2".to_string());
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x4000);
    }

    #[test]
    fn test_clone_eq() {
        let flags = ProcedureFlags::new(0x09);
        let a = SLabel32::new(0x100, 1, flags, "a".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_variant_label32() {
        let sym = SLabel32::with_variant(
            0x2000, 1, ProcedureFlags::new(0), "L".to_string(),
            LabelVariant::Label32,
        );
        assert_eq!(sym.pdb_id(), 0x0209);
        assert_eq!(sym.variant(), LabelVariant::Label32);
    }

    #[test]
    fn test_variant_label32_v2() {
        let sym = SLabel32::new(0x2000, 1, ProcedureFlags::new(0), "L".to_string());
        assert_eq!(sym.pdb_id(), 0x1105);
        assert_eq!(sym.variant(), LabelVariant::Label32V2);
    }

    #[test]
    fn test_has_function_indication() {
        let sym = SLabel32::new(
            0x2000, 1,
            ProcedureFlags::new(0x01), // frame pointer present
            "fn_label".to_string(),
        );
        assert!(sym.has_function_indication());

        let sym = SLabel32::new(
            0x2000, 1,
            ProcedureFlags::new(0x00), // no flags
            "plain".to_string(),
        );
        assert!(!sym.has_function_indication());
    }

    #[test]
    fn test_parse_as_variant() {
        let data = make_label32_bytes(0x2000, 1, 0, b"L");
        let sym = SLabel32::parse_as(&data, LabelVariant::Label32).unwrap();
        assert_eq!(sym.variant(), LabelVariant::Label32);
        assert_eq!(sym.pdb_id(), 0x0209);
    }
}
