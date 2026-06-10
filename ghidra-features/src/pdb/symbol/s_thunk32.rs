//! S_THUNK32, S_THUNK16, and S_THUNK32_ST -- Thunk symbol variants.
//!
//! Ports Ghidra's:
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractThunkMsSymbol` (base)
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.Thunk32MsSymbol` (0x1102)
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.Thunk16MsSymbol` (0x0106)
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.Thunk32StMsSymbol` (0x0206)

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// Thunk ordinal type matching Ghidra's `AbstractThunkMsSymbol.Ordinal`.
///
/// The ordinal determines the kind of thunk and controls how variant data
/// is parsed and interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThunkOrdinal {
    /// No type (standard thunk).
    NoType,
    /// Adjustor thunk -- adjusts `this` pointer before forwarding.
    Adjustor,
    /// Virtual call thunk -- dispatches through a vtable.
    VCall,
    /// P-code thunk (ordinal 3).
    PCode,
    /// Load thunk (ordinal 4).
    Load,
    /// Incremental linking trampoline (ordinal 5).
    TrampolineIncremental,
    /// Branch island trampoline (ordinal 6).
    TrampolineBranchIsland,
    /// Unknown/unsupported thunk ordinal.
    Unknown(u8),
}

impl ThunkOrdinal {
    /// Decode a thunk ordinal from a raw byte value.
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::NoType,
            1 => Self::Adjustor,
            2 => Self::VCall,
            3 => Self::PCode,
            4 => Self::Load,
            5 => Self::TrampolineIncremental,
            6 => Self::TrampolineBranchIsland,
            other => Self::Unknown(other),
        }
    }

    /// Return the human-readable label for this ordinal.
    pub fn label(&self) -> &'static str {
        match self {
            Self::NoType => "",
            Self::Adjustor => "Type: Adjustor",
            Self::VCall => "Type: VCall",
            Self::PCode => "Type: 03",
            Self::Load => "Type: 04",
            Self::TrampolineIncremental => "Type: 05",
            Self::TrampolineBranchIsland => "Type: 06",
            Self::Unknown(_) => "Type: Unknown",
        }
    }

    /// Return the raw ordinal value.
    pub fn value(&self) -> u8 {
        match self {
            Self::NoType => 0,
            Self::Adjustor => 1,
            Self::VCall => 2,
            Self::PCode => 3,
            Self::Load => 4,
            Self::TrampolineIncremental => 5,
            Self::TrampolineBranchIsland => 6,
            Self::Unknown(v) => *v,
        }
    }
}

impl fmt::Display for ThunkOrdinal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

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
/// parent          : u32
/// end             : u32
/// next            : u32
/// offset          : u32 (var-sized: 16 or 32)
/// segment         : u16
/// length          : u16
/// ordinal         : u8
/// name            : NT string
/// (variant fields): depends on ordinal, then align4
/// ```
///
/// This corresponds to `S_THUNK32` (0x1102) and `S_THUNK16` (0x0106) in the
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

    /// The thunk ordinal (decoded from the raw byte).
    pub ordinal: ThunkOrdinal,

    /// The thunk name.
    pub name: String,

    /// Variant integer value (meaning depends on `ordinal`).
    ///
    /// For `Adjustor` thunks this is the delta. For `VCall` thunks this is
    /// the vtable entry index. For other types this is 0.
    pub variant: u16,

    /// Variant string (only meaningful for `Adjustor` thunks, where it
    /// contains the target function name).
    pub variant_string: String,
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
        ordinal: ThunkOrdinal,
        name: String,
        variant: u16,
        variant_string: String,
    ) -> Self {
        Self {
            parent,
            end,
            next,
            offset,
            segment,
            length,
            ordinal,
            name,
            variant,
            variant_string,
        }
    }

    /// Return the raw thunk type byte (convenience accessor).
    pub fn thunk_type(&self) -> u8 {
        self.ordinal.value()
    }

    /// Parse an S_THUNK32 symbol from a byte slice.
    ///
    /// Expects the layout:
    /// ```text
    /// parent(u32) + end(u32) + next(u32) + offset(u32) + segment(u16) +
    /// length(u16) + ordinal(u8) + name(NT) + variant fields (per ordinal) + align4
    /// ```
    ///
    /// Variant parsing per ordinal:
    /// - `ADJUSTOR`: variant(u16) + variant_string(NT)
    /// - `VCALL`: variant(u16)
    /// - All others: no variant data
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
        let ordinal = ThunkOrdinal::from_u8(data[20]);
        let name = parse_nt_string(&data[21..]);
        let mut pos = 21 + name.len() + 1; // +1 for null terminator

        let (variant, variant_string) = match ordinal {
            ThunkOrdinal::Adjustor => {
                // Adjustor: variant(u16) + variant_string(NT)
                if pos + 2 <= data.len() {
                    let v = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    let vs = parse_nt_string(&data[pos..]);
                    pos += vs.len() + 1;
                    (v, vs)
                } else {
                    (0, String::new())
                }
            }
            ThunkOrdinal::VCall => {
                // VCall: variant(u16)
                if pos + 2 <= data.len() {
                    let v = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    (v, String::new())
                } else {
                    (0, String::new())
                }
            }
            _ => (0, String::new()),
        };

        // Align to 4-byte boundary (matching Java's reader.align4())
        let _aligned_pos = (pos + 3) & !3;

        Some(Self {
            parent,
            end,
            next,
            offset,
            segment,
            length,
            ordinal,
            name,
            variant,
            variant_string,
        })
    }
}

impl AbstractMsSymbol for SThunk32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_THUNK32
    }

    fn symbol_type_name(&self) -> &'static str {
        "THUNK32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{}: [{:04X}:{:08X}], Length: {:08X}, {}",
            self.symbol_type_name(),
            self.segment,
            self.offset,
            self.length,
            self.name,
        )?;
        writeln!(
            f,
            "   Parent: {:08X}, End: {:08X}, Next: {:08X}",
            self.parent, self.end, self.next,
        )?;
        match self.ordinal {
            ThunkOrdinal::NoType => {}
            ThunkOrdinal::Adjustor => {
                writeln!(
                    f,
                    "   {}, Delta: {}, Target: {}",
                    self.ordinal, self.variant, self.variant_string,
                )?;
            }
            ThunkOrdinal::VCall => {
                writeln!(
                    f,
                    "   {}, Table Entry: {}",
                    self.ordinal, self.variant,
                )?;
            }
            _ => {
                writeln!(f, "   {}", self.ordinal)?;
            }
        }
        Ok(())
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

/// A 16-bit thunk symbol (`S_THUNK16`).
///
/// This symbol is the 16-bit offset variant of [`SThunk32`]. It uses 16-bit
/// offsets instead of 32-bit, and ST-format strings (length-prefixed) instead
/// of NT strings.
///
/// # PDB Binary Layout (16-bit)
///
/// ```text
/// parent          : u32
/// end             : u32
/// next            : u32
/// offset          : u16 (16-bit var-sized offset)
/// segment         : u16
/// length          : u16
/// ordinal         : u8
/// name            : ST string (length-prefixed UTF-8)
/// (variant fields): depends on ordinal, then align4
/// ```
///
/// This corresponds to `S_THUNK16` (0x0106) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SThunk16 {
    /// Offset of the enclosing scope (parent block or procedure).
    pub parent: u32,
    /// Offset where this thunk's scope ends.
    pub end: u32,
    /// Offset of the next thunk in the thunk chain (0 if last).
    pub next: u32,
    /// Offset of the thunk entry point within the segment (16-bit).
    pub offset: u64,
    /// The PE section/segment containing this thunk.
    pub segment: u16,
    /// Length of the thunk code in bytes.
    pub length: u16,
    /// The thunk ordinal (decoded from the raw byte).
    pub ordinal: ThunkOrdinal,
    /// The thunk name.
    pub name: String,
    /// Variant integer value (meaning depends on `ordinal`).
    pub variant: u16,
    /// Variant string (only meaningful for `Adjustor` thunks).
    pub variant_string: String,
}

impl SThunk16 {
    /// Create a new 16-bit thunk symbol.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: u32,
        end: u32,
        next: u32,
        offset: u64,
        segment: u16,
        length: u16,
        ordinal: ThunkOrdinal,
        name: String,
        variant: u16,
        variant_string: String,
    ) -> Self {
        Self {
            parent, end, next, offset, segment, length, ordinal, name, variant, variant_string,
        }
    }

    /// Parse an S_THUNK16 symbol from a byte slice.
    ///
    /// Uses 16-bit offset and ST-format (length-prefixed) strings.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 19 {
            return None;
        }
        let parent = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let next = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let offset = u16::from_le_bytes([data[12], data[13]]) as u64;
        let segment = u16::from_le_bytes([data[14], data[15]]);
        let length = u16::from_le_bytes([data[16], data[17]]);
        let ordinal = ThunkOrdinal::from_u8(data[18]);
        let (name, mut pos) = parse_st_string(&data[19..]);
        pos += 19;

        let (variant, variant_string) = match ordinal {
            ThunkOrdinal::Adjustor => {
                if pos + 2 <= data.len() {
                    let v = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    let (vs, vlen) = parse_st_string(&data[pos..]);
                    pos += vlen;
                    (v, vs)
                } else {
                    (0, String::new())
                }
            }
            ThunkOrdinal::VCall => {
                if pos + 2 <= data.len() {
                    let v = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    (v, String::new())
                } else {
                    (0, String::new())
                }
            }
            _ => (0, String::new()),
        };

        Some(Self {
            parent, end, next, offset, segment, length, ordinal, name, variant, variant_string,
        })
    }
}

impl AbstractMsSymbol for SThunk16 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_THUNK16
    }

    fn symbol_type_name(&self) -> &'static str {
        "THUNK16"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{}: [{:04X}:{:08X}], Length: {:08X}, {}",
            self.symbol_type_name(), self.segment, self.offset, self.length, self.name,
        )?;
        writeln!(
            f,
            "   Parent: {:08X}, End: {:08X}, Next: {:08X}",
            self.parent, self.end, self.next,
        )?;
        match self.ordinal {
            ThunkOrdinal::NoType => {}
            ThunkOrdinal::Adjustor => {
                writeln!(f, "   {}, Delta: {}, Target: {}", self.ordinal, self.variant, self.variant_string)?;
            }
            ThunkOrdinal::VCall => {
                writeln!(f, "   {}, Table Entry: {}", self.ordinal, self.variant)?;
            }
            _ => {
                writeln!(f, "   {}", self.ordinal)?;
            }
        }
        Ok(())
    }
}

impl AddressMsSymbol for SThunk16 {
    fn offset(&self) -> u64 { self.offset }
    fn segment(&self) -> u16 { self.segment }
}

impl NameMsSymbol for SThunk16 {
    fn name(&self) -> &str { &self.name }
}

impl fmt::Display for SThunk16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// A 32-bit ST-format thunk symbol (`S_THUNK32_ST`).
///
/// This symbol is identical to [`SThunk32`] in binary layout, but uses
/// ST-format strings (length-prefixed UTF-8) instead of null-terminated
/// strings, and has a different PDB ID.
///
/// This corresponds to `S_THUNK32_ST` (0x0206 / 0x1114) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SThunk32St {
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
    /// The thunk ordinal (decoded from the raw byte).
    pub ordinal: ThunkOrdinal,
    /// The thunk name.
    pub name: String,
    /// Variant integer value (meaning depends on `ordinal`).
    pub variant: u16,
    /// Variant string (only meaningful for `Adjustor` thunks).
    pub variant_string: String,
}

impl SThunk32St {
    /// Create a new ST-format 32-bit thunk symbol.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: u32,
        end: u32,
        next: u32,
        offset: u64,
        segment: u16,
        length: u16,
        ordinal: ThunkOrdinal,
        name: String,
        variant: u16,
        variant_string: String,
    ) -> Self {
        Self {
            parent, end, next, offset, segment, length, ordinal, name, variant, variant_string,
        }
    }

    /// Parse an S_THUNK32_ST symbol from a byte slice.
    ///
    /// Uses 32-bit offset and ST-format (length-prefixed) strings.
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
        let ordinal = ThunkOrdinal::from_u8(data[20]);
        let (name, mut pos) = parse_st_string(&data[21..]);
        pos += 21;

        let (variant, variant_string) = match ordinal {
            ThunkOrdinal::Adjustor => {
                if pos + 2 <= data.len() {
                    let v = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    let (vs, vlen) = parse_st_string(&data[pos..]);
                    pos += vlen;
                    (v, vs)
                } else {
                    (0, String::new())
                }
            }
            ThunkOrdinal::VCall => {
                if pos + 2 <= data.len() {
                    let v = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    (v, String::new())
                } else {
                    (0, String::new())
                }
            }
            _ => (0, String::new()),
        };

        Some(Self {
            parent, end, next, offset, segment, length, ordinal, name, variant, variant_string,
        })
    }
}

impl AbstractMsSymbol for SThunk32St {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_THUNK32
    }

    fn symbol_type_name(&self) -> &'static str {
        "THUNK32_ST"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{}: [{:04X}:{:08X}], Length: {:08X}, {}",
            self.symbol_type_name(), self.segment, self.offset, self.length, self.name,
        )?;
        writeln!(
            f,
            "   Parent: {:08X}, End: {:08X}, Next: {:08X}",
            self.parent, self.end, self.next,
        )?;
        match self.ordinal {
            ThunkOrdinal::NoType => {}
            ThunkOrdinal::Adjustor => {
                writeln!(f, "   {}, Delta: {}, Target: {}", self.ordinal, self.variant, self.variant_string)?;
            }
            ThunkOrdinal::VCall => {
                writeln!(f, "   {}, Table Entry: {}", self.ordinal, self.variant)?;
            }
            _ => {
                writeln!(f, "   {}", self.ordinal)?;
            }
        }
        Ok(())
    }
}

impl AddressMsSymbol for SThunk32St {
    fn offset(&self) -> u64 { self.offset }
    fn segment(&self) -> u16 { self.segment }
}

impl NameMsSymbol for SThunk32St {
    fn name(&self) -> &str { &self.name }
}

impl fmt::Display for SThunk32St {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// Parse a null-terminated UTF-8 string from a byte slice.
fn parse_nt_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Parse an ST-format (length-prefixed) string from a byte slice.
///
/// Returns the parsed string and the total number of bytes consumed
/// (including the 2-byte length prefix).
fn parse_st_string(data: &[u8]) -> (String, usize) {
    if data.len() < 2 {
        return (String::new(), 0);
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return (String::new(), 0);
    }
    let s = String::from_utf8_lossy(&data[2..2 + len]).to_string();
    (s, 2 + len)
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
        data.push(0);                                         // ordinal (NoType)
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
        assert_eq!(sym.ordinal, ThunkOrdinal::NoType);
        assert_eq!(sym.name, "__imp_main");
        assert_eq!(sym.variant, 0);
        assert!(sym.variant_string.is_empty());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SThunk32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_adjustor() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());         // parent
        data.extend_from_slice(&0x100u32.to_le_bytes());     // end
        data.extend_from_slice(&0u32.to_le_bytes());         // next
        data.extend_from_slice(&0x5000u32.to_le_bytes());    // offset
        data.extend_from_slice(&1u16.to_le_bytes());         // segment
        data.extend_from_slice(&10u16.to_le_bytes());        // length
        data.push(1);                                         // ordinal (Adjustor)
        data.extend_from_slice(b"adj_thunk\0");              // name
        data.extend_from_slice(&42u16.to_le_bytes());        // variant (delta)
        data.extend_from_slice(b"target_func\0");            // variant_string
        let sym = SThunk32::parse(&data).unwrap();
        assert_eq!(sym.ordinal, ThunkOrdinal::Adjustor);
        assert_eq!(sym.variant, 42);
        assert_eq!(sym.variant_string, "target_func");
    }

    #[test]
    fn test_parse_vcall() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());         // parent
        data.extend_from_slice(&0x100u32.to_le_bytes());     // end
        data.extend_from_slice(&0u32.to_le_bytes());         // next
        data.extend_from_slice(&0x5000u32.to_le_bytes());    // offset
        data.extend_from_slice(&1u16.to_le_bytes());         // segment
        data.extend_from_slice(&8u16.to_le_bytes());         // length
        data.push(2);                                         // ordinal (VCall)
        data.extend_from_slice(b"vcall\0");                  // name
        data.extend_from_slice(&7u16.to_le_bytes());         // variant (table entry)
        let sym = SThunk32::parse(&data).unwrap();
        assert_eq!(sym.ordinal, ThunkOrdinal::VCall);
        assert_eq!(sym.variant, 7);
        assert!(sym.variant_string.is_empty());
    }

    #[test]
    fn test_thunk_type_accessor() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 1, 6, ThunkOrdinal::Adjustor,
            "adj".to_string(), 10, "tgt".to_string(),
        );
        assert_eq!(sym.thunk_type(), 1);
    }

    #[test]
    fn test_ordinal_from_u8() {
        assert_eq!(ThunkOrdinal::from_u8(0), ThunkOrdinal::NoType);
        assert_eq!(ThunkOrdinal::from_u8(1), ThunkOrdinal::Adjustor);
        assert_eq!(ThunkOrdinal::from_u8(2), ThunkOrdinal::VCall);
        assert_eq!(ThunkOrdinal::from_u8(6), ThunkOrdinal::TrampolineBranchIsland);
        assert_eq!(ThunkOrdinal::from_u8(0xFF), ThunkOrdinal::Unknown(0xFF));
    }

    #[test]
    fn test_ordinal_labels() {
        assert_eq!(ThunkOrdinal::NoType.label(), "");
        assert_eq!(ThunkOrdinal::Adjustor.label(), "Type: Adjustor");
        assert_eq!(ThunkOrdinal::VCall.label(), "Type: VCall");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 1, 6, ThunkOrdinal::NoType,
            "thunk_func".to_string(), 0, String::new(),
        );
        assert_eq!(sym.pdb_id(), 0x0206);
        assert_eq!(sym.symbol_type_name(), "THUNK32");
        assert_eq!(sym.name(), "thunk_func");
        assert_eq!(sym.offset(), 0x5000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_display() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 1, 6, ThunkOrdinal::NoType,
            "__imp_foo".to_string(), 0, String::new(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("THUNK32"));
        assert!(s.contains("__imp_foo"));
        assert!(s.contains("5000"));
    }

    #[test]
    fn test_display_adjustor() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 1, 10, ThunkOrdinal::Adjustor,
            "adj".to_string(), 42, "target".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Adjustor"));
        assert!(s.contains("Delta: 42"));
        assert!(s.contains("target"));
    }

    #[test]
    fn test_display_vcall() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 1, 8, ThunkOrdinal::VCall,
            "vcall".to_string(), 7, String::new(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("VCall"));
        assert!(s.contains("Table Entry: 7"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SThunk32::new(
            0, 0x100, 0, 0x5000, 3, 6, ThunkOrdinal::NoType,
            "t".to_string(), 0, String::new(),
        );
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x5000);
    }

    // -- SThunk16 tests --

    fn make_thunk16_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());         // parent
        data.extend_from_slice(&0x100u32.to_le_bytes());     // end
        data.extend_from_slice(&0u32.to_le_bytes());         // next
        data.extend_from_slice(&0x2000u16.to_le_bytes());    // offset (16-bit)
        data.extend_from_slice(&1u16.to_le_bytes());         // segment
        data.extend_from_slice(&6u16.to_le_bytes());         // length
        data.push(0);                                         // ordinal (NoType)
        // ST-format string: length(2) + bytes
        let name = b"__imp_main";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);
        data
    }

    #[test]
    fn test_thunk16_parse_basic() {
        let data = make_thunk16_bytes();
        let sym = SThunk16::parse(&data).unwrap();
        assert_eq!(sym.parent, 0);
        assert_eq!(sym.end, 0x100);
        assert_eq!(sym.next, 0);
        assert_eq!(sym.offset, 0x2000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.length, 6);
        assert_eq!(sym.ordinal, ThunkOrdinal::NoType);
        assert_eq!(sym.name, "__imp_main");
    }

    #[test]
    fn test_thunk16_parse_truncated() {
        let data = [0x00, 0x01, 0x02];
        assert!(SThunk16::parse(&data).is_none());
    }

    #[test]
    fn test_thunk16_trait_impls() {
        let sym = SThunk16::new(
            0, 0x100, 0, 0x2000, 1, 6, ThunkOrdinal::NoType,
            "thunk16".to_string(), 0, String::new(),
        );
        assert_eq!(sym.pdb_id(), 0x0106);
        assert_eq!(sym.symbol_type_name(), "THUNK16");
        assert_eq!(sym.name(), "thunk16");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_thunk16_display() {
        let sym = SThunk16::new(
            0, 0x100, 0, 0x2000, 1, 6, ThunkOrdinal::NoType,
            "__imp_foo16".to_string(), 0, String::new(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("THUNK16"));
        assert!(s.contains("__imp_foo16"));
    }

    #[test]
    fn test_thunk16_address_trait() {
        let sym = SThunk16::new(
            0, 0x100, 0, 0x2000, 3, 6, ThunkOrdinal::NoType,
            "t".to_string(), 0, String::new(),
        );
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x2000);
    }

    // -- SThunk32St tests --

    fn make_thunk32_st_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());         // parent
        data.extend_from_slice(&0x100u32.to_le_bytes());     // end
        data.extend_from_slice(&0u32.to_le_bytes());         // next
        data.extend_from_slice(&0x5000u32.to_le_bytes());    // offset
        data.extend_from_slice(&1u16.to_le_bytes());         // segment
        data.extend_from_slice(&6u16.to_le_bytes());         // length
        data.push(0);                                         // ordinal (NoType)
        // ST-format string: length(2) + bytes
        let name = b"__imp_main_st";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);
        data
    }

    #[test]
    fn test_thunk32_st_parse_basic() {
        let data = make_thunk32_st_bytes();
        let sym = SThunk32St::parse(&data).unwrap();
        assert_eq!(sym.parent, 0);
        assert_eq!(sym.end, 0x100);
        assert_eq!(sym.offset, 0x5000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.ordinal, ThunkOrdinal::NoType);
        assert_eq!(sym.name, "__imp_main_st");
    }

    #[test]
    fn test_thunk32_st_parse_truncated() {
        let data = [0x00, 0x01, 0x02];
        assert!(SThunk32St::parse(&data).is_none());
    }

    #[test]
    fn test_thunk32_st_trait_impls() {
        let sym = SThunk32St::new(
            0, 0x100, 0, 0x5000, 1, 6, ThunkOrdinal::NoType,
            "thunk32st".to_string(), 0, String::new(),
        );
        assert_eq!(sym.pdb_id(), 0x0206);
        assert_eq!(sym.symbol_type_name(), "THUNK32_ST");
        assert_eq!(sym.name(), "thunk32st");
    }

    #[test]
    fn test_thunk32_st_display() {
        let sym = SThunk32St::new(
            0, 0x100, 0, 0x5000, 1, 8, ThunkOrdinal::VCall,
            "vcall_st".to_string(), 5, String::new(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("THUNK32_ST"));
        assert!(s.contains("VCall"));
        assert!(s.contains("Table Entry: 5"));
    }

    // -- parse_st_string tests --

    #[test]
    fn test_parse_st_string() {
        let mut data = Vec::new();
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(b"hello");
        let (s, consumed) = parse_st_string(&data);
        assert_eq!(s, "hello");
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_parse_st_string_empty() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes());
        let (s, consumed) = parse_st_string(&data);
        assert_eq!(s, "");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_parse_st_string_too_short() {
        let data = [0x05]; // only 1 byte, need at least 2 for length
        let (s, consumed) = parse_st_string(&data);
        assert_eq!(s, "");
        assert_eq!(consumed, 0);
    }
}
