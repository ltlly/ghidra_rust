//! S_GPROC32 -- Global procedure symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_GProc32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// Procedure flags defined by the CodeView specification.
///
/// These flags describe properties of a procedure symbol.
pub mod proc_flags {
    /// No flags set.
    pub const NONE: u8 = 0x00;

    /// The procedure does not return (e.g., `noreturn` functions like `abort`).
    pub const NO_RETURN: u8 = 0x01;

    /// The procedure is unreachable (dead code).
    pub const UNREACHABLE: u8 = 0x02;

    /// The procedure has no inline optimization.
    pub const NO_INLINE: u8 = 0x04;

    /// The procedure was optimized in some way.
    pub const OPTIMIZED: u8 = 0x08;
}

/// A global procedure symbol (`S_GPROC32`).
///
/// This symbol describes a global function/procedure in the PDB. It carries the
/// procedure's type index, debug range offsets, the procedure's entry point
/// address (segment:offset), flags, and the procedure name.
///
/// # PDB Binary Layout (32-bit)
///
/// ```text
/// type_index      : u32
/// parent          : u32
/// end             : u32
/// debug_start     : u32
/// debug_end       : u32
/// offset          : u32
/// segment         : u16
/// flags           : u8
/// name            : NT string
/// ```
///
/// This corresponds to `S_GPROC32` (0x0205) and `S_GPROC32_ST` (0x100B) in the
/// CodeView symbol set. The `_ST` variant uses a 16-bit length-prefixed string
/// instead of a null-terminated string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SGProc32 {
    /// The type record number for this procedure's signature.
    pub type_record_number: RecordNumber,

    /// Offset of the enclosing scope (parent block or procedure).
    pub parent: u32,

    /// Offset where this procedure's scope ends.
    pub end: u32,

    /// Offset of the first instruction with debug information.
    pub debug_start: u32,

    /// Offset of the last instruction with debug information.
    pub debug_end: u32,

    /// Offset of the procedure entry point within the segment.
    pub offset: u64,

    /// The PE section/segment containing this procedure.
    pub segment: u16,

    /// Procedure flags (see [`proc_flags`] constants).
    pub flags: u8,

    /// The procedure name.
    pub name: String,
}

impl SGProc32 {
    /// Create a new global procedure symbol.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        type_record_number: RecordNumber,
        parent: u32,
        end: u32,
        debug_start: u32,
        debug_end: u32,
        offset: u64,
        segment: u16,
        flags: u8,
        name: String,
    ) -> Self {
        Self {
            type_record_number,
            parent,
            end,
            debug_start,
            debug_end,
            offset,
            segment,
            flags,
            name,
        }
    }

    /// Parse an S_GPROC32 symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `type_index(u32) + parent(u32) + end(u32) + debug_start(u32) +
    /// debug_end(u32) + offset(u32) + segment(u16) + flags(u8) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 27 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let parent = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let end = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let debug_start = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let debug_end = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let offset = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as u64;
        let segment = u16::from_le_bytes([data[24], data[25]]);
        let flags = data[26];
        let name = parse_nt_string(&data[27..]);
        Some(Self {
            type_record_number: trn,
            parent,
            end,
            debug_start,
            debug_end,
            offset,
            segment,
            flags,
            name,
        })
    }

    /// Parse an S_GPROC32_ST symbol from a byte slice.
    ///
    /// Same layout as [`Self::parse`] but uses an ST-format (length-prefixed)
    /// string for the procedure name.
    pub fn parse_st(data: &[u8]) -> Option<Self> {
        if data.len() < 27 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let parent = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let end = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let debug_start = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let debug_end = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let offset = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as u64;
        let segment = u16::from_le_bytes([data[24], data[25]]);
        let flags = data[26];
        let name = parse_st_string(&data[27..]);
        Some(Self {
            type_record_number: trn,
            parent,
            end,
            debug_start,
            debug_end,
            offset,
            segment,
            flags,
            name,
        })
    }

    /// Return `true` if this procedure does not return.
    pub fn is_noreturn(&self) -> bool {
        self.flags & proc_flags::NO_RETURN != 0
    }

    /// Return `true` if this procedure is unreachable.
    pub fn is_unreachable(&self) -> bool {
        self.flags & proc_flags::UNREACHABLE != 0
    }

    /// Return `true` if this procedure has no inline optimization.
    pub fn is_no_inline(&self) -> bool {
        self.flags & proc_flags::NO_INLINE != 0
    }

    /// Return `true` if this procedure was optimized.
    pub fn is_optimized(&self) -> bool {
        self.flags & proc_flags::OPTIMIZED != 0
    }

    /// Return the size of the procedure in bytes (end - offset).
    pub fn size(&self) -> u32 {
        self.end.saturating_sub(self.offset as u32)
    }

    /// Return the debug range size in bytes (debug_end - debug_start).
    pub fn debug_range_size(&self) -> u32 {
        self.debug_end.saturating_sub(self.debug_start)
    }
}

impl AbstractMsSymbol for SGProc32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_GPROC32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_GPROC32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GlobalProcedure: [{:04X}:{:08X}], Type: {}, Debug: {:08X}..{:08X}, Parent: {:08X}, End: {:08X}, {}",
            self.segment, self.offset, self.type_record_number,
            self.debug_start, self.debug_end, self.parent, self.end, self.name
        )
    }
}

impl AddressMsSymbol for SGProc32 {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SGProc32 {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SGProc32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// Parse a null-terminated UTF-8 string from a byte slice.
fn parse_nt_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Parse an ST-format (16-bit length-prefixed) UTF-8 string from a byte slice.
fn parse_st_string(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let end = 2 + len;
    if end > data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&data[2..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_gproc32_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes()); // type_index
        data.extend_from_slice(&0u32.to_le_bytes());       // parent
        data.extend_from_slice(&0x200u32.to_le_bytes());   // end
        data.extend_from_slice(&0x10u32.to_le_bytes());    // debug_start
        data.extend_from_slice(&0x100u32.to_le_bytes());   // debug_end
        data.extend_from_slice(&0x1000u32.to_le_bytes());  // offset
        data.extend_from_slice(&1u16.to_le_bytes());       // segment
        data.push(0x00);                                    // flags
        data.extend_from_slice(b"main\0");                 // name
        data
    }

    fn make_gproc32_st_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes()); // type_index
        data.extend_from_slice(&0u32.to_le_bytes());       // parent
        data.extend_from_slice(&0x200u32.to_le_bytes());   // end
        data.extend_from_slice(&0x10u32.to_le_bytes());    // debug_start
        data.extend_from_slice(&0x100u32.to_le_bytes());   // debug_end
        data.extend_from_slice(&0x1000u32.to_le_bytes());  // offset
        data.extend_from_slice(&1u16.to_le_bytes());       // segment
        data.push(0x00);                                    // flags
        // ST-format string: length(2) + data
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(b"main");
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_gproc32_bytes();
        let sym = SGProc32::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.parent, 0);
        assert_eq!(sym.end, 0x200);
        assert_eq!(sym.debug_start, 0x10);
        assert_eq!(sym.debug_end, 0x100);
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.name, "main");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SGProc32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x200u32.to_le_bytes());
        data.extend_from_slice(&0x10u32.to_le_bytes());
        data.extend_from_slice(&0x100u32.to_le_bytes());
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(0x00); // flags
        data.push(0x00); // empty name (null terminator only)

        let sym = SGProc32::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_st_basic() {
        let data = make_gproc32_st_bytes();
        let sym = SGProc32::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.name, "main");
        assert_eq!(sym.offset, 0x1000);
    }

    #[test]
    fn test_parse_st_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SGProc32::parse_st(&data).is_none());
    }

    #[test]
    fn test_parse_st_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x200u32.to_le_bytes());
        data.extend_from_slice(&0x10u32.to_le_bytes());
        data.extend_from_slice(&0x100u32.to_le_bytes());
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(0x00); // flags
        data.extend_from_slice(&0u16.to_le_bytes()); // ST empty string (length=0)

        let sym = SGProc32::parse_st(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_flags_noreturn() {
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x200, 0x10, 0x100, 0x1000, 1,
            proc_flags::NO_RETURN,
            "abort".to_string(),
        );
        assert!(sym.is_noreturn());
        assert!(!sym.is_unreachable());
        assert!(!sym.is_no_inline());
        assert!(!sym.is_optimized());
    }

    #[test]
    fn test_flags_no_inline() {
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x200, 0x10, 0x100, 0x1000, 1,
            proc_flags::NO_INLINE,
            "noinline_func".to_string(),
        );
        assert!(sym.is_no_inline());
        assert!(!sym.is_noreturn());
    }

    #[test]
    fn test_flags_optimized() {
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x200, 0x10, 0x100, 0x1000, 1,
            proc_flags::OPTIMIZED,
            "fast_func".to_string(),
        );
        assert!(sym.is_optimized());
    }

    #[test]
    fn test_flags_combined() {
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x200, 0x10, 0x100, 0x1000, 1,
            proc_flags::NO_RETURN | proc_flags::OPTIMIZED,
            "abort_opt".to_string(),
        );
        assert!(sym.is_noreturn());
        assert!(sym.is_optimized());
        assert!(!sym.is_unreachable());
    }

    #[test]
    fn test_size() {
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x300, 0x10, 0x100, 0x100, 1, 0,
            "f".to_string(),
        );
        assert_eq!(sym.size(), 0x200); // 0x300 - 0x100
    }

    #[test]
    fn test_size_saturating() {
        // If end < offset (shouldn't happen, but test safety)
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x100, 0x10, 0x100, 0x200, 1, 0,
            "f".to_string(),
        );
        assert_eq!(sym.size(), 0); // saturating_sub prevents underflow
    }

    #[test]
    fn test_debug_range_size() {
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x200, 0x10, 0x100, 0x1000, 1, 0,
            "f".to_string(),
        );
        assert_eq!(sym.debug_range_size(), 0xF0); // 0x100 - 0x10
    }

    #[test]
    fn test_trait_impls() {
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x200, 0x10, 0x100, 0x1000, 1, 0, "my_func".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x0205);
        assert_eq!(sym.symbol_type_name(), "S_GPROC32");
        assert_eq!(sym.name(), "my_func");
        assert_eq!(sym.offset(), 0x1000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_display() {
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x200, 0x10, 0x100, 0x1000, 1, 0, "main".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("GlobalProcedure"));
        assert!(s.contains("main"));
        assert!(s.contains("1000"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x200, 0x10, 0x100, 0x1000, 2, 0, "f".to_string(),
        );
        assert_eq!(sym.flat_address(), (2u64 << 32) | 0x1000);
    }

    #[test]
    fn test_clone_eq() {
        let a = SGProc32::new(
            RecordNumber::type_record_number(0x1020),
            0, 0x200, 0x10, 0x100, 0x1000, 1, 0, "clone_test".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
