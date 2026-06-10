//! S_GPROCIA64 -- Global procedure symbol (IA-64).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.GlobalProcedureStartIa64MsSymbol`
//! (0x1119) and `GlobalProcedureStartIa64StMsSymbol` (0x1016), both backed by
//! `AbstractProcedureStartIa64MsSymbol`.
//!
//! # Binary Format (IA-64 Procedure Start)
//!
//! ```text
//! parent            : u32
//! end               : u32
//! next              : u32
//! procedure_length  : u32
//! debug_start       : u32
//! debug_end         : u32
//! type_index        : u32  (RecordNumber)
//! offset            : u32
//! segment           : u16
//! return_register   : u16  (CV register index for return value)
//! flags             : u8   (ProcedureFlags)
//! name              : NT string
//! ```
//!
//! This layout matches the Java `AbstractProcedureStartIa64MsSymbol` constructor.
//! The Ms variant (0x1119) uses a UTF-8 NT string; the St variant (0x1016) uses
//! an ST-format string. Both share the same field layout.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};
use super::s_label32::ProcedureFlags;

/// A global procedure symbol for IA-64 (`S_GPROCIA64`).
///
/// This symbol describes a global function/procedure compiled for the Intel
/// IA-64 (Itanium) architecture. It carries additional fields compared to the
/// 32-bit proc variants: `next` (linked-list pointer), `procedure_length`,
/// `return_register` (CV register containing the return value), and
/// `procedure_flags`.
///
/// # PDB Binary Layout
///
/// ```text
/// parent            : u32
/// end               : u32
/// next              : u32
/// procedure_length  : u32
/// debug_start       : u32
/// debug_end         : u32
/// type_index        : u32  (RecordNumber)
/// offset            : u32
/// segment           : u16
/// return_register   : u16
/// flags             : u8   (ProcedureFlags)
/// name              : NT string
/// ```
///
/// This corresponds to `S_GPROCIA64` (0x1119) and `S_GPROCIA64_ST` (0x1016)
/// in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SGProcIA64 {
    /// Offset of the enclosing scope (parent block or procedure).
    pub parent: u32,

    /// Offset where this procedure's scope ends.
    pub end: u32,

    /// Offset to the next procedure (linked-list pointer).
    pub next: u32,

    /// Length of the procedure in bytes.
    pub procedure_length: u32,

    /// Offset of the first instruction with debug information.
    pub debug_start: u32,

    /// Offset of the last instruction with debug information.
    pub debug_end: u32,

    /// The type record number for this procedure's signature.
    pub type_record_number: RecordNumber,

    /// Offset of the procedure entry point within the segment.
    pub offset: u64,

    /// The PE section/segment containing this procedure.
    pub segment: u16,

    /// CV register index containing the return value.
    pub return_register: u16,

    /// Procedure flags.
    pub flags: ProcedureFlags,

    /// Whether this was parsed from the St format (0x1016).
    pub is_st_format: bool,

    /// The procedure name.
    pub name: String,
}

impl SGProcIA64 {
    /// Create a new IA-64 global procedure symbol.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: u32,
        end: u32,
        next: u32,
        procedure_length: u32,
        debug_start: u32,
        debug_end: u32,
        type_record_number: RecordNumber,
        offset: u64,
        segment: u16,
        return_register: u16,
        flags: ProcedureFlags,
        name: String,
    ) -> Self {
        Self {
            parent,
            end,
            next,
            procedure_length,
            debug_start,
            debug_end,
            type_record_number,
            offset,
            segment,
            return_register,
            flags,
            is_st_format: false,
            name,
        }
    }

    /// Parse an S_GPROCIA64 symbol from a byte slice (Ms format, 0x1119).
    ///
    /// Expects the layout:
    /// `parent(u32) + end(u32) + next(u32) + procedure_length(u32) +
    /// debug_start(u32) + debug_end(u32) + type_index(u32) + offset(u32) +
    /// segment(u16) + return_register(u16) + flags(u8) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        Self::parse_inner(data, false)
    }

    /// Parse an S_GPROCIA64_ST symbol from a byte slice (St format, 0x1016).
    ///
    /// Same binary layout as [`Self::parse`], but marks the symbol as St format.
    pub fn parse_st(data: &[u8]) -> Option<Self> {
        Self::parse_inner(data, true)
    }

    fn parse_inner(data: &[u8], is_st: bool) -> Option<Self> {
        // Minimum: 4*7 + 4 + 2 + 2 + 1 = 37 bytes (plus at least 1 for name)
        if data.len() < 37 {
            return None;
        }
        let parent = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let next = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let procedure_length = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let debug_start = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let debug_end = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let (trn, _) = RecordNumber::parse(data, 24, RecordCategory::Type, 32);
        let offset = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as u64;
        let segment = u16::from_le_bytes([data[32], data[33]]);
        let return_register = u16::from_le_bytes([data[34], data[35]]);
        let flags = ProcedureFlags::new(data[36]);
        let name = parse_nt_string(&data[37..]);
        Some(Self {
            parent,
            end,
            next,
            procedure_length,
            debug_start,
            debug_end,
            type_record_number: trn,
            offset,
            segment,
            return_register,
            flags,
            is_st_format: is_st,
            name,
        })
    }

    /// Return `true` if this procedure does not return.
    pub fn is_noreturn(&self) -> bool {
        self.flags.does_not_return()
    }

    /// Return `true` if this procedure has a frame pointer.
    pub fn has_frame_pointer(&self) -> bool {
        self.flags.has_frame_pointer_present()
    }

    /// Return `true` if this procedure has no inline optimization.
    pub fn is_no_inline(&self) -> bool {
        self.flags.marked_as_no_inline()
    }

    /// Return the size of the procedure in bytes.
    pub fn size(&self) -> u32 {
        self.procedure_length
    }

    /// Return the debug range size in bytes (debug_end - debug_start).
    pub fn debug_range_size(&self) -> u32 {
        self.debug_end.saturating_sub(self.debug_start)
    }
}

impl AbstractMsSymbol for SGProcIA64 {
    fn pdb_id(&self) -> u16 {
        if self.is_st_format {
            super::super::symbol_kind::S_GPROCIA64_ST
        } else {
            super::super::symbol_kind::S_GPROCIA64
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        if self.is_st_format {
            "S_GPROCIA64_ST"
        } else {
            "S_GPROCIA64"
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GlobalProcedureIA64: [{:04X}:{:08X}], Length: {:08X}, Type: {}, {}",
            self.segment, self.offset, self.procedure_length,
            self.type_record_number, self.name,
        )?;
        write!(
            f,
            "   Parent: {:08X}, End: {:08X}, Next: {:08X}",
            self.parent, self.end, self.next,
        )?;
        write!(
            f,
            "   Debug start: {:08X}, Debug end: {:08X}",
            self.debug_start, self.debug_end,
        )?;
        write!(f, "   {}", self.flags)?;
        write!(f, "   Return Reg: {}", self.return_register)
    }
}

impl AddressMsSymbol for SGProcIA64 {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SGProcIA64 {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SGProcIA64 {
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
    use super::super::record_number::RecordNumber;
    use super::super::s_label32::ProcedureFlags;

    fn make_gprocia64_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());              // parent
        data.extend_from_slice(&0x200u32.to_le_bytes());          // end
        data.extend_from_slice(&0u32.to_le_bytes());              // next
        data.extend_from_slice(&0x200u32.to_le_bytes());          // procedure_length
        data.extend_from_slice(&0x10u32.to_le_bytes());           // debug_start
        data.extend_from_slice(&0x100u32.to_le_bytes());          // debug_end
        data.extend_from_slice(&0x1020u32.to_le_bytes());         // type_index
        data.extend_from_slice(&0x1000u32.to_le_bytes());         // offset
        data.extend_from_slice(&1u16.to_le_bytes());              // segment
        data.extend_from_slice(&0u16.to_le_bytes());              // return_register
        data.push(0x00);                                          // flags
        data.extend_from_slice(b"main\0");                        // name
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_gprocia64_bytes();
        let sym = SGProcIA64::parse(&data).unwrap();
        assert_eq!(sym.parent, 0);
        assert_eq!(sym.end, 0x200);
        assert_eq!(sym.next, 0);
        assert_eq!(sym.procedure_length, 0x200);
        assert_eq!(sym.debug_start, 0x10);
        assert_eq!(sym.debug_end, 0x100);
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.return_register, 0);
        assert_eq!(sym.name, "main");
        assert!(!sym.is_st_format);
    }

    #[test]
    fn test_parse_st() {
        let data = make_gprocia64_bytes();
        let sym = SGProcIA64::parse_st(&data).unwrap();
        assert_eq!(sym.name, "main");
        assert!(sym.is_st_format);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SGProcIA64::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SGProcIA64::new(
            0, 0x200, 0, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 0, ProcedureFlags::default(), "ia64_func".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1119);
        assert_eq!(sym.symbol_type_name(), "S_GPROCIA64");
        assert_eq!(sym.name(), "ia64_func");
        assert_eq!(sym.offset(), 0x1000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_trait_impls_st() {
        let sym = SGProcIA64::new(
            0, 0x200, 0, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 0, ProcedureFlags::default(), "main".to_string(),
        );
        let mut sym = sym;
        sym.is_st_format = true;
        assert_eq!(sym.pdb_id(), 0x1016);
        assert_eq!(sym.symbol_type_name(), "S_GPROCIA64_ST");
    }

    #[test]
    fn test_display() {
        let sym = SGProcIA64::new(
            0, 0x200, 0, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 0, ProcedureFlags::default(), "main".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("GlobalProcedureIA64"));
        assert!(s.contains("main"));
        assert!(s.contains("1000"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SGProcIA64::new(
            0, 0x200, 0, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 2, 0, ProcedureFlags::default(), "f".to_string(),
        );
        assert_eq!(sym.flat_address(), (2u64 << 32) | 0x1000);
    }

    #[test]
    fn test_noreturn_flag() {
        let flags = ProcedureFlags::new(0x08); // DOES_NOT_RETURN
        let sym = SGProcIA64::new(
            0, 0x200, 0, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 0, flags, "abort".to_string(),
        );
        assert!(sym.is_noreturn());
        assert!(!sym.has_frame_pointer());
    }

    #[test]
    fn test_frame_pointer_flag() {
        let flags = ProcedureFlags::new(0x01); // HAS_FRAME_POINTER_PRESENT
        let sym = SGProcIA64::new(
            0, 0x200, 0, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 0, flags, "fp_func".to_string(),
        );
        assert!(sym.has_frame_pointer());
        assert!(!sym.is_noreturn());
    }

    #[test]
    fn test_procedure_length() {
        let sym = SGProcIA64::new(
            0, 0x400, 0, 0x400, 0x10, 0x200,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 0, ProcedureFlags::default(), "f".to_string(),
        );
        assert_eq!(sym.size(), 0x400);
    }

    #[test]
    fn test_debug_range_size() {
        let sym = SGProcIA64::new(
            0, 0x200, 0, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 0, ProcedureFlags::default(), "f".to_string(),
        );
        assert_eq!(sym.debug_range_size(), 0xF0);
    }

    #[test]
    fn test_next_pointer() {
        let sym = SGProcIA64::new(
            0, 0x200, 0x500, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 0, ProcedureFlags::default(), "f".to_string(),
        );
        assert_eq!(sym.next, 0x500);
    }

    #[test]
    fn test_return_register() {
        let sym = SGProcIA64::new(
            0, 0x200, 0, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 8, ProcedureFlags::default(), "f".to_string(),
        );
        assert_eq!(sym.return_register, 8);
    }

    #[test]
    fn test_clone_eq() {
        let a = SGProcIA64::new(
            0, 0x200, 0, 0x200, 0x10, 0x100,
            RecordNumber::type_record_number(0x1020),
            0x1000, 1, 0, ProcedureFlags::default(), "f".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
