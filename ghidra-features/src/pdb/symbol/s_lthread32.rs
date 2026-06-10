//! S_LTHREAD32 -- Local thread storage symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_LThread32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A local thread storage symbol (`S_LTHREAD32`).
///
/// This symbol describes a thread-local variable that is scoped to a single
/// compilation unit (file-local or function-static `__declspec(thread)` / C11
/// `_Thread_local` variable). Its layout is identical to
/// [`SGThread32`](self) (global thread storage); only the symbol kind
/// differs.
///
/// Thread storage variables are located via the TLS slot at a segment:offset
/// address, similar to regular data symbols but relative to the thread
/// environment block.
///
/// # PDB Binary Layout (32-bit)
///
/// ```text
/// type_index : u32
/// offset     : u32
/// segment    : u16
/// name       : NT string
/// ```
///
/// This corresponds to `S_LTHREAD32` (0x020D) and `S_LTHREAD32_ST` (0x100E)
/// in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLThread32 {
    /// The type record number for this thread storage variable.
    pub type_record_number: RecordNumber,

    /// Offset of the variable within the TLS data block.
    pub offset: u64,

    /// The PE section/segment for the TLS block.
    pub segment: u16,

    /// The variable name.
    pub name: String,
}

impl SLThread32 {
    /// Create a new local thread storage symbol.
    pub fn new(
        type_record_number: RecordNumber,
        offset: u64,
        segment: u16,
        name: String,
    ) -> Self {
        Self {
            type_record_number,
            offset,
            segment,
            name,
        }
    }

    /// Parse an S_LTHREAD32 symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `type_index(u32) + offset(u32) + segment(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
        let segment = u16::from_le_bytes([data[8], data[9]]);
        let name = parse_nt_string(&data[10..]);
        Some(Self {
            type_record_number: trn,
            offset,
            segment,
            name,
        })
    }
}

impl AbstractMsSymbol for SLThread32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_LTHREAD32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_LTHREAD32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LocalThreadStorage: [{:04X}:{:08X}], Type: {}, {}",
            self.segment, self.offset, self.type_record_number, self.name
        )
    }
}

impl AddressMsSymbol for SLThread32 {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SLThread32 {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SLThread32 {
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

    fn make_lthread32_bytes(type_idx: u32, offset: u32, segment: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_idx.to_le_bytes());
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_lthread32_bytes(0x1020, 0x100, 1, b"tls_var");
        let sym = SLThread32::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.offset, 0x100);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.name, "tls_var");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SLThread32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x50u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(0); // empty name

        let sym = SLThread32::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SLThread32::new(
            RecordNumber::type_record_number(0x1020),
            0x100,
            1,
            "errno".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x020D);
        assert_eq!(sym.symbol_type_name(), "S_LTHREAD32");
        assert_eq!(sym.name(), "errno");
        assert_eq!(sym.offset(), 0x100);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_display() {
        let sym = SLThread32::new(
            RecordNumber::type_record_number(0x1020),
            0x200,
            2,
            "thread_local_buf".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("LocalThreadStorage"));
        assert!(s.contains("thread_local_buf"));
        assert!(s.contains("0200"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SLThread32::new(
            RecordNumber::type_record_number(0x1020),
            0x300,
            3,
            "t".to_string(),
        );
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x300);
    }
}
