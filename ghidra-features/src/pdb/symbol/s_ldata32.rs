//! S_LDATA32 -- Local data symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_LData32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::data_symbol_internals::DataSymbolInternals;
use super::name_ms_symbol::NameMsSymbol;

/// A local data symbol (`S_LDATA32`).
///
/// This symbol describes a file-scoped or function-scoped data variable located
/// at a segment:offset address. It delegates to [`DataSymbolInternals`] for the
/// shared fields, matching Ghidra's Java implementation.
///
/// This corresponds to `S_LDATA32` (0x0201) and `S_LDATA32_ST` (0x1007) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLData32 {
    /// Shared internal fields (type, offset, segment, name, emit-token flag).
    pub internals: DataSymbolInternals,
}

impl SLData32 {
    /// Create a new local data symbol.
    pub fn new(internals: DataSymbolInternals) -> Self {
        Self { internals }
    }

    /// Parse an S_LDATA32 symbol from a byte slice.
    ///
    /// Uses [`DataSymbolInternals::parse32`] for the field layout.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse32(data, 0, false)?;
        Some(Self { internals })
    }

    /// Parse an S_LDATA32 symbol with an emit token (managed metadata token).
    pub fn parse_emit_token(data: &[u8]) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse32(data, 0, true)?;
        Some(Self { internals })
    }
}

impl AbstractMsSymbol for SLData32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_LDATA32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_LDATA32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalData")?;
        self.internals.emit(f)
    }
}

impl AddressMsSymbol for SLData32 {
    fn offset(&self) -> u64 {
        self.internals.offset
    }

    fn segment(&self) -> u16 {
        self.internals.segment
    }
}

impl NameMsSymbol for SLData32 {
    fn name(&self) -> &str {
        &self.internals.name
    }
}

impl fmt::Display for SLData32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_ldata32_bytes(type_idx: u32, offset: u32, segment: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_idx.to_le_bytes());
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        // align to 4
        while data.len() % 4 != 0 {
            data.push(0);
        }
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_ldata32_bytes(0x1020, 0x2000, 2, b"local_var");
        let sym = SLData32::parse(&data).unwrap();
        assert_eq!(sym.internals.offset, 0x2000);
        assert_eq!(sym.internals.segment, 2);
        assert_eq!(sym.internals.name, "local_var");
        assert_eq!(sym.internals.type_record_number.number(), 0x1020);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SLData32::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1020),
            offset: 0x2000,
            segment: 2,
            name: "my_local".to_string(),
            is_emit_token: false,
        };
        let sym = SLData32::new(internals);
        assert_eq!(sym.pdb_id(), 0x0201);
        assert_eq!(sym.symbol_type_name(), "S_LDATA32");
        assert_eq!(sym.name(), "my_local");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 2);
    }

    #[test]
    fn test_display() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1020),
            offset: 0x3000,
            segment: 1,
            name: "x".to_string(),
            is_emit_token: false,
        };
        let sym = SLData32::new(internals);
        let s = format!("{}", sym);
        assert!(s.contains("LocalData"));
        assert!(s.contains("x"));
    }

    #[test]
    fn test_address_trait() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1020),
            offset: 0x1000,
            segment: 3,
            name: "v".to_string(),
            is_emit_token: false,
        };
        let sym = SLData32::new(internals);
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x1000);
    }
}
