//! S_GDATA32 -- Global data symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_GData32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::data_symbol_internals::DataSymbolInternals;
use super::name_ms_symbol::NameMsSymbol;

/// A global data symbol (`S_GDATA32`).
///
/// This symbol describes a globally-visible data variable located at a
/// segment:offset address. It delegates to [`DataSymbolInternals`] for the
/// shared fields, matching Ghidra's Java implementation.
///
/// This corresponds to `S_GDATA32` (0x0202) and `S_GDATA32_ST` (0x1008) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SGData32 {
    /// Shared internal fields (type, offset, segment, name, emit-token flag).
    pub internals: DataSymbolInternals,
}

impl SGData32 {
    /// Create a new global data symbol.
    pub fn new(internals: DataSymbolInternals) -> Self {
        Self { internals }
    }

    /// Parse an S_GDATA32 symbol from a byte slice.
    ///
    /// Uses [`DataSymbolInternals::parse32`] for the field layout.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse32(data, 0, false)?;
        Some(Self { internals })
    }

    /// Parse an S_GDATA32 symbol with an emit token (managed metadata token).
    pub fn parse_emit_token(data: &[u8]) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse32(data, 0, true)?;
        Some(Self { internals })
    }
}

impl AbstractMsSymbol for SGData32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_GDATA32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_GDATA32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GlobalData")?;
        self.internals.emit(f)
    }
}

impl AddressMsSymbol for SGData32 {
    fn offset(&self) -> u64 {
        self.internals.offset
    }

    fn segment(&self) -> u16 {
        self.internals.segment
    }
}

impl NameMsSymbol for SGData32 {
    fn name(&self) -> &str {
        &self.internals.name
    }
}

impl fmt::Display for SGData32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_gdata32_bytes(type_idx: u32, offset: u32, segment: u16, name: &[u8]) -> Vec<u8> {
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
        let data = make_gdata32_bytes(0x1020, 0x2000, 2, b"global_var");
        let sym = SGData32::parse(&data).unwrap();
        assert_eq!(sym.internals.offset, 0x2000);
        assert_eq!(sym.internals.segment, 2);
        assert_eq!(sym.internals.name, "global_var");
        assert_eq!(sym.internals.type_record_number.number(), 0x1020);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SGData32::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1020),
            offset: 0x2000,
            segment: 2,
            name: "my_global".to_string(),
            is_emit_token: false,
        };
        let sym = SGData32::new(internals);
        assert_eq!(sym.pdb_id(), 0x0202);
        assert_eq!(sym.symbol_type_name(), "S_GDATA32");
        assert_eq!(sym.name(), "my_global");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 2);
    }

    #[test]
    fn test_display() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1020),
            offset: 0x3000,
            segment: 1,
            name: "g_count".to_string(),
            is_emit_token: false,
        };
        let sym = SGData32::new(internals);
        let s = format!("{}", sym);
        assert!(s.contains("GlobalData"));
        assert!(s.contains("g_count"));
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
        let sym = SGData32::new(internals);
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x1000);
    }

    #[test]
    fn test_parse_emit_token() {
        let data = make_gdata32_bytes(0x1020, 0x2000, 1, b"managed");
        let sym = SGData32::parse_emit_token(&data).unwrap();
        assert!(sym.internals.is_emit_token);
        assert_eq!(sym.internals.name, "managed");
    }
}
