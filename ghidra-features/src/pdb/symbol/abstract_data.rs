//! AbstractData -- abstract base for data symbols.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractDataMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::data_symbol_internals::DataSymbolInternals;
use super::name_ms_symbol::NameMsSymbol;

/// Abstract base for PDB data symbols.
///
/// These symbols correspond to `S_GDATA16`, `S_LDATA16`, `S_GDATA32`,
/// `S_LDATA32`, `S_GDATA32_ST`, `S_LDATA32_ST`, `S_GMANDATA`, and
/// `S_LMANDATA` in the CodeView symbol set. They describe global and local
/// data variables located at a segment:offset address.
///
/// This struct delegates to [`DataSymbolInternals`] for the shared fields,
/// following the same pattern as Ghidra's Java implementation.
///
/// # Variants
///
/// - **Global data** (`S_GDATA32`, `S_GDATA16`, etc.) — Visible across
///   translation units.
/// - **Local data** (`S_LDATA32`, `S_LDATA16`, etc.) — File-scoped or
///   function-scoped variables.
/// - **Managed data** (`S_GMANDATA`, `S_LMANDATA`) — .NET metadata token
///   variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractData {
    /// Shared internal fields (type, offset, segment, name, emit-token flag).
    pub internals: DataSymbolInternals,

    /// Whether this is a global (true) or local (false) data symbol.
    pub is_global: bool,
}

impl AbstractData {
    /// Create a new data symbol.
    pub fn new(internals: DataSymbolInternals, is_global: bool) -> Self {
        Self { internals, is_global }
    }

    /// Parse a 32-bit data symbol from a byte slice.
    ///
    /// Uses [`DataSymbolInternals::parse32`] for the field layout.
    /// `is_global` selects between `S_GDATA32` and `S_LDATA32`.
    pub fn parse32(data: &[u8], is_global: bool, emit_token: bool) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse32(data, 0, emit_token)?;
        Some(Self { internals, is_global })
    }

    /// Parse a 16-bit data symbol from a byte slice.
    ///
    /// Uses [`DataSymbolInternals::parse16`] for the field layout.
    pub fn parse16(data: &[u8], is_global: bool, emit_token: bool) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse16(data, 0, emit_token)?;
        Some(Self { internals, is_global })
    }

    /// Parse a 3216 data symbol from a byte slice (32-bit offsets, 16-bit type indices).
    ///
    /// Uses [`DataSymbolInternals::parse3216`] for the field layout.
    pub fn parse3216(data: &[u8], is_global: bool, emit_token: bool) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse3216(data, 0, emit_token)?;
        Some(Self { internals, is_global })
    }

    /// Parse a 32ST data symbol from a byte slice (32-bit type indices, ST strings).
    ///
    /// Uses [`DataSymbolInternals::parse32_st`] for the field layout.
    pub fn parse32_st(data: &[u8], is_global: bool, emit_token: bool) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse32_st(data, 0, emit_token)?;
        Some(Self { internals, is_global })
    }
}

impl AbstractMsSymbol for AbstractData {
    fn pdb_id(&self) -> u16 {
        if self.is_global {
            super::super::symbol_kind::S_GDATA32
        } else {
            super::super::symbol_kind::S_LDATA32
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        if self.is_global {
            "S_GDATA32"
        } else {
            "S_LDATA32"
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = if self.is_global { "GlobalData" } else { "LocalData" };
        write!(f, "{}", prefix)?;
        self.internals.emit(f)
    }
}

impl AddressMsSymbol for AbstractData {
    fn offset(&self) -> u64 {
        self.internals.offset
    }

    fn segment(&self) -> u16 {
        self.internals.segment
    }
}

impl NameMsSymbol for AbstractData {
    fn name(&self) -> &str {
        &self.internals.name
    }
}

impl fmt::Display for AbstractData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::{RecordCategory, RecordNumber};

    fn make_data32_bytes(type_idx: u32, offset: u32, segment: u16, name: &[u8]) -> Vec<u8> {
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
    fn test_parse32_global() {
        let data = make_data32_bytes(0x1020, 0x1000, 1, b"myGlobal");
        let sym = AbstractData::parse32(&data, true, false).unwrap();
        assert!(sym.is_global);
        assert_eq!(sym.internals.offset, 0x1000);
        assert_eq!(sym.internals.segment, 1);
        assert_eq!(sym.internals.name, "myGlobal");
        assert_eq!(sym.internals.type_record_number.number(), 0x1020);
    }

    #[test]
    fn test_parse32_local() {
        let data = make_data32_bytes(0x1020, 0x2000, 2, b"local");
        let sym = AbstractData::parse32(&data, false, false).unwrap();
        assert!(!sym.is_global);
        assert_eq!(sym.pdb_id(), 0x0201); // S_LDATA32
    }

    #[test]
    fn test_parse32_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(AbstractData::parse32(&data, true, false).is_none());
    }

    #[test]
    fn test_address_trait() {
        let data = make_data32_bytes(0x1020, 0x1000, 1, b"var");
        let sym = AbstractData::parse32(&data, true, false).unwrap();
        assert_eq!(sym.offset(), 0x1000);
        assert_eq!(sym.segment(), 1);
        assert_eq!(sym.flat_address(), (1u64 << 32) | 0x1000);
    }

    #[test]
    fn test_name_trait() {
        let data = make_data32_bytes(0x1020, 0, 0, b"named");
        let sym = AbstractData::parse32(&data, true, false).unwrap();
        assert_eq!(sym.name(), "named");
    }

    #[test]
    fn test_display_global() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1020),
            offset: 0x1000,
            segment: 1,
            name: "g_var".to_string(),
            is_emit_token: false,
        };
        let sym = AbstractData::new(internals, true);
        let s = format!("{}", sym);
        assert!(s.contains("GlobalData"));
        assert!(s.contains("g_var"));
    }

    #[test]
    fn test_display_local() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1020),
            offset: 0x2000,
            segment: 2,
            name: "l_var".to_string(),
            is_emit_token: false,
        };
        let sym = AbstractData::new(internals, false);
        let s = format!("{}", sym);
        assert!(s.contains("LocalData"));
        assert!(s.contains("l_var"));
    }
}
