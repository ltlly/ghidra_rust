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
/// # PDB Binary Layout (32-bit, NT strings)
///
/// ```text
/// type_index : u32
/// offset     : u32
/// segment    : u16
/// name       : NT string
/// ```
///
/// This corresponds to `S_GDATA32` (0x0202) and `S_GDATA32_ST` (0x1008) in the
/// CodeView symbol set. The `_ST` variant uses a 16-bit length-prefixed string
/// instead of a null-terminated string.
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
    /// Uses [`DataSymbolInternals::parse32`] for the 32-bit field layout with
    /// NT-format strings.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse32(data, 0, false)?;
        Some(Self { internals })
    }

    /// Parse an S_GDATA32_ST symbol from a byte slice.
    ///
    /// Uses [`DataSymbolInternals::parse32_st`] for the 32-bit field layout with
    /// ST-format (length-prefixed) strings.
    pub fn parse_st(data: &[u8]) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse32_st(data, 0, false)?;
        Some(Self { internals })
    }

    /// Parse an S_GDATA32 symbol with an emit token (managed metadata token).
    ///
    /// When `is_emit_token` is true, the type record number is treated as a
    /// .NET ECMA-335 metadata token rather than a standard PDB type index.
    pub fn parse_emit_token(data: &[u8]) -> Option<Self> {
        let (internals, _) = DataSymbolInternals::parse32(data, 0, true)?;
        Some(Self { internals })
    }

    /// Return `true` if the type record number is a managed metadata token.
    pub fn is_emit_token(&self) -> bool {
        self.internals.is_emit_token
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

    fn make_gdata32_st_bytes(type_idx: u32, offset: u32, segment: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_idx.to_le_bytes());
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);
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
    fn test_parse_empty_name() {
        let data = make_gdata32_bytes(0x1000, 0x100, 1, b"");
        let sym = SGData32::parse(&data).unwrap();
        assert_eq!(sym.internals.name, "");
        assert_eq!(sym.internals.offset, 0x100);
    }

    #[test]
    fn test_parse_st_basic() {
        let data = make_gdata32_st_bytes(0x1020, 0x3000, 3, b"st_global");
        let sym = SGData32::parse_st(&data).unwrap();
        assert_eq!(sym.internals.offset, 0x3000);
        assert_eq!(sym.internals.segment, 3);
        assert_eq!(sym.internals.name, "st_global");
        assert_eq!(sym.internals.type_record_number.number(), 0x1020);
    }

    #[test]
    fn test_parse_st_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SGData32::parse_st(&data).is_none());
    }

    #[test]
    fn test_parse_st_empty_name() {
        let data = make_gdata32_st_bytes(0x1000, 0x100, 1, b"");
        let sym = SGData32::parse_st(&data).unwrap();
        assert_eq!(sym.internals.name, "");
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

    #[test]
    fn test_is_emit_token() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x04000001),
            offset: 0x100,
            segment: 1,
            name: "token_var".to_string(),
            is_emit_token: true,
        };
        let sym = SGData32::new(internals);
        assert!(sym.is_emit_token());

        let internals2 = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1020),
            offset: 0x100,
            segment: 1,
            name: "normal_var".to_string(),
            is_emit_token: false,
        };
        let sym2 = SGData32::new(internals2);
        assert!(!sym2.is_emit_token());
    }

    #[test]
    fn test_display_emit_token() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x04000001),
            offset: 0x1000,
            segment: 1,
            name: "managed_var".to_string(),
            is_emit_token: true,
        };
        let sym = SGData32::new(internals);
        let s = format!("{}", sym);
        assert!(s.contains("Token"));
        assert!(s.contains("managed_var"));
    }

    #[test]
    fn test_clone_eq() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1020),
            offset: 0x2000,
            segment: 1,
            name: "clone_test".to_string(),
            is_emit_token: false,
        };
        let a = SGData32::new(internals);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
