//! DataSymbolInternals -- internal data shared by data symbol variants.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DataSymbolInternals`.

use super::record_number::{RecordCategory, RecordNumber};
use super::string_parse_type::StringParseType;

/// Internal data fields shared by the various data symbol flavors
/// (`S_GDATA32`, `S_LDATA32`, `S_GDATA16`, `S_GDATA32_ST`, etc.).
///
/// In Ghidra's Java implementation, `DataSymbolInternals` is a separate class
/// that multiple symbol wrappers delegate to. This Rust port keeps the same
/// structure: the fields are stored here and symbol wrappers can embed or
/// reference this type.
///
/// # Parsing variants
///
/// The `parse_*` associated functions correspond to the Java factory methods:
///
/// - [`DataSymbolInternals::parse16`] — 16-bit offsets, 16-bit type indices, ST strings.
/// - [`DataSymbolInternals::parse32`] — 32-bit offsets, 32-bit type indices, NT strings.
/// - [`DataSymbolInternals::parse3216`] — 32-bit offsets, 16-bit type indices, ST strings.
/// - [`DataSymbolInternals::parse32_st`] — 32-bit offsets, 32-bit type indices, ST strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSymbolInternals {
    /// The type record number that describes this data symbol's type.
    pub type_record_number: RecordNumber,

    /// The offset within the segment.
    pub offset: u64,

    /// The segment index.
    pub segment: u16,

    /// The symbol name.
    pub name: String,

    /// Whether the type record number is a metadata token (ECMA-335) rather
    /// than a standard type index.
    pub is_emit_token: bool,
}

impl DataSymbolInternals {
    /// Parse internals for a 16-bit symbol (16-bit offsets, 16-bit type indices, ST strings).
    pub fn parse16(data: &[u8], offset: usize, emit_token: bool) -> Option<(Self, usize)> {
        let mut pos = offset;

        // offset: variable-sized (16-bit)
        if pos + 2 > data.len() {
            return None;
        }
        let sym_offset = u16::from_le_bytes([data[pos], data[pos + 1]]) as u64;
        pos += 2;

        // segment
        if pos + 2 > data.len() {
            return None;
        }
        let segment = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // type record number (16-bit)
        let (trn, consumed) = RecordNumber::parse(data, pos, RecordCategory::Type, 16);
        if consumed == 0 {
            return None;
        }
        pos += consumed;

        // name: ST-format UTF-8 string
        let (name, consumed) = parse_string_st(data, pos);
        pos += consumed;

        // align to 4
        pos = (pos + 3) & !3;

        Some((
            DataSymbolInternals {
                type_record_number: trn,
                offset: sym_offset,
                segment,
                name,
                is_emit_token: emit_token,
            },
            pos - offset,
        ))
    }

    /// Parse internals for a 32-bit symbol (32-bit offsets, 32-bit type indices, NT strings).
    pub fn parse32(data: &[u8], offset: usize, emit_token: bool) -> Option<(Self, usize)> {
        let mut pos = offset;

        // type record number (32-bit)
        let (trn, consumed) = RecordNumber::parse(data, pos, RecordCategory::Type, 32);
        if consumed == 0 {
            return None;
        }
        pos += consumed;

        // offset: variable-sized (32-bit)
        if pos + 4 > data.len() {
            return None;
        }
        let sym_offset = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]) as u64;
        pos += 4;

        // segment
        if pos + 2 > data.len() {
            return None;
        }
        let segment = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // name: NT-format UTF-8 string
        let (name, consumed) = parse_string_nt(data, pos);
        pos += consumed;

        // align to 4
        pos = (pos + 3) & !3;

        Some((
            DataSymbolInternals {
                type_record_number: trn,
                offset: sym_offset,
                segment,
                name,
                is_emit_token: emit_token,
            },
            pos - offset,
        ))
    }

    /// Parse internals for a 3216 symbol (32-bit offsets, 16-bit type indices, ST strings).
    pub fn parse3216(data: &[u8], offset: usize, emit_token: bool) -> Option<(Self, usize)> {
        let mut pos = offset;

        // offset: variable-sized (32-bit)
        if pos + 4 > data.len() {
            return None;
        }
        let sym_offset = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]) as u64;
        pos += 4;

        // segment
        if pos + 2 > data.len() {
            return None;
        }
        let segment = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // type record number (16-bit)
        let (trn, consumed) = RecordNumber::parse(data, pos, RecordCategory::Type, 16);
        if consumed == 0 {
            return None;
        }
        pos += consumed;

        // name: ST-format UTF-8 string
        let (name, consumed) = parse_string_st(data, pos);
        pos += consumed;

        // align to 4
        pos = (pos + 3) & !3;

        Some((
            DataSymbolInternals {
                type_record_number: trn,
                offset: sym_offset,
                segment,
                name,
                is_emit_token: emit_token,
            },
            pos - offset,
        ))
    }

    /// Parse internals for a 32ST symbol (32-bit offsets, 32-bit type indices, ST strings).
    pub fn parse32_st(data: &[u8], offset: usize, emit_token: bool) -> Option<(Self, usize)> {
        let mut pos = offset;

        // type record number (32-bit)
        let (trn, consumed) = RecordNumber::parse(data, pos, RecordCategory::Type, 32);
        if consumed == 0 {
            return None;
        }
        pos += consumed;

        // offset: variable-sized (32-bit)
        if pos + 4 > data.len() {
            return None;
        }
        let sym_offset = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]) as u64;
        pos += 4;

        // segment
        if pos + 2 > data.len() {
            return None;
        }
        let segment = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // name: ST-format UTF-8 string
        let (name, consumed) = parse_string_st(data, pos);
        pos += consumed;

        // align to 4
        pos = (pos + 3) & !3;

        Some((
            DataSymbolInternals {
                type_record_number: trn,
                offset: sym_offset,
                segment,
                name,
                is_emit_token: emit_token,
            },
            pos - offset,
        ))
    }

    /// Emit a formatted representation of this data symbol.
    ///
    /// If `is_emit_token` is true, the type record number is printed as a
    /// raw token value; otherwise it is printed as a resolved type reference.
    pub fn emit(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_emit_token {
            write!(
                f,
                ": [{:04X}:{:08X}], Token: {:08X}, {}",
                self.segment, self.offset,
                self.type_record_number.number(),
                self.name
            )
        } else {
            write!(
                f,
                ": [{:04X}:{:08X}], Type: {}, {}",
                self.segment, self.offset,
                self.type_record_number,
                self.name
            )
        }
    }
}

/// Parse an ST-format string (16-bit length prefix followed by that many bytes).
fn parse_string_st(data: &[u8], offset: usize) -> (String, usize) {
    if offset + 2 > data.len() {
        return (String::new(), 0);
    }
    let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    let start = offset + 2;
    let end = start + len;
    if end > data.len() {
        return (String::new(), 0);
    }
    let s = String::from_utf8_lossy(&data[start..end]).to_string();
    (s, 2 + len)
}

/// Parse an NT-format (null-terminated) string.
fn parse_string_nt(data: &[u8], offset: usize) -> (String, usize) {
    if offset >= data.len() {
        return (String::new(), 0);
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    let s = String::from_utf8_lossy(&data[offset..end]).to_string();
    let consumed = end - offset + 1; // include null terminator
    (s, consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse32_basic() {
        // type_record(4) + offset(4) + segment(2) + name("x\0")
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes()); // type record number
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // offset
        data.extend_from_slice(&1u16.to_le_bytes()); // segment
        data.extend_from_slice(b"x\0"); // name

        let result = DataSymbolInternals::parse32(&data, 0, false);
        assert!(result.is_some());
        let (internals, consumed) = result.unwrap();
        assert_eq!(internals.type_record_number.number(), 0x1020);
        assert_eq!(internals.offset, 0x1000);
        assert_eq!(internals.segment, 1);
        assert_eq!(internals.name, "x");
        assert!(!internals.is_emit_token);
        // consumed should be aligned to 4
        assert_eq!(consumed % 4, 0);
    }

    #[test]
    fn test_parse16_basic() {
        // offset(2) + segment(2) + type_record(2) + name ST("ab\0" = len 2)
        let mut data = Vec::new();
        data.extend_from_slice(&0x200u16.to_le_bytes()); // offset
        data.extend_from_slice(&3u16.to_le_bytes()); // segment
        data.extend_from_slice(&0x1000u16.to_le_bytes()); // type record number (16-bit)
        data.extend_from_slice(&2u16.to_le_bytes()); // ST string length
        data.extend_from_slice(b"ab"); // ST string data

        let result = DataSymbolInternals::parse16(&data, 0, true);
        assert!(result.is_some());
        let (internals, _) = result.unwrap();
        assert_eq!(internals.offset, 0x200);
        assert_eq!(internals.segment, 3);
        assert_eq!(internals.type_record_number.number(), 0x1000);
        assert_eq!(internals.name, "ab");
        assert!(internals.is_emit_token);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        let result = DataSymbolInternals::parse32(&data, 0, false);
        assert!(result.is_none());
    }

    #[test]
    fn test_emit_token_mode() {
        let internals = DataSymbolInternals {
            type_record_number: RecordNumber::type_record_number(0x1234),
            offset: 0x5678,
            segment: 1,
            name: "myVar".to_string(),
            is_emit_token: true,
        };
        let s = format!("{:?}", internals);
        assert!(s.contains("myVar"));
    }
}
