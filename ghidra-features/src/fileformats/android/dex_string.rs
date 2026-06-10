//! Android DEX string structures.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.dex.format`
//! `StringIDItem` and `StringDataItem` packages.
//!
//! Covers the `string_id_item` (4 bytes) and `string_data_item`
//! (variable-length, MUTF-8 encoded) on-disk structures.

/// Maximum allowed string length (2 MiB, matching the Java implementation).
const MAX_STRING_LEN: usize = 0x200000;

// ═══════════════════════════════════════════════════════════════════════════════════
// StringIDItem
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `string_id_item` structure (4 bytes).
///
/// Each string in the DEX file has an entry in the `string_ids` table.
/// The entry contains the offset to the string data.
#[derive(Debug, Clone)]
pub struct StringIDItem {
    /// File offset of this item (set during parsing).
    pub file_offset: u64,
    /// Offset from start of file to the string data.
    /// NOTE: For CDEX files, this value is relative to `data_off` in `DexHeader`.
    pub string_data_offset: u32,
}

impl StringIDItem {
    /// Size of the on-disk structure (4 bytes).
    pub const SIZE: usize = 4;

    /// Parse a `string_id_item` from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Parse a `string_id_item` from a byte slice, recording the file offset.
    pub fn parse_at(data: &[u8], file_offset: usize) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for StringIDItem".to_string());
        }

        let string_data_offset = u32::from_le_bytes(data[0..4].try_into().unwrap());

        Ok(StringIDItem {
            file_offset: file_offset as u64,
            string_data_offset,
        })
    }

    /// Parse all `string_id_item` entries from a DEX file.
    ///
    /// `count` is the number of entries (from the DEX header).
    /// `offset` is the byte offset of the `string_ids` table.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, String> {
        let start = offset as usize;
        let table_size = count as usize * Self::SIZE;
        if start + table_size > data.len() {
            return Err("StringIDItem table extends beyond data".to_string());
        }

        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let entry_start = start + i * Self::SIZE;
            let item = Self::parse_at(&data[entry_start..], entry_start)?;
            result.push(item);
        }
        Ok(result)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// StringDataItem
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a parsed `string_data_item`.
///
/// The `string_data_item` contains a ULEB128-encoded string length followed
/// by the string data in MUTF-8 encoding, terminated by a null byte.
#[derive(Debug, Clone)]
pub struct StringDataItem {
    /// The decoded string value.
    pub string: String,
    /// The ULEB128-encoded string length field.
    pub string_length: u32,
    /// Length of the ULEB128 encoding (bytes).
    pub leb_length: u32,
    /// Total byte length of the item (ULEB128 + data + null terminator).
    pub actual_length: usize,
}

impl StringDataItem {
    /// Parse a `string_data_item` from raw bytes at the given offset.
    ///
    /// The offset should be the `string_data_offset` from a `StringIDItem`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset >= data.len() {
            return Err("StringDataItem offset out of range".to_string());
        }

        let input = &data[offset..];
        let mut pos = 0;

        // Read ULEB128 string length
        let (string_length, new_pos, leb_length) = read_uleb128_with_len(input, pos)?;
        pos = new_pos;

        // Find null terminator
        let null_pos = find_null_terminator(input, pos)?;
        let actual_length = null_pos - pos + 1; // include null terminator

        // Decode MUTF-8 string
        let string_bytes = &input[pos..null_pos];
        let string = decode_mutf8(string_bytes, string_length as usize)?;

        Ok(StringDataItem {
            string,
            string_length,
            leb_length,
            actual_length: leb_length as usize + actual_length,
        })
    }

    /// Parse a `string_data_item` and handle errors gracefully.
    ///
    /// Returns a placeholder string if parsing fails.
    pub fn parse_or_invalid(data: &[u8], offset: usize) -> Self {
        match Self::parse(data, offset) {
            Ok(item) => item,
            Err(_) => StringDataItem {
                string: format!("Invalid_String_0x{:x}", offset),
                string_length: 0,
                leb_length: 0,
                actual_length: 0,
            },
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// MUTF-8 Decoding
// ═══════════════════════════════════════════════════════════════════════════════════

/// Decode a Modified UTF-8 (MUTF-8) byte sequence into a Rust `String`.
///
/// MUTF-8 is used in DEX files and is similar to standard UTF-8 but:
/// - The null byte is encoded as two bytes: 0xC0 0x80
/// - Supplementary characters use a surrogate pair encoding
fn decode_mutf8(bytes: &[u8], expected_len: usize) -> Result<String, String> {
    let mut result = String::with_capacity(expected_len);
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            return Err("Unexpected null byte in MUTF-8 string".to_string());
        }

        if b & 0x80 == 0 {
            // Single-byte character (ASCII)
            result.push(b as char);
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            // Two-byte character
            if i + 1 >= bytes.len() {
                return Err("Truncated MUTF-8 two-byte sequence".to_string());
            }
            let b2 = bytes[i + 1];
            if b2 & 0xC0 != 0x80 {
                return Err("Invalid MUTF-8 continuation byte".to_string());
            }
            let code_point = ((b as u32 & 0x1F) << 6) | (b2 as u32 & 0x3F);
            // Handle the special null encoding: 0xC0 0x80 -> U+0000
            if code_point == 0 {
                result.push('\0');
            } else if let Some(c) = char::from_u32(code_point) {
                result.push(c);
            } else {
                return Err(format!("Invalid MUTF-8 code point: 0x{:x}", code_point));
            }
            i += 2;
        } else if b & 0xF0 == 0xE0 {
            // Three-byte character
            if i + 2 >= bytes.len() {
                return Err("Truncated MUTF-8 three-byte sequence".to_string());
            }
            let b2 = bytes[i + 1];
            let b3 = bytes[i + 2];
            if b2 & 0xC0 != 0x80 || b3 & 0xC0 != 0x80 {
                return Err("Invalid MUTF-8 continuation bytes".to_string());
            }
            let code_point = ((b as u32 & 0x0F) << 12)
                | ((b2 as u32 & 0x3F) << 6)
                | (b3 as u32 & 0x3F);

            // Check for surrogate pairs (supplementary characters)
            if code_point >= 0xD800 && code_point <= 0xDBFF {
                // High surrogate - read the low surrogate
                if i + 5 >= bytes.len() {
                    return Err("Truncated MUTF-8 surrogate pair".to_string());
                }
                let b4 = bytes[i + 3];
                let b5 = bytes[i + 4];
                let b6 = bytes[i + 5];
                if b4 & 0xF0 != 0xE0 || b5 & 0xC0 != 0x80 || b6 & 0xC0 != 0x80 {
                    return Err("Invalid MUTF-8 low surrogate encoding".to_string());
                }
                let low_surrogate = ((b4 as u32 & 0x0F) << 12)
                    | ((b5 as u32 & 0x3F) << 6)
                    | (b6 as u32 & 0x3F);
                if low_surrogate < 0xDC00 || low_surrogate > 0xDFFF {
                    return Err(format!(
                        "Invalid MUTF-8 low surrogate: 0x{:x}",
                        low_surrogate
                    ));
                }
                let supplementary = 0x10000
                    + ((code_point - 0xD800) << 10)
                    + (low_surrogate - 0xDC00);
                if let Some(c) = char::from_u32(supplementary) {
                    result.push(c);
                } else {
                    return Err(format!(
                        "Invalid MUTF-8 supplementary code point: 0x{:x}",
                        supplementary
                    ));
                }
                i += 6;
            } else if code_point >= 0xDC00 && code_point <= 0xDFFF {
                return Err(format!(
                    "Unexpected low surrogate in MUTF-8: 0x{:x}",
                    code_point
                ));
            } else if let Some(c) = char::from_u32(code_point) {
                result.push(c);
                i += 3;
            } else {
                return Err(format!("Invalid MUTF-8 code point: 0x{:x}", code_point));
            }
        } else {
            return Err(format!("Invalid MUTF-8 lead byte: 0x{:x}", b));
        }
    }

    Ok(result)
}

/// Find the null terminator in a byte slice starting at `start`.
///
/// Returns the index of the null byte, or an error if not found within
/// `MAX_STRING_LEN` bytes.
fn find_null_terminator(data: &[u8], start: usize) -> Result<usize, String> {
    let max = std::cmp::min(start + MAX_STRING_LEN, data.len());
    for i in start..max {
        if data[i] == 0 {
            return Ok(i);
        }
    }
    Err("Null terminator not found within MAX_STRING_LEN".to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ULEB128 reader with length tracking
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read an unsigned LEB128 value from `data` starting at `pos`.
///
/// Returns `(value, new_position, byte_length)`.
fn read_uleb128_with_len(data: &[u8], mut pos: usize) -> Result<(u32, usize, u32), String> {
    let mut result: u32 = 0;
    let mut shift = 0;
    let start_pos = pos;

    loop {
        if pos >= data.len() {
            return Err("ULEB128: unexpected end of data".to_string());
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, pos, (pos - start_pos) as u32));
        }
        shift += 7;
        if shift >= 32 {
            return Err("ULEB128: too many bytes for u32".to_string());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_id_item_parse() {
        let mut data = vec![0u8; StringIDItem::SIZE];
        data[0..4].copy_from_slice(&0x200u32.to_le_bytes()); // string_data_offset

        let item = StringIDItem::parse(&data).unwrap();
        assert_eq!(item.string_data_offset, 0x200);
    }

    #[test]
    fn test_string_id_item_parse_all() {
        let mut data = vec![0u8; StringIDItem::SIZE * 2];
        data[0..4].copy_from_slice(&0x100u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x200u32.to_le_bytes());

        let items = StringIDItem::parse_all(&data, 0, 2).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].string_data_offset, 0x100);
        assert_eq!(items[1].string_data_offset, 0x200);
    }

    #[test]
    fn test_string_data_item_parse_ascii() {
        // "Hello" in MUTF-8: length=5, 'H','e','l','l','o', 0x00
        let mut data = Vec::new();
        data.push(0x05); // ULEB128 length = 5
        data.extend_from_slice(b"Hello");
        data.push(0x00); // null terminator

        let item = StringDataItem::parse(&data, 0).unwrap();
        assert_eq!(item.string, "Hello");
        assert_eq!(item.string_length, 5);
        assert_eq!(item.leb_length, 1);
    }

    #[test]
    fn test_string_data_item_parse_two_byte() {
        // "é" (e-acute) in MUTF-8: 0xC3 0xA9
        let mut data = Vec::new();
        data.push(0x01); // ULEB128 length = 1 (1 character)
        data.push(0xC3);
        data.push(0xA9);
        data.push(0x00); // null terminator

        let item = StringDataItem::parse(&data, 0).unwrap();
        assert_eq!(item.string, "\u{00E9}");
        assert_eq!(item.string_length, 1);
    }

    #[test]
    fn test_string_data_item_parse_null_encoding() {
        // Null character encoded as 0xC0 0x80 in MUTF-8
        let mut data = Vec::new();
        data.push(0x01); // ULEB128 length = 1
        data.push(0xC0);
        data.push(0x80);
        data.push(0x00); // null terminator

        let item = StringDataItem::parse(&data, 0).unwrap();
        assert_eq!(item.string, "\0");
        assert_eq!(item.string_length, 1);
    }

    #[test]
    fn test_string_data_item_parse_with_offset() {
        let mut data = vec![0xFF, 0xFF, 0xFF]; // padding
        // "Hi" at offset 3
        data.push(0x02); // ULEB128 length = 2
        data.extend_from_slice(b"Hi");
        data.push(0x00);

        let item = StringDataItem::parse(&data, 3).unwrap();
        assert_eq!(item.string, "Hi");
    }

    #[test]
    fn test_string_data_item_parse_or_invalid() {
        let data = vec![0xFF, 0xFF]; // invalid data
        let item = StringDataItem::parse_or_invalid(&data, 0);
        assert!(item.string.starts_with("Invalid_String_0x"));
    }

    #[test]
    fn test_string_data_item_offset_out_of_range() {
        let data = vec![0u8; 4];
        assert!(StringDataItem::parse(&data, 10).is_err());
    }

    #[test]
    fn test_string_data_item_no_null_terminator() {
        let mut data = Vec::new();
        data.push(0x05); // length = 5
        data.extend_from_slice(b"Hello"); // no null terminator
        assert!(StringDataItem::parse(&data, 0).is_err());
    }

    #[test]
    fn test_string_id_item_truncated() {
        let data = vec![0u8; 2];
        assert!(StringIDItem::parse(&data).is_err());
    }

    #[test]
    fn test_decode_mutf8_empty() {
        let result = decode_mutf8(&[], 0).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_decode_mutf8_ascii() {
        let result = decode_mutf8(b"Hello", 5).unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_find_null_terminator() {
        assert_eq!(find_null_terminator(b"abc\0def", 0).unwrap(), 3);
        assert_eq!(find_null_terminator(b"\0", 0).unwrap(), 0);
        assert!(find_null_terminator(b"abcdef", 0).is_err());
    }

    #[test]
    fn test_find_null_terminator_with_offset() {
        // "abc\0def\0" - searching from offset 4 should find null at index 7
        assert_eq!(find_null_terminator(b"abc\0def\0", 4).unwrap(), 7);
    }
}
