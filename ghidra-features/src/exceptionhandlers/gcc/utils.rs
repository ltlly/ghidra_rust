//! GCC Analysis Utilities
//!
//! Ported from `GccAnalysisUtils.java` and `GccAnalysisClass.java`.
//!
//! Provides helper functions for reading memory and parsing LEB128 values
//! from program data, as well as common analysis base types.

use super::decode::{read_uleb128, read_sleb128};

/// Read a single byte from the data buffer.
pub fn read_byte(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

/// Read a 16-bit unsigned word (little-endian) from the data buffer.
pub fn read_word(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Read a 32-bit unsigned double word (little-endian) from the data buffer.
pub fn read_dword(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Read a 64-bit unsigned quad word (little-endian) from the data buffer.
pub fn read_qword(data: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

/// Read a slice of bytes from the data buffer.
pub fn read_bytes(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    if offset + len > data.len() {
        return None;
    }
    Some(&data[offset..offset + len])
}

/// Read an unsigned LEB128 value from the data buffer at the given offset.
pub fn read_uleb128_at(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    if offset >= data.len() {
        return None;
    }
    read_uleb128(&data[offset..])
}

/// Read a signed LEB128 value from the data buffer at the given offset.
pub fn read_sleb128_at(data: &[u8], offset: usize) -> Option<(i64, usize)> {
    if offset >= data.len() {
        return None;
    }
    read_sleb128(&data[offset..])
}

/// Read a NUL-terminated ASCII string from the data buffer.
pub fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)?;
    std::str::from_utf8(&data[offset..end])
        .ok()
        .map(|s| s.to_string())
}

/// Encode a NUL-terminated string as bytes (for augmentation string parsing).
pub fn encode_cstring(s: &str) -> Vec<u8> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_byte() {
        assert_eq!(read_byte(&[0x42, 0x00], 0), Some(0x42));
        assert_eq!(read_byte(&[0x42], 1), None);
    }

    #[test]
    fn test_read_word() {
        assert_eq!(read_word(&[0x34, 0x12], 0), Some(0x1234));
        assert_eq!(read_word(&[0x34], 0), None);
    }

    #[test]
    fn test_read_dword() {
        assert_eq!(
            read_dword(&[0x78, 0x56, 0x34, 0x12], 0),
            Some(0x12345678)
        );
        assert_eq!(read_dword(&[0x78, 0x56], 0), None);
    }

    #[test]
    fn test_read_qword() {
        let data = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        assert_eq!(read_qword(&data, 0), Some(0x0102030405060708));
    }

    #[test]
    fn test_read_bytes() {
        let data = [1, 2, 3, 4, 5];
        assert_eq!(read_bytes(&data, 1, 3), Some(&[2, 3, 4][..]));
        assert_eq!(read_bytes(&data, 3, 5), None);
    }

    #[test]
    fn test_read_uleb128_at() {
        let data = [0x02, 0x80, 0x01, 0x00];
        assert_eq!(read_uleb128_at(&data, 0), Some((2, 1)));
        assert_eq!(read_uleb128_at(&data, 1), Some((128, 2)));
    }

    #[test]
    fn test_read_sleb128_at() {
        let data = [0x7e]; // -2
        assert_eq!(read_sleb128_at(&data, 0), Some((-2, 1)));
    }

    #[test]
    fn test_read_cstring() {
        let data = b"hello\0world\0";
        assert_eq!(read_cstring(data, 0), Some("hello".to_string()));
        assert_eq!(read_cstring(data, 6), Some("world".to_string()));
        assert_eq!(read_cstring(data, 12), None);
    }

    #[test]
    fn test_encode_cstring() {
        let encoded = encode_cstring("abc");
        assert_eq!(encoded, b"abc\0");
    }
}
