//! LEB128 variable-length integer encoding/decoding.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.LEB128Info`. This encoding is
//! used in DWARF debug info, WebAssembly, and many other formats.

use std::io;

use super::binary_reader::BinaryReader;

/// Decoded LEB128 value with its byte length.
///
/// Ported from `ghidra.app.util.bin.LEB128Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LEB128Info {
    /// The decoded value.
    pub value: u64,
    /// The number of bytes consumed to decode.
    pub length: usize,
}

/// LEB128 (Little Endian Base 128) variable-length integer encoding.
///
/// Ported from Ghidra's LEB128 utilities.
pub struct LEB128;

impl LEB128 {
    /// Decode an unsigned LEB128 value from the given bytes.
    pub fn read_unsigned(data: &[u8]) -> io::Result<LEB128Info> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;

        for &byte in data {
            bytes_read += 1;
            let low_bits = (byte & 0x7F) as u64;
            result |= low_bits << shift;
            if byte & 0x80 == 0 {
                return Ok(LEB128Info {
                    value: result,
                    length: bytes_read,
                });
            }
            shift += 7;
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ULEB128 too large",
                ));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated ULEB128",
        ))
    }

    /// Decode a signed LEB128 value from the given bytes.
    pub fn read_signed(data: &[u8]) -> io::Result<(i64, usize)> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;
        let mut byte: u8 = 0;
        let mut finished = false;

        for &b in data {
            byte = b;
            bytes_read += 1;
            let low_bits = (byte & 0x7F) as i64;
            result |= low_bits << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                finished = true;
                break;
            }
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SLEB128 too large",
                ));
            }
        }

        if !finished {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated SLEB128",
            ));
        }

        // Sign extend if the high bit of the last byte is set
        if shift < 64 && (byte & 0x40) != 0 {
            result |= -(1i64 << shift);
        }

        Ok((result, bytes_read))
    }

    /// Encode an unsigned value as ULEB128.
    pub fn write_unsigned(mut value: u64) -> Vec<u8> {
        let mut result = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            result.push(byte);
            if value == 0 {
                break;
            }
        }
        result
    }

    /// Encode a signed value as SLEB128.
    pub fn write_signed(mut value: i64) -> Vec<u8> {
        let mut result = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0) {
                result.push(byte);
                break;
            }
            byte |= 0x80;
            result.push(byte);
        }
        result
    }

    /// Read an unsigned LEB128 from a BinaryReader, advancing the cursor.
    pub fn read_unsigned_from_reader(reader: &mut BinaryReader) -> io::Result<LEB128Info> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;

        loop {
            let byte = reader.read_next_u8()?;
            bytes_read += 1;
            let low_bits = (byte & 0x7F) as u64;
            result |= low_bits << shift;
            if byte & 0x80 == 0 {
                return Ok(LEB128Info {
                    value: result,
                    length: bytes_read,
                });
            }
            shift += 7;
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ULEB128 too large",
                ));
            }
        }
    }

    /// Read a signed LEB128 from a BinaryReader, advancing the cursor.
    pub fn read_signed_from_reader(reader: &mut BinaryReader) -> io::Result<(i64, usize)> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;
        let mut byte: u8;

        loop {
            byte = reader.read_next_u8()?;
            bytes_read += 1;
            let low_bits = (byte & 0x7F) as i64;
            result |= low_bits << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SLEB128 too large",
                ));
            }
        }

        // Sign extend
        if shift < 64 && (byte & 0x40) != 0 {
            result |= -(1i64 << shift);
        }

        Ok((result, bytes_read))
    }

    /// Compute the encoded size of an unsigned value without actually encoding.
    pub fn encoded_size_unsigned(value: u64) -> usize {
        let mut size = 1;
        let mut val = value >> 7;
        while val != 0 {
            size += 1;
            val >>= 7;
        }
        size
    }

    /// Compute the encoded size of a signed value without actually encoding.
    pub fn encoded_size_signed(value: i64) -> usize {
        let mut size = 1;
        let mut val = value >> 6;
        let mut done = value >> 6 == 0 || value >> 6 == -1;
        while !done {
            val >>= 7;
            size += 1;
            done = val == 0 || val == -1;
        }
        size
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leb128_unsigned() {
        // 624485 encodes as 0xE5, 0x8E, 0x26
        let encoded = LEB128::write_unsigned(624485);
        assert_eq!(encoded, vec![0xE5, 0x8E, 0x26]);

        let decoded = LEB128::read_unsigned(&encoded).unwrap();
        assert_eq!(decoded.value, 624485);
        assert_eq!(decoded.length, 3);
    }

    #[test]
    fn test_leb128_signed() {
        // -123456
        let encoded = LEB128::write_signed(-123456);
        let (decoded, len) = LEB128::read_signed(&encoded).unwrap();
        assert_eq!(decoded, -123456);
        assert_eq!(len, encoded.len());
    }

    #[test]
    fn test_leb128_small_values() {
        // Single byte values
        assert_eq!(LEB128::write_unsigned(0), vec![0x00]);
        assert_eq!(LEB128::write_unsigned(127), vec![0x7F]);
        assert_eq!(LEB128::write_unsigned(128), vec![0x80, 0x01]);

        assert_eq!(LEB128::read_unsigned(&[0x00]).unwrap().value, 0);
        assert_eq!(LEB128::read_unsigned(&[0x7F]).unwrap().value, 127);
        assert_eq!(LEB128::read_unsigned(&[0x80, 0x01]).unwrap().value, 128);
    }

    #[test]
    fn test_leb128_reader() {
        let data = LEB128::write_unsigned(1000);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let info = LEB128::read_unsigned_from_reader(&mut reader).unwrap();
        assert_eq!(info.value, 1000);
        assert_eq!(reader.cursor(), info.length as u64);
    }

    #[test]
    fn test_leb128_signed_reader() {
        let data = LEB128::write_signed(-1000);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let (value, len) = LEB128::read_signed_from_reader(&mut reader).unwrap();
        assert_eq!(value, -1000);
        assert_eq!(reader.cursor(), len as u64);
    }

    #[test]
    fn test_leb128_edge_cases() {
        // u64 max
        let encoded = LEB128::write_unsigned(u64::MAX);
        let decoded = LEB128::read_unsigned(&encoded).unwrap();
        assert_eq!(decoded.value, u64::MAX);

        // i64 min/max
        let encoded_min = LEB128::write_signed(i64::MIN);
        let (decoded_min, _) = LEB128::read_signed(&encoded_min).unwrap();
        assert_eq!(decoded_min, i64::MIN);

        let encoded_max = LEB128::write_signed(i64::MAX);
        let (decoded_max, _) = LEB128::read_signed(&encoded_max).unwrap();
        assert_eq!(decoded_max, i64::MAX);
    }

    #[test]
    fn test_leb128_truncated() {
        // A continuation byte with no following byte
        assert!(LEB128::read_unsigned(&[0x80]).is_err());
        assert!(LEB128::read_signed(&[0x80]).is_err());
    }

    #[test]
    fn test_leb128_encoded_size() {
        assert_eq!(LEB128::encoded_size_unsigned(0), 1);
        assert_eq!(LEB128::encoded_size_unsigned(127), 1);
        assert_eq!(LEB128::encoded_size_unsigned(128), 2);
        assert_eq!(LEB128::encoded_size_unsigned(16383), 2);
        assert_eq!(LEB128::encoded_size_unsigned(16384), 3);

        assert_eq!(LEB128::encoded_size_signed(0), 1);
        assert_eq!(LEB128::encoded_size_signed(63), 1);
        assert_eq!(LEB128::encoded_size_signed(64), 2);
        assert_eq!(LEB128::encoded_size_signed(-1), 1);
        assert_eq!(LEB128::encoded_size_signed(-64), 1);
        assert_eq!(LEB128::encoded_size_signed(-65), 2);
    }

    #[test]
    fn test_leb128_roundtrip() {
        for val in [0u64, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let encoded = LEB128::write_unsigned(val);
            let decoded = LEB128::read_unsigned(&encoded).unwrap();
            assert_eq!(decoded.value, val, "failed roundtrip for {}", val);
        }

        for val in [0i64, 1, -1, 63, 64, -64, -65, i32::MIN as i64, i32::MAX as i64, i64::MIN, i64::MAX] {
            let encoded = LEB128::write_signed(val);
            let (decoded, _) = LEB128::read_signed(&encoded).unwrap();
            assert_eq!(decoded, val, "failed roundtrip for {}", val);
        }
    }
}
