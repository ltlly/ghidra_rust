//! Endian-aware binary reader ported from Ghidra's `ghidra.app.util.bin.BinaryReader`.

use std::io;

use super::byte_provider::{ByteArrayProvider, ByteProvider};

// ---------------------------------------------------------------------------
// BinaryReader
// ---------------------------------------------------------------------------

/// Endian-aware binary reader with an internal cursor.
///
/// Ported from `ghidra.app.util.bin.BinaryReader`. Reads data from a
/// `ByteProvider` in either big-endian or little-endian byte order.
pub struct BinaryReader {
    provider: Box<dyn ByteProvider>,
    is_little_endian: bool,
    index: u64,
}

impl BinaryReader {
    /// Size constants matching Java's `BinaryReader`.
    pub const SIZEOF_BYTE: usize = 1;
    pub const SIZEOF_SHORT: usize = 2;
    pub const SIZEOF_INT: usize = 4;
    pub const SIZEOF_LONG: usize = 8;

    /// Create a new reader.
    pub fn new(provider: Box<dyn ByteProvider>, is_little_endian: bool) -> Self {
        Self {
            provider,
            is_little_endian,
            index: 0,
        }
    }

    /// Create a reader from a byte slice.
    pub fn from_bytes(data: &[u8], is_little_endian: bool) -> Self {
        Self::new(
            Box::new(ByteArrayProvider::new(None, data.to_vec())),
            is_little_endian,
        )
    }

    /// Get the underlying byte provider.
    pub fn provider(&self) -> &dyn ByteProvider {
        self.provider.as_ref()
    }

    /// Get the current cursor position.
    pub fn cursor(&self) -> u64 {
        self.index
    }

    /// Set the cursor position.
    pub fn set_cursor(&mut self, index: u64) {
        self.index = index;
    }

    /// Advance the cursor by the given offset.
    pub fn advance(&mut self, offset: u64) {
        self.index += offset;
    }

    /// Get the total length of the underlying provider.
    pub fn length(&self) -> u64 {
        self.provider.length()
    }

    /// Returns true if the reader is little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    /// Get the number of remaining bytes from cursor to end.
    pub fn remaining(&self) -> u64 {
        self.provider.length().saturating_sub(self.index)
    }

    // --- Read primitives at cursor (advancing) ---

    /// Read a u8 at cursor and advance by 1.
    pub fn read_next_u8(&mut self) -> io::Result<u8> {
        let val = self.provider.read_u8(self.index)?;
        self.index += 1;
        Ok(val)
    }

    /// Read a i8 at cursor and advance by 1.
    pub fn read_next_i8(&mut self) -> io::Result<i8> {
        Ok(self.read_next_u8()? as i8)
    }

    /// Read a u16 at cursor and advance by 2.
    pub fn read_next_u16(&mut self) -> io::Result<u16> {
        let mut buf = [0u8; 2];
        self.read_exact_at_cursor(&mut buf)?;
        Ok(if self.is_little_endian {
            u16::from_le_bytes(buf)
        } else {
            u16::from_be_bytes(buf)
        })
    }

    /// Read a i16 at cursor and advance by 2.
    pub fn read_next_i16(&mut self) -> io::Result<i16> {
        Ok(self.read_next_u16()? as i16)
    }

    /// Read a u32 at cursor and advance by 4.
    pub fn read_next_u32(&mut self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact_at_cursor(&mut buf)?;
        Ok(if self.is_little_endian {
            u32::from_le_bytes(buf)
        } else {
            u32::from_be_bytes(buf)
        })
    }

    /// Read a i32 at cursor and advance by 4.
    pub fn read_next_i32(&mut self) -> io::Result<i32> {
        Ok(self.read_next_u32()? as i32)
    }

    /// Read a u64 at cursor and advance by 8.
    pub fn read_next_u64(&mut self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact_at_cursor(&mut buf)?;
        Ok(if self.is_little_endian {
            u64::from_le_bytes(buf)
        } else {
            u64::from_be_bytes(buf)
        })
    }

    /// Read a i64 at cursor and advance by 8.
    pub fn read_next_i64(&mut self) -> io::Result<i64> {
        Ok(self.read_next_u64()? as i64)
    }

    /// Read a f32 at cursor and advance by 4.
    pub fn read_next_f32(&mut self) -> io::Result<f32> {
        Ok(f32::from_bits(self.read_next_u32()?))
    }

    /// Read a f64 at cursor and advance by 8.
    pub fn read_next_f64(&mut self) -> io::Result<f64> {
        Ok(f64::from_bits(self.read_next_u64()?))
    }

    /// Read `len` bytes at cursor and advance.
    pub fn read_next_bytes(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_exact_at_cursor(&mut buf)?;
        Ok(buf)
    }

    /// Read a i16 at cursor and advance by 2 (alias for `read_next_i16`).
    ///
    /// Matches the Java `BinaryReader.readNextShort()` API used by XCOFF parsers.
    pub fn read_next_short(&mut self) -> io::Result<i16> {
        self.read_next_i16()
    }

    /// Read a i32 at cursor and advance by 4 (alias for `read_next_i32`).
    ///
    /// Matches the Java `BinaryReader.readNextInt()` API used by XCOFF parsers.
    pub fn read_next_int(&mut self) -> io::Result<i32> {
        self.read_next_i32()
    }

    /// Read a i64 at cursor and advance by 8 (alias for `read_next_i64`).
    ///
    /// Matches the Java `BinaryReader.readNextLong()` API used by XCOFF parsers.
    pub fn read_next_long(&mut self) -> io::Result<i64> {
        self.read_next_i64()
    }

    /// Read a u8 at cursor and advance by 1 (alias for `read_next_u8`).
    ///
    /// Matches the Java `BinaryReader.readNextByte()` API used by XCOFF parsers.
    pub fn read_next_byte(&mut self) -> io::Result<u8> {
        self.read_next_u8()
    }

    /// Peek at a i16 at cursor without advancing.
    ///
    /// Matches the Java `BinaryReader.peekNextShort()` API used by XCOFF parsers.
    pub fn peek_next_short(&self) -> io::Result<i16> {
        self.read_u16_at(self.index).map(|v| v as i16)
    }

    /// Get the current cursor position as a `usize`.
    ///
    /// Matches the Java `BinaryReader.getPointerIndex()` API used by XCOFF parsers.
    pub fn get_pointer_index(&self) -> usize {
        self.index as usize
    }

    /// Peek at a i32 at cursor without advancing.
    pub fn peek_i32(&self) -> i32 {
        self.read_u32_at(self.index).map(|v| v as i32).unwrap_or(0)
    }

    /// Read a null-terminated ASCII string at the given offset (non-advancing).
    pub fn read_cstring_at(&self, offset: u64) -> io::Result<String> {
        let mut bytes = Vec::new();
        let mut pos = offset;
        loop {
            let b = self.provider.read_u8(pos)?;
            if b == 0 {
                break;
            }
            bytes.push(b);
            pos += 1;
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Read exactly `buf.len()` bytes into `buf` at the current cursor and advance.
    pub fn read_exact_bytes(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.read_exact_at_cursor(buf)
    }

    /// Read a null-terminated ASCII string at cursor and advance past the null.
    pub fn read_next_cstring(&mut self) -> io::Result<String> {
        let mut bytes = Vec::new();
        loop {
            let b = self.read_next_u8()?;
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Read a fixed-length ASCII string at cursor (padded with nulls) and advance.
    pub fn read_next_fixed_string(&mut self, len: usize) -> io::Result<String> {
        let bytes = self.read_next_bytes(len)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Read a null-terminated UTF-16LE string at cursor and advance.
    pub fn read_next_utf16_cstring(&mut self) -> io::Result<String> {
        let mut code_units = Vec::new();
        loop {
            let cu = self.read_next_u16()?;
            if cu == 0 {
                break;
            }
            code_units.push(cu);
        }
        Ok(String::from_utf16_lossy(&code_units))
    }

    // --- Read primitives at arbitrary index (non-advancing) ---

    /// Read a u8 at the given index without moving the cursor.
    pub fn read_u8_at(&self, index: u64) -> io::Result<u8> {
        self.provider.read_u8(index)
    }

    /// Read a u16 at the given index without moving the cursor.
    pub fn read_u16_at(&self, index: u64) -> io::Result<u16> {
        let mut buf = [0u8; 2];
        self.provider.read_bytes(index, &mut buf)?;
        Ok(if self.is_little_endian {
            u16::from_le_bytes(buf)
        } else {
            u16::from_be_bytes(buf)
        })
    }

    /// Read a u32 at the given index without moving the cursor.
    pub fn read_u32_at(&self, index: u64) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.provider.read_bytes(index, &mut buf)?;
        Ok(if self.is_little_endian {
            u32::from_le_bytes(buf)
        } else {
            u32::from_be_bytes(buf)
        })
    }

    /// Read a u64 at the given index without moving the cursor.
    pub fn read_u64_at(&self, index: u64) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.provider.read_bytes(index, &mut buf)?;
        Ok(if self.is_little_endian {
            u64::from_le_bytes(buf)
        } else {
            u64::from_be_bytes(buf)
        })
    }

    /// Read bytes at the given index without moving the cursor.
    pub fn read_bytes_at(&self, index: u64, len: usize) -> io::Result<Vec<u8>> {
        self.provider.read_slice(index, len)
    }

    /// Read a fixed-length ASCII string at the given index (null/whitespace trimmed)
    /// without moving the cursor.
    pub fn read_fixed_string_at(&self, index: u64, len: usize) -> io::Result<String> {
        let bytes = self.provider.read_slice(index, len)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    // --- Convenience methods matching Java BinaryReader ---

    /// Read a u32 at the given index in the specified endianness.
    pub fn read_u32_at_endian(
        index: u64,
        provider: &dyn ByteProvider,
        le: bool,
    ) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        provider.read_bytes(index, &mut buf)?;
        Ok(if le {
            u32::from_le_bytes(buf)
        } else {
            u32::from_be_bytes(buf)
        })
    }

    /// Create a new reader with a different endianness sharing the same provider.
    ///
    /// NOTE: The returned reader has its own cursor starting at 0.
    pub fn as_other_endian(&self, is_little_endian: bool) -> io::Result<BinaryReader> {
        let data = self.provider.read_slice(0, self.provider.length() as usize)?;
        Ok(BinaryReader::from_bytes(&data, is_little_endian))
    }

    // Private helper
    fn read_exact_at_cursor(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let n = self.provider.read_bytes(self.index, buf)?;
        if n < buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "expected {} bytes at offset {}, got {}",
                    buf.len(),
                    self.index,
                    n
                ),
            ));
        }
        self.index += buf.len() as u64;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_reader_le() {
        let data = vec![0x78, 0x56, 0x34, 0x12];
        let mut reader = BinaryReader::from_bytes(&data, true);
        assert_eq!(reader.read_next_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_binary_reader_be() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let mut reader = BinaryReader::from_bytes(&data, false);
        assert_eq!(reader.read_next_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_binary_reader_cursor() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut reader = BinaryReader::from_bytes(&data, true);
        assert_eq!(reader.cursor(), 0);
        let val = reader.read_next_u16().unwrap();
        assert_eq!(val, 0x0201);
        assert_eq!(reader.cursor(), 2);
        reader.set_cursor(4);
        let val = reader.read_next_u32().unwrap();
        assert_eq!(val, 0x08070605);
    }

    #[test]
    fn test_binary_reader_at() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let reader = BinaryReader::from_bytes(&data, false);
        assert_eq!(reader.read_u16_at(0).unwrap(), 0xAABB);
        assert_eq!(reader.read_u32_at(2).unwrap(), 0xCCDDEEFF);
        assert_eq!(reader.cursor(), 0); // cursor unchanged
    }

    #[test]
    fn test_binary_reader_string() {
        let data = b"hello\0world\0";
        let mut reader = BinaryReader::from_bytes(data, true);
        assert_eq!(reader.read_next_cstring().unwrap(), "hello");
        assert_eq!(reader.read_next_cstring().unwrap(), "world");
    }

    #[test]
    fn test_binary_reader_fixed_string() {
        let data = b"hello\0\0\0";
        let mut reader = BinaryReader::from_bytes(data, true);
        assert_eq!(reader.read_next_fixed_string(8).unwrap(), "hello");
    }

    #[test]
    fn test_binary_reader_remaining() {
        let data = vec![0u8; 10];
        let mut reader = BinaryReader::from_bytes(&data, true);
        assert_eq!(reader.remaining(), 10);
        reader.advance(3);
        assert_eq!(reader.remaining(), 7);
    }

    #[test]
    fn test_reader_f32_f64() {
        let val_f32: f32 = 3.14;
        let bytes_f32 = val_f32.to_bits().to_le_bytes();
        let mut reader = BinaryReader::from_bytes(&bytes_f32, true);
        let decoded = reader.read_next_f32().unwrap();
        assert!((decoded - val_f32).abs() < f32::EPSILON);

        let val_f64: f64 = 2.718281828;
        let bytes_f64 = val_f64.to_bits().to_le_bytes();
        let mut reader = BinaryReader::from_bytes(&bytes_f64, true);
        let decoded = reader.read_next_f64().unwrap();
        assert!((decoded - val_f64).abs() < f64::EPSILON);
    }

    #[test]
    fn test_binary_reader_utf16_cstring() {
        // "Hi" in UTF-16LE followed by null terminator
        let data: Vec<u8> = vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        let mut reader = BinaryReader::from_bytes(&data, true);
        assert_eq!(reader.read_next_utf16_cstring().unwrap(), "Hi");
    }

    #[test]
    fn test_binary_reader_i8() {
        let data = vec![0xFF_u8]; // -1 as signed
        let mut reader = BinaryReader::from_bytes(&data, true);
        assert_eq!(reader.read_next_i8().unwrap(), -1);
    }

    #[test]
    fn test_binary_reader_as_other_endian() {
        let data = vec![0x01, 0x00, 0x00, 0x00];
        let reader = BinaryReader::from_bytes(&data, true);
        let mut be_reader = reader.as_other_endian(false).unwrap();
        assert_eq!(be_reader.read_next_u32().unwrap(), 0x01000000);
    }

    #[test]
    fn test_sizeof_constants() {
        assert_eq!(BinaryReader::SIZEOF_BYTE, 1);
        assert_eq!(BinaryReader::SIZEOF_SHORT, 2);
        assert_eq!(BinaryReader::SIZEOF_INT, 4);
        assert_eq!(BinaryReader::SIZEOF_LONG, 8);
    }
}
