//! PDB byte reader -- low-level binary parsing primitives.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader`
//! and related Java byte-buffer utilities.
//!
//! Provides a cursor-based reader over a byte slice with bounds-checked
//! reads for all common PDB primitive types (u8, u16, u32, u64, i8, i16,
//! i32, i64, f32, f64), null-terminated string extraction, alignment
//! helpers, and sub-slice splitting.

use std::fmt;

use super::pdb_exception::PdbException;

// =============================================================================
// PdbByteReader
// =============================================================================
/// A cursor-based reader over a byte slice for parsing PDB data.
///
/// Tracks a current position and provides bounds-checked reads for all
/// common PDB primitive types. This replaces the scattered inline
/// `read_u32_le` / `le_u32_at` / `read_u16_le` helper functions.
pub struct PdbByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PdbByteReader<'a> {
    /// Create a new reader over the given byte slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Create a reader starting at a specific offset.
    pub fn new_at(data: &'a [u8], offset: usize) -> Self {
        Self { data, pos: offset.min(data.len()) }
    }

    // =========================================================================
    // Position / capacity
    // =========================================================================

    /// Current read position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Set the read position.
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos.min(self.data.len());
    }

    /// Advance the position by `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<(), PdbException> {
        if self.pos + n > self.data.len() {
            return Err(PdbException::truncated("skip", n, self.data.len() - self.pos));
        }
        self.pos += n;
        Ok(())
    }

    /// Number of bytes remaining from the current position.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Whether the reader has reached the end of the data.
    pub fn is_eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// The total length of the underlying data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the underlying data is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the full underlying byte slice.
    pub fn as_slice(&self) -> &'a [u8] {
        self.data
    }

    /// Return the remaining unread bytes.
    pub fn remaining_slice(&self) -> &'a [u8] {
        if self.pos >= self.data.len() {
            &[]
        } else {
            &self.data[self.pos..]
        }
    }

    // =========================================================================
    // Primitive reads (little-endian)
    // =========================================================================

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8, PdbException> {
        if self.pos + 1 > self.data.len() {
            return Err(PdbException::truncated("u8", 1, self.remaining()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a signed byte.
    pub fn read_i8(&mut self) -> Result<i8, PdbException> {
        Ok(self.read_u8()? as i8)
    }

    /// Read a little-endian u16.
    pub fn read_u16(&mut self) -> Result<u16, PdbException> {
        if self.pos + 2 > self.data.len() {
            return Err(PdbException::truncated("u16", 2, self.remaining()));
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read a little-endian i16.
    pub fn read_i16(&mut self) -> Result<i16, PdbException> {
        Ok(self.read_u16()? as i16)
    }

    /// Read a little-endian u32.
    pub fn read_u32(&mut self) -> Result<u32, PdbException> {
        if self.pos + 4 > self.data.len() {
            return Err(PdbException::truncated("u32", 4, self.remaining()));
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Read a little-endian i32.
    pub fn read_i32(&mut self) -> Result<i32, PdbException> {
        Ok(self.read_u32()? as i32)
    }

    /// Read a little-endian u64.
    pub fn read_u64(&mut self) -> Result<u64, PdbException> {
        if self.pos + 8 > self.data.len() {
            return Err(PdbException::truncated("u64", 8, self.remaining()));
        }
        let v = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    /// Read a little-endian i64.
    pub fn read_i64(&mut self) -> Result<i64, PdbException> {
        Ok(self.read_u64()? as i64)
    }

    /// Read a little-endian f32.
    pub fn read_f32(&mut self) -> Result<f32, PdbException> {
        Ok(f32::from_bits(self.read_u32()?))
    }

    /// Read a little-endian f64.
    pub fn read_f64(&mut self) -> Result<f64, PdbException> {
        Ok(f64::from_bits(self.read_u64()?))
    }

    // =========================================================================
    // Bulk / slice reads
    // =========================================================================

    /// Read exactly `n` bytes and return them as a `Vec<u8>`.
    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, PdbException> {
        if self.pos + n > self.data.len() {
            return Err(PdbException::truncated("bytes", n, self.remaining()));
        }
        let v = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    /// Read exactly `n` bytes as a borrowed slice (zero-copy).
    ///
    /// The returned slice borrows from the reader's underlying data.
    pub fn read_slice(&mut self, n: usize) -> Result<&'a [u8], PdbException> {
        if self.pos + n > self.data.len() {
            return Err(PdbException::truncated("slice", n, self.remaining()));
        }
        let v = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(v)
    }

    /// Copy `n` bytes into the provided destination buffer.
    ///
    /// Returns an error if there are fewer than `n` bytes remaining.
    pub fn read_into(&mut self, dest: &mut [u8]) -> Result<(), PdbException> {
        let n = dest.len();
        if self.pos + n > self.data.len() {
            return Err(PdbException::truncated("into", n, self.remaining()));
        }
        dest.copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(())
    }

    // =========================================================================
    // String reads
    // =========================================================================

    /// Read a null-terminated string starting at the current position.
    ///
    /// Advances past the null terminator. Returns an empty string if
    /// the terminator is not found before EOF.
    pub fn read_cstring(&mut self) -> Result<String, PdbException> {
        let remaining = &self.data[self.pos..];
        let end = remaining.iter().position(|&b| b == 0).unwrap_or(remaining.len());
        let s = String::from_utf8_lossy(&remaining[..end]).to_string();
        self.pos += end;
        if self.pos < self.data.len() {
            self.pos += 1; // skip null terminator
        }
        Ok(s)
    }

    /// Read a null-terminated string and align the position to 4 bytes.
    ///
    /// This matches the PDB convention where some string fields are
    /// followed by padding to the next 4-byte boundary.
    pub fn read_cstring_aligned4(&mut self) -> Result<String, PdbException> {
        let s = self.read_cstring()?;
        // Align to next 4-byte boundary
        self.pos = (self.pos + 3) & !3;
        Ok(s)
    }

    /// Read a length-prefixed string (2-byte LE length followed by UTF-8 bytes).
    ///
    /// The length does NOT include the 2-byte prefix itself.
    pub fn read_len_string(&mut self) -> Result<String, PdbException> {
        let len = self.read_u16()? as usize;
        let bytes = self.read_bytes(len)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    // =========================================================================
    // Alignment
    // =========================================================================

    /// Align the current position up to the next `alignment`-byte boundary.
    ///
    /// `alignment` must be a power of two. Commonly used with alignment=4.
    pub fn align(&mut self, alignment: usize) {
        debug_assert!(alignment.is_power_of_two());
        self.pos = (self.pos + alignment - 1) & !(alignment - 1);
    }

    // =========================================================================
    // Peeking (non-advancing reads)
    // =========================================================================

    /// Peek at the next u8 without advancing.
    pub fn peek_u8(&self) -> Result<u8, PdbException> {
        if self.pos + 1 > self.data.len() {
            return Err(PdbException::truncated("peek_u8", 1, self.remaining()));
        }
        Ok(self.data[self.pos])
    }

    /// Peek at the next u16 without advancing.
    pub fn peek_u16(&self) -> Result<u16, PdbException> {
        if self.pos + 2 > self.data.len() {
            return Err(PdbException::truncated("peek_u16", 2, self.remaining()));
        }
        Ok(u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]))
    }

    /// Peek at the next u32 without advancing.
    pub fn peek_u32(&self) -> Result<u32, PdbException> {
        if self.pos + 4 > self.data.len() {
            return Err(PdbException::truncated("peek_u32", 4, self.remaining()));
        }
        Ok(u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]))
    }

    // =========================================================================
    // Sub-reader
    // =========================================================================

    /// Create a new reader over a sub-slice of `n` bytes starting at the
    /// current position, and advance past it.
    ///
    /// This is useful for parsing nested record structures.
    pub fn sub_reader(&mut self, n: usize) -> Result<PdbByteReader<'a>, PdbException> {
        let slice = self.read_slice(n)?;
        Ok(PdbByteReader::new(slice))
    }

    /// Create a new reader spanning from the current position to the end.
    pub fn tail_reader(&mut self) -> PdbByteReader<'a> {
        let slice = &self.data[self.pos..];
        self.pos = self.data.len();
        PdbByteReader::new(slice)
    }
}

impl<'a> fmt::Debug for PdbByteReader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdbByteReader")
            .field("len", &self.data.len())
            .field("pos", &self.pos)
            .field("remaining", &self.remaining())
            .finish()
    }
}

// =============================================================================
// Standalone helpers (non-cursor, used by existing mod.rs inline code)
// =============================================================================
/// Read a little-endian u16 from `data` at `offset` (no bounds check).
///
/// # Safety
/// Caller must ensure `offset + 2 <= data.len()`.
#[inline]
pub fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian u32 from `data` at `offset` (no bounds check).
///
/// # Safety
/// Caller must ensure `offset + 4 <= data.len()`.
#[inline]
pub fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Read a little-endian u64 from `data` at `offset` (no bounds check).
#[inline]
pub fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}

/// Read a little-endian i32 from `data` at `offset`.
#[inline]
pub fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Extract a null-terminated string starting at `data[offset]`.
///
/// Returns `(string, byte_after_null)`.
pub fn read_null_terminated_string(data: &[u8], offset: usize) -> (String, usize) {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    if end >= data.len() {
        return (String::from_utf8_lossy(&data[offset..end]).to_string(), end);
    }
    let s = String::from_utf8_lossy(&data[offset..end]).to_string();
    (s, end + 1)
}

/// Parse a null-terminated string from the start of a byte slice.
pub fn parse_null_terminated_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Check whether `n` is a power of two.
#[inline]
pub fn is_power_of_two(n: u32) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// Parse an MSFT Numeric value from `data` at `offset`.
///
/// Returns `(value, next_offset)`. Small values (< 0x8000) are encoded
/// directly in a u16; larger values use a variant tag byte.
pub fn parse_numeric(data: &[u8], offset: usize) -> (u64, usize) {
    if offset + 2 > data.len() {
        return (0, offset);
    }
    let low = read_u16_le(data, offset);
    if low < 0x8000 {
        return (low as u64, offset + 2);
    }
    if offset + 3 > data.len() {
        return (0, offset);
    }
    let variant = data[offset + 2];
    match variant {
        0x00 => {
            if offset + 5 > data.len() { return (0, offset + 3); }
            (read_u16_le(data, offset + 3) as u64, offset + 5)
        }
        0x01 => {
            if offset + 5 > data.len() { return (0, offset + 3); }
            (i16::from_le_bytes([data[offset + 3], data[offset + 4]]) as u64, offset + 5)
        }
        0x02 => {
            if offset + 7 > data.len() { return (0, offset + 3); }
            (read_u32_le(data, offset + 3) as u64, offset + 7)
        }
        0x03 => {
            if offset + 7 > data.len() { return (0, offset + 3); }
            (i32::from_le_bytes([
                data[offset + 3], data[offset + 4], data[offset + 5], data[offset + 6],
            ]) as u64, offset + 7)
        }
        0x10 => {
            if offset + 11 > data.len() { return (0, offset + 3); }
            (
                u64::from_le_bytes([
                    data[offset + 3], data[offset + 4], data[offset + 5], data[offset + 6],
                    data[offset + 7], data[offset + 8], data[offset + 9], data[offset + 10],
                ]),
                offset + 11,
            )
        }
        _ => (low as u64, offset + 2),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u8() {
        let data = [0x42u8];
        let mut r = PdbByteReader::new(&data);
        assert_eq!(r.read_u8().unwrap(), 0x42);
        assert!(r.is_eof());
    }

    #[test]
    fn test_read_u16_le() {
        let data = [0x34, 0x12];
        let mut r = PdbByteReader::new(&data);
        assert_eq!(r.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x78, 0x56, 0x34, 0x12];
        let mut r = PdbByteReader::new(&data);
        assert_eq!(r.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_u64_le() {
        let data = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let mut r = PdbByteReader::new(&data);
        assert_eq!(r.read_u64().unwrap(), 0x0102030405060708);
    }

    #[test]
    fn test_read_f32() {
        let val: f32 = 3.14;
        let bytes = val.to_le_bytes();
        let mut r = PdbByteReader::new(&bytes);
        assert!((r.read_f32().unwrap() - 3.14).abs() < 1e-6);
    }

    #[test]
    fn test_read_cstring() {
        let data = b"hello\0world";
        let mut r = PdbByteReader::new(data);
        assert_eq!(r.read_cstring().unwrap(), "hello");
        assert_eq!(r.position(), 6); // past the null
    }

    #[test]
    fn test_read_cstring_aligned4() {
        let data = b"hi\0\x00extra"; // 'h','i','\0','\0' then 'extra'
        let mut r = PdbByteReader::new(data);
        assert_eq!(r.read_cstring_aligned4().unwrap(), "hi");
        assert_eq!(r.position(), 4); // aligned to 4
    }

    #[test]
    fn test_read_bytes() {
        let data = [1u8, 2, 3, 4, 5];
        let mut r = PdbByteReader::new(&data);
        let buf = r.read_bytes(3).unwrap();
        assert_eq!(buf, vec![1, 2, 3]);
        assert_eq!(r.position(), 3);
    }

    #[test]
    fn test_read_slice() {
        let data = [10u8, 20, 30, 40];
        let mut r = PdbByteReader::new(&data);
        let s = r.read_slice(2).unwrap();
        assert_eq!(s, &[10, 20]);
    }

    #[test]
    fn test_read_into() {
        let data = [0xAA, 0xBB, 0xCC];
        let mut r = PdbByteReader::new(&data);
        let mut buf = [0u8; 2];
        r.read_into(&mut buf).unwrap();
        assert_eq!(buf, [0xAA, 0xBB]);
    }

    #[test]
    fn test_skip() {
        let data = [0u8; 10];
        let mut r = PdbByteReader::new(&data);
        r.skip(5).unwrap();
        assert_eq!(r.position(), 5);
        assert_eq!(r.remaining(), 5);
    }

    #[test]
    fn test_peek() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let r = PdbByteReader::new(&data);
        assert_eq!(r.peek_u8().unwrap(), 0x12);
        assert_eq!(r.peek_u16().unwrap(), 0x3412);
        assert_eq!(r.peek_u32().unwrap(), 0x78563412);
        assert_eq!(r.position(), 0); // did not advance
    }

    #[test]
    fn test_sub_reader() {
        let data = [1u8, 2, 3, 4, 5, 6];
        let mut r = PdbByteReader::new(&data);
        r.skip(1).unwrap();
        let mut sub = r.sub_reader(3).unwrap();
        assert_eq!(sub.read_u8().unwrap(), 2);
        assert_eq!(sub.read_u16().unwrap(), 0x0403);
        assert_eq!(r.position(), 4);
    }

    #[test]
    fn test_tail_reader() {
        let data = [1u8, 2, 3, 4, 5];
        let mut r = PdbByteReader::new(&data);
        r.skip(2).unwrap();
        let mut tail = r.tail_reader();
        assert_eq!(tail.remaining(), 3);
        assert_eq!(tail.read_bytes(3).unwrap(), vec![3, 4, 5]);
    }

    #[test]
    fn test_align() {
        let data = [0u8; 16];
        let mut r = PdbByteReader::new(&data);
        r.skip(5).unwrap();
        r.align(4);
        assert_eq!(r.position(), 8);
    }

    #[test]
    fn test_read_i8() {
        let data = [0xFEu8]; // -2 as i8
        let mut r = PdbByteReader::new(&data);
        assert_eq!(r.read_i8().unwrap(), -2);
    }

    #[test]
    fn test_read_i16() {
        let data = [0xFF, 0x7F]; // 32767
        let mut r = PdbByteReader::new(&data);
        assert_eq!(r.read_i16().unwrap(), 32767);
    }

    #[test]
    fn test_read_i32() {
        let data = [0xFF, 0xFF, 0xFF, 0x7F]; // i32::MAX
        let mut r = PdbByteReader::new(&data);
        assert_eq!(r.read_i32().unwrap(), i32::MAX);
    }

    #[test]
    fn test_read_f64() {
        let val: f64 = 2.718281828;
        let bytes = val.to_le_bytes();
        let mut r = PdbByteReader::new(&bytes);
        assert!((r.read_f64().unwrap() - 2.718281828).abs() < 1e-9);
    }

    #[test]
    fn test_eof_error() {
        let data = [0u8; 2];
        let mut r = PdbByteReader::new(&data);
        r.skip(2).unwrap();
        assert!(r.read_u32().is_err());
    }

    #[test]
    fn test_read_len_string() {
        // "AB" = length 2, then 'A', 'B'
        let data = [2u8, 0, b'A', b'B'];
        let mut r = PdbByteReader::new(&data);
        assert_eq!(r.read_len_string().unwrap(), "AB");
    }

    // Standalone helper tests

    #[test]
    fn test_standalone_read_u16_le() {
        assert_eq!(read_u16_le(&[0x34, 0x12], 0), 0x1234);
    }

    #[test]
    fn test_standalone_read_u32_le() {
        assert_eq!(read_u32_le(&[0x78, 0x56, 0x34, 0x12], 0), 0x12345678);
    }

    #[test]
    fn test_standalone_read_u64_le() {
        assert_eq!(
            read_u64_le(&[0, 1, 2, 3, 4, 5, 6, 7], 0),
            0x0706050403020100
        );
    }

    #[test]
    fn test_standalone_parse_null_terminated_string() {
        assert_eq!(parse_null_terminated_string(b"hello\0world"), "hello");
        assert_eq!(parse_null_terminated_string(b"no_null"), "no_null");
    }

    #[test]
    fn test_standalone_read_null_terminated_string() {
        let data = b"\0abc\0";
        let (s, pos) = read_null_terminated_string(data, 0);
        assert_eq!(s, "");
        assert_eq!(pos, 1);

        let (s2, pos2) = read_null_terminated_string(data, 1);
        assert_eq!(s2, "abc");
        assert_eq!(pos2, 5);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(4096));
        assert!(!is_power_of_two(0));
        assert!(!is_power_of_two(3));
    }

    #[test]
    fn test_parse_numeric_small() {
        let data = [42u8, 0];
        let (val, off) = parse_numeric(&data, 0);
        assert_eq!(val, 42);
        assert_eq!(off, 2);
    }

    #[test]
    fn test_parse_numeric_u32() {
        // LF_LONG variant (0x02) followed by 4 bytes
        let data = [0x00, 0x80, 0x02, 0x78, 0x56, 0x34, 0x12];
        let (val, off) = parse_numeric(&data, 0);
        assert_eq!(val, 0x12345678);
        assert_eq!(off, 7);
    }
}
