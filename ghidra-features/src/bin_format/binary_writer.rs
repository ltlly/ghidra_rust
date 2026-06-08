//! Endian-aware binary writer ported from Ghidra's `Writeable` and `DataConverter`.

use std::io;

// ---------------------------------------------------------------------------
// BinaryWriter
// ---------------------------------------------------------------------------

/// Endian-aware binary writer.
///
/// Ported from Ghidra's `Writeable` interface and `DataConverter` pattern.
pub struct BinaryWriter {
    output: Vec<u8>,
    is_little_endian: bool,
}

impl BinaryWriter {
    /// Create a new writer with the given endianness.
    pub fn new(is_little_endian: bool) -> Self {
        Self {
            output: Vec::new(),
            is_little_endian,
        }
    }

    /// Create a writer with a pre-allocated capacity.
    pub fn with_capacity(capacity: usize, is_little_endian: bool) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
            is_little_endian,
        }
    }

    /// Returns true if the writer is little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    /// Get the current write position (length of output).
    pub fn position(&self) -> u64 {
        self.output.len() as u64
    }

    /// Get the length of the output buffer.
    pub fn len(&self) -> usize {
        self.output.len()
    }

    /// Returns true if the output buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.output.is_empty()
    }

    // --- Write primitives ---

    /// Write a u8.
    pub fn write_u8(&mut self, val: u8) {
        self.output.push(val);
    }

    /// Write a i8.
    pub fn write_i8(&mut self, val: i8) {
        self.output.push(val as u8);
    }

    /// Write a u16.
    pub fn write_u16(&mut self, val: u16) {
        let bytes = if self.is_little_endian {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        self.output.extend_from_slice(&bytes);
    }

    /// Write a i16.
    pub fn write_i16(&mut self, val: i16) {
        self.write_u16(val as u16);
    }

    /// Write a u32.
    pub fn write_u32(&mut self, val: u32) {
        let bytes = if self.is_little_endian {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        self.output.extend_from_slice(&bytes);
    }

    /// Write a i32.
    pub fn write_i32(&mut self, val: i32) {
        self.write_u32(val as u32);
    }

    /// Write a u64.
    pub fn write_u64(&mut self, val: u64) {
        let bytes = if self.is_little_endian {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        self.output.extend_from_slice(&bytes);
    }

    /// Write a i64.
    pub fn write_i64(&mut self, val: i64) {
        self.write_u64(val as u64);
    }

    /// Write a f32.
    pub fn write_f32(&mut self, val: f32) {
        self.write_u32(val.to_bits());
    }

    /// Write a f64.
    pub fn write_f64(&mut self, val: f64) {
        self.write_u64(val.to_bits());
    }

    /// Write raw bytes.
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.output.extend_from_slice(data);
    }

    /// Write a null-terminated C string.
    pub fn write_cstring(&mut self, s: &str) {
        self.output.extend_from_slice(s.as_bytes());
        self.output.push(0);
    }

    /// Write a UTF-16 null-terminated string.
    pub fn write_utf16_cstring(&mut self, s: &str) {
        for cu in s.encode_utf16() {
            self.write_u16(cu);
        }
        self.write_u16(0);
    }

    /// Pad the output with zeros to reach the given alignment.
    pub fn align(&mut self, alignment: usize) {
        let current = self.output.len();
        let padding = (alignment - (current % alignment)) % alignment;
        self.output.extend(std::iter::repeat_n(0u8, padding));
    }

    /// Pad the output with a specific byte value to reach alignment.
    pub fn align_with(&mut self, alignment: usize, fill: u8) {
        let current = self.output.len();
        let padding = (alignment - (current % alignment)) % alignment;
        self.output.extend(std::iter::repeat_n(fill, padding));
    }

    /// Write `count` zero bytes.
    pub fn write_zeros(&mut self, count: usize) {
        self.output.extend(std::iter::repeat_n(0u8, count));
    }

    /// Consume the writer and return the output bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.output
    }

    /// Get a reference to the output bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.output
    }

    /// Get a mutable reference to the output bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.output
    }

    /// Clear the output buffer.
    pub fn clear(&mut self) {
        self.output.clear();
    }

    /// Truncate the output to the given length.
    pub fn truncate(&mut self, len: usize) {
        self.output.truncate(len);
    }

    /// Set the write position by truncating or zero-padding.
    pub fn set_position(&mut self, pos: usize) {
        if pos < self.output.len() {
            self.output.truncate(pos);
        } else if pos > self.output.len() {
            self.write_zeros(pos - self.output.len());
        }
    }
}

/// Trait for types that can write themselves to a binary format.
///
/// Ported from `ghidra.app.util.bin.format.Writeable`.
pub trait BinaryWritable {
    /// Write this object using the given writer.
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_writer() {
        let mut writer = BinaryWriter::new(true);
        writer.write_u8(0x01);
        writer.write_u16(0x0203);
        writer.write_u32(0x04050607);
        let data = writer.into_vec();
        assert_eq!(data, vec![0x01, 0x03, 0x02, 0x07, 0x06, 0x05, 0x04]);
    }

    #[test]
    fn test_binary_writer_be() {
        let mut writer = BinaryWriter::new(false);
        writer.write_u16(0x0203);
        writer.write_u32(0x04050607);
        let data = writer.into_vec();
        assert_eq!(data, vec![0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn test_binary_writer_align() {
        let mut writer = BinaryWriter::new(true);
        writer.write_u8(0xAA);
        writer.write_u8(0xBB);
        writer.align(4);
        assert_eq!(writer.position(), 4);
        assert_eq!(writer.as_slice(), &[0xAA, 0xBB, 0x00, 0x00]);
    }

    #[test]
    fn test_binary_writer_cstring() {
        let mut writer = BinaryWriter::new(true);
        writer.write_cstring("test");
        assert_eq!(writer.as_slice(), b"test\0");
    }

    #[test]
    fn test_binary_writer_i8() {
        let mut writer = BinaryWriter::new(true);
        writer.write_i8(-1);
        assert_eq!(writer.as_slice(), &[0xFF]);
    }

    #[test]
    fn test_binary_writer_f32() {
        let mut writer = BinaryWriter::new(true);
        writer.write_f32(3.14);
        let data = writer.into_vec();
        let val = f32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert!((val - 3.14).abs() < f32::EPSILON);
    }

    #[test]
    fn test_binary_writer_f64() {
        let mut writer = BinaryWriter::new(true);
        writer.write_f64(2.718281828);
        let data = writer.into_vec();
        let val = f64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        assert!((val - 2.718281828).abs() < f64::EPSILON);
    }

    #[test]
    fn test_binary_writer_utf16_cstring() {
        let mut writer = BinaryWriter::new(true);
        writer.write_utf16_cstring("Hi");
        // 'H'=0x0048, 'i'=0x0069, null=0x0000 in LE
        assert_eq!(
            writer.as_slice(),
            &[0x48, 0x00, 0x69, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_binary_writer_align_with() {
        let mut writer = BinaryWriter::new(true);
        writer.write_u8(0xAA);
        writer.align_with(4, 0xFF);
        assert_eq!(writer.as_slice(), &[0xAA, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_binary_writer_zeros() {
        let mut writer = BinaryWriter::new(true);
        writer.write_u8(0x01);
        writer.write_zeros(3);
        assert_eq!(writer.as_slice(), &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_binary_writer_set_position() {
        let mut writer = BinaryWriter::new(true);
        writer.write_u32(0xDEADBEEF);
        writer.set_position(2);
        assert_eq!(writer.len(), 2);
        assert_eq!(writer.as_slice(), &[0xEF, 0xBE]);

        writer.set_position(6);
        assert_eq!(writer.len(), 6);
        assert_eq!(writer.as_slice(), &[0xEF, 0xBE, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_binary_writer_with_capacity() {
        let writer = BinaryWriter::with_capacity(1024, true);
        assert!(writer.is_empty());
        assert_eq!(writer.len(), 0);
        assert_eq!(writer.position(), 0);
    }

    #[test]
    fn test_binary_writer_clear() {
        let mut writer = BinaryWriter::new(true);
        writer.write_u32(0x12345678);
        assert!(!writer.is_empty());
        writer.clear();
        assert!(writer.is_empty());
    }

    #[test]
    fn test_binary_writer_i64() {
        let mut writer = BinaryWriter::new(true);
        writer.write_i64(-123456789012345i64);
        let data = writer.into_vec();
        let val = i64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        assert_eq!(val, -123456789012345i64);
    }
}
