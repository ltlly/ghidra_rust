//! Data conversion utilities for Ghidra Rust.
//!
//! Direct translation of `ghidra.util.GhidraDataConverter` and
//! `ghidra.util.GhidraLittleEndianDataConverter`/`GhidraBigEndianDataConverter`.
//!
//! Provides [`GhidraDataConverter`] for converting between byte arrays and
//! primitive values with configurable endianness.

use serde::{Deserialize, Serialize};

/// Converts between byte arrays and primitive values.
///
/// Corresponds to `ghidra.util.GhidraDataConverter`.
///
/// This converter handles endianness-aware conversion of byte arrays to
/// and from primitive types (u8, u16, u32, u64, i8, i16, i32, i64, f32, f64).
///
/// # Examples
///
/// ```
/// use ghidra_core::util::converter::GhidraDataConverter;
///
/// let le = GhidraDataConverter::little_endian();
/// assert_eq!(le.get_u16(&[0x01, 0x02]), 0x0201);
///
/// let be = GhidraDataConverter::big_endian();
/// assert_eq!(be.get_u16(&[0x01, 0x02]), 0x0102);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhidraDataConverter {
    big_endian: bool,
}

impl GhidraDataConverter {
    /// Create a big-endian converter.
    pub fn big_endian() -> Self {
        Self { big_endian: true }
    }

    /// Create a little-endian converter.
    pub fn little_endian() -> Self {
        Self { big_endian: false }
    }

    /// Create a converter with the specified endianness.
    pub fn new(big_endian: bool) -> Self {
        Self { big_endian }
    }

    /// Returns true if this converter is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    // ---- Unsigned integer reads ----

    /// Read an unsigned 16-bit value from the byte array at the given offset.
    pub fn get_u16(&self, bytes: &[u8]) -> u16 {
        let b = [bytes[0], bytes[1]];
        if self.big_endian {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        }
    }

    /// Read an unsigned 32-bit value from the byte array at the given offset.
    pub fn get_u32(&self, bytes: &[u8]) -> u32 {
        let b = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    }

    /// Read an unsigned 64-bit value from the byte array at the given offset.
    pub fn get_u64(&self, bytes: &[u8]) -> u64 {
        let b = [bytes[0], bytes[1], bytes[2], bytes[3],
                 bytes[4], bytes[5], bytes[6], bytes[7]];
        if self.big_endian {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        }
    }

    // ---- Signed integer reads ----

    /// Read a signed 16-bit value from the byte array at the given offset.
    pub fn get_i16(&self, bytes: &[u8]) -> i16 {
        self.get_u16(bytes) as i16
    }

    /// Read a signed 32-bit value from the byte array at the given offset.
    pub fn get_i32(&self, bytes: &[u8]) -> i32 {
        self.get_u32(bytes) as i32
    }

    /// Read a signed 64-bit value from the byte array at the given offset.
    pub fn get_i64(&self, bytes: &[u8]) -> i64 {
        self.get_u64(bytes) as i64
    }

    // ---- Float reads ----

    /// Read a 32-bit float from the byte array at the given offset.
    pub fn get_f32(&self, bytes: &[u8]) -> f32 {
        f32::from_bits(self.get_u32(bytes))
    }

    /// Read a 64-bit double from the byte array at the given offset.
    pub fn get_f64(&self, bytes: &[u8]) -> f64 {
        f64::from_bits(self.get_u64(bytes))
    }

    // ---- Unsigned integer writes ----

    /// Write an unsigned 16-bit value to the byte array at the given offset.
    pub fn put_u16(&self, buf: &mut [u8], value: u16) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        buf[..2].copy_from_slice(&bytes);
    }

    /// Write an unsigned 32-bit value to the byte array at the given offset.
    pub fn put_u32(&self, buf: &mut [u8], value: u32) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        buf[..4].copy_from_slice(&bytes);
    }

    /// Write an unsigned 64-bit value to the byte array at the given offset.
    pub fn put_u64(&self, buf: &mut [u8], value: u64) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        buf[..8].copy_from_slice(&bytes);
    }

    // ---- Signed integer writes ----

    /// Write a signed 16-bit value to the byte array at the given offset.
    pub fn put_i16(&self, buf: &mut [u8], value: i16) {
        self.put_u16(buf, value as u16);
    }

    /// Write a signed 32-bit value to the byte array at the given offset.
    pub fn put_i32(&self, buf: &mut [u8], value: i32) {
        self.put_u32(buf, value as u32);
    }

    /// Write a signed 64-bit value to the byte array at the given offset.
    pub fn put_i64(&self, buf: &mut [u8], value: i64) {
        self.put_u64(buf, value as u64);
    }

    // ---- Float writes ----

    /// Write a 32-bit float to the byte array at the given offset.
    pub fn put_f32(&self, buf: &mut [u8], value: f32) {
        self.put_u32(buf, value.to_bits());
    }

    /// Write a 64-bit double to the byte array at the given offset.
    pub fn put_f64(&self, buf: &mut [u8], value: f64) {
        self.put_u64(buf, value.to_bits());
    }

    // ---- Utility methods ----

    /// Convert a byte array to a hex string.
    pub fn bytes_to_hex(&self, bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
    }

    /// Get the name of this converter's endianness.
    pub fn endian_name(&self) -> &'static str {
        if self.big_endian { "BigEndian" } else { "LittleEndian" }
    }
}

impl Default for GhidraDataConverter {
    /// Default is little-endian.
    fn default() -> Self {
        Self::little_endian()
    }
}

impl std::fmt::Display for GhidraDataConverter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GhidraDataConverter({})", self.endian_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_little_endian_u16() {
        let conv = GhidraDataConverter::little_endian();
        assert_eq!(conv.get_u16(&[0x01, 0x02]), 0x0201);
        assert_eq!(conv.get_u16(&[0xFF, 0xFF]), 0xFFFF);
    }

    #[test]
    fn test_big_endian_u16() {
        let conv = GhidraDataConverter::big_endian();
        assert_eq!(conv.get_u16(&[0x01, 0x02]), 0x0102);
        assert_eq!(conv.get_u16(&[0xFF, 0xFF]), 0xFFFF);
    }

    #[test]
    fn test_little_endian_u32() {
        let conv = GhidraDataConverter::little_endian();
        assert_eq!(conv.get_u32(&[0x01, 0x02, 0x03, 0x04]), 0x04030201);
    }

    #[test]
    fn test_big_endian_u32() {
        let conv = GhidraDataConverter::big_endian();
        assert_eq!(conv.get_u32(&[0x01, 0x02, 0x03, 0x04]), 0x01020304);
    }

    #[test]
    fn test_little_endian_u64() {
        let conv = GhidraDataConverter::little_endian();
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(conv.get_u64(&bytes), 0x0807060504030201);
    }

    #[test]
    fn test_big_endian_u64() {
        let conv = GhidraDataConverter::big_endian();
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(conv.get_u64(&bytes), 0x0102030405060708);
    }

    #[test]
    fn test_signed() {
        let conv = GhidraDataConverter::little_endian();
        assert_eq!(conv.get_i16(&[0xFF, 0xFF]), -1);
        assert_eq!(conv.get_i32(&[0xFF, 0xFF, 0xFF, 0xFF]), -1);
        assert_eq!(conv.get_i64(&[0xFF; 8]), -1);
    }

    #[test]
    fn test_float() {
        let conv = GhidraDataConverter::little_endian();
        let val: f32 = 3.14;
        let mut buf = [0u8; 4];
        conv.put_f32(&mut buf, val);
        assert_eq!(conv.get_f32(&buf), val);
    }

    #[test]
    fn test_double() {
        let conv = GhidraDataConverter::big_endian();
        let val: f64 = 3.141592653589793;
        let mut buf = [0u8; 8];
        conv.put_f64(&mut buf, val);
        assert_eq!(conv.get_f64(&buf), val);
    }

    #[test]
    fn test_write_read_roundtrip() {
        let conv = GhidraDataConverter::big_endian();
        let mut buf = [0u8; 8];

        conv.put_u16(&mut buf, 0xBEEF);
        assert_eq!(conv.get_u16(&buf), 0xBEEF);

        conv.put_u32(&mut buf, 0xDEADBEEF);
        assert_eq!(conv.get_u32(&buf), 0xDEADBEEF);

        conv.put_u64(&mut buf, 0xCAFEBABEDEADBEEF);
        assert_eq!(conv.get_u64(&buf), 0xCAFEBABEDEADBEEF);
    }

    #[test]
    fn test_put_i16() {
        let conv = GhidraDataConverter::little_endian();
        let mut buf = [0u8; 2];
        conv.put_i16(&mut buf, -1);
        assert_eq!(buf, [0xFF, 0xFF]);
    }

    #[test]
    fn test_put_i32() {
        let conv = GhidraDataConverter::big_endian();
        let mut buf = [0u8; 4];
        conv.put_i32(&mut buf, -1);
        assert_eq!(buf, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_bytes_to_hex() {
        let conv = GhidraDataConverter::little_endian();
        assert_eq!(conv.bytes_to_hex(&[0x0A, 0xFF, 0x00]), "0a ff 00");
    }

    #[test]
    fn test_endian_name() {
        assert_eq!(GhidraDataConverter::big_endian().endian_name(), "BigEndian");
        assert_eq!(GhidraDataConverter::little_endian().endian_name(), "LittleEndian");
    }

    #[test]
    fn test_default() {
        let conv = GhidraDataConverter::default();
        assert!(!conv.is_big_endian());
    }

    #[test]
    fn test_display() {
        let conv = GhidraDataConverter::big_endian();
        assert_eq!(format!("{}", conv), "GhidraDataConverter(BigEndian)");
    }

    #[test]
    fn test_is_big_endian() {
        assert!(GhidraDataConverter::big_endian().is_big_endian());
        assert!(!GhidraDataConverter::little_endian().is_big_endian());
    }

    #[test]
    fn test_new() {
        assert!(GhidraDataConverter::new(true).is_big_endian());
        assert!(!GhidraDataConverter::new(false).is_big_endian());
    }
}
