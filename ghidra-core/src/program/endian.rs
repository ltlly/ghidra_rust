//! Endianness definitions for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.lang.Endian`.
//!
//! Provides the [`Endian`] enum for representing byte order (big-endian vs
//! little-endian), with parsing, display, and conversion utilities.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents the byte order (endianness) of a processor or data layout.
///
/// Corresponds to `ghidra.program.model.lang.Endian`.
///
/// # Variants
///
/// * `Big` — big-endian: most significant byte at lowest address.
/// * `Little` — little-endian: least significant byte at lowest address.
///
/// # Examples
///
/// ```
/// use ghidra_core::program::endian::Endian;
///
/// let e = Endian::from_str("BE").unwrap();
/// assert!(e.is_big_endian());
/// assert_eq!(e.to_short_string(), "BE");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endian {
    /// Big-endian byte order (most significant byte first).
    Big,
    /// Little-endian byte order (least significant byte first).
    Little,
}

impl Endian {
    /// Parse an endianness string.
    ///
    /// Accepts `"big"`, `"BIG"`, `"BE"`, `"be"` for big-endian and
    /// `"little"`, `"LITTLE"`, `"LE"`, `"le"` for little-endian.
    /// Returns `None` for unrecognized strings or `None` input.
    ///
    /// Corresponds to `Endian.toEndian(String)` in Java.
    pub fn from_str(s: &str) -> Option<Self> {
        let upper = s.to_uppercase();
        match upper.as_str() {
            "BIG" | "BE" => Some(Endian::Big),
            "LITTLE" | "LE" => Some(Endian::Little),
            _ => None,
        }
    }

    /// Returns the short string form (`"BE"` or `"LE"`).
    ///
    /// Corresponds to `Endian.toShortString()` in Java.
    pub fn to_short_string(&self) -> &'static str {
        match self {
            Endian::Big => "BE",
            Endian::Little => "LE",
        }
    }

    /// Returns `true` if this is big-endian.
    ///
    /// Corresponds to `Endian.isBigEndian()` in Java.
    pub fn is_big_endian(&self) -> bool {
        *self == Endian::Big
    }

    /// Returns `true` if this is little-endian.
    pub fn is_little_endian(&self) -> bool {
        *self == Endian::Little
    }

    /// Returns the display name with first letter capitalized.
    ///
    /// Corresponds to `Endian.getDisplayName()` in Java.
    pub fn display_name(&self) -> &'static str {
        match self {
            Endian::Big => "Big",
            Endian::Little => "Little",
        }
    }

    /// Read a 16-bit value from the given byte slice, respecting endianness.
    pub fn read_u16(&self, bytes: &[u8]) -> u16 {
        match self {
            Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
            Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
        }
    }

    /// Read a 32-bit value from the given byte slice, respecting endianness.
    pub fn read_u32(&self, bytes: &[u8]) -> u32 {
        match self {
            Endian::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Endian::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }

    /// Read a 64-bit value from the given byte slice, respecting endianness.
    pub fn read_u64(&self, bytes: &[u8]) -> u64 {
        match self {
            Endian::Big => u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            Endian::Little => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
        }
    }

    /// Write a 16-bit value into the given byte slice, respecting endianness.
    pub fn write_u16(&self, buf: &mut [u8], value: u16) {
        let bytes = match self {
            Endian::Big => value.to_be_bytes(),
            Endian::Little => value.to_le_bytes(),
        };
        buf[..2].copy_from_slice(&bytes);
    }

    /// Write a 32-bit value into the given byte slice, respecting endianness.
    pub fn write_u32(&self, buf: &mut [u8], value: u32) {
        let bytes = match self {
            Endian::Big => value.to_be_bytes(),
            Endian::Little => value.to_le_bytes(),
        };
        buf[..4].copy_from_slice(&bytes);
    }

    /// Write a 64-bit value into the given byte slice, respecting endianness.
    pub fn write_u64(&self, buf: &mut [u8], value: u64) {
        let bytes = match self {
            Endian::Big => value.to_be_bytes(),
            Endian::Little => value.to_le_bytes(),
        };
        buf[..8].copy_from_slice(&bytes);
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endian::Big => write!(f, "big"),
            Endian::Little => write!(f, "little"),
        }
    }
}

impl Default for Endian {
    /// Default is little-endian (most common in modern architectures).
    fn default() -> Self {
        Endian::Little
    }
}

impl From<bool> for Endian {
    /// `true` = big-endian, `false` = little-endian.
    fn from(is_big: bool) -> Self {
        if is_big { Endian::Big } else { Endian::Little }
    }
}

impl From<Endian> for bool {
    fn from(e: Endian) -> Self {
        e.is_big_endian()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str_big() {
        assert_eq!(Endian::from_str("big"), Some(Endian::Big));
        assert_eq!(Endian::from_str("BIG"), Some(Endian::Big));
        assert_eq!(Endian::from_str("BE"), Some(Endian::Big));
        assert_eq!(Endian::from_str("be"), Some(Endian::Big));
    }

    #[test]
    fn test_from_str_little() {
        assert_eq!(Endian::from_str("little"), Some(Endian::Little));
        assert_eq!(Endian::from_str("LITTLE"), Some(Endian::Little));
        assert_eq!(Endian::from_str("LE"), Some(Endian::Little));
        assert_eq!(Endian::from_str("le"), Some(Endian::Little));
    }

    #[test]
    fn test_from_str_invalid() {
        assert_eq!(Endian::from_str("unknown"), None);
        assert_eq!(Endian::from_str(""), None);
    }

    #[test]
    fn test_to_short_string() {
        assert_eq!(Endian::Big.to_short_string(), "BE");
        assert_eq!(Endian::Little.to_short_string(), "LE");
    }

    #[test]
    fn test_is_big_endian() {
        assert!(Endian::Big.is_big_endian());
        assert!(!Endian::Little.is_big_endian());
    }

    #[test]
    fn test_is_little_endian() {
        assert!(Endian::Little.is_little_endian());
        assert!(!Endian::Big.is_little_endian());
    }

    #[test]
    fn test_display_name() {
        assert_eq!(Endian::Big.display_name(), "Big");
        assert_eq!(Endian::Little.display_name(), "Little");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Endian::Big), "big");
        assert_eq!(format!("{}", Endian::Little), "little");
    }

    #[test]
    fn test_default() {
        assert_eq!(Endian::default(), Endian::Little);
    }

    #[test]
    fn test_from_bool() {
        assert_eq!(Endian::from(true), Endian::Big);
        assert_eq!(Endian::from(false), Endian::Little);
    }

    #[test]
    fn test_into_bool() {
        let b: bool = Endian::Big.into();
        assert!(b);
        let l: bool = Endian::Little.into();
        assert!(!l);
    }

    #[test]
    fn test_read_u16() {
        let be_bytes = [0x01, 0x02u8];
        assert_eq!(Endian::Big.read_u16(&be_bytes), 0x0102);
        assert_eq!(Endian::Little.read_u16(&be_bytes), 0x0201);
    }

    #[test]
    fn test_read_u32() {
        let bytes = [0x01, 0x02, 0x03, 0x04u8];
        assert_eq!(Endian::Big.read_u32(&bytes), 0x01020304);
        assert_eq!(Endian::Little.read_u32(&bytes), 0x04030201);
    }

    #[test]
    fn test_read_u64() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08u8];
        assert_eq!(Endian::Big.read_u64(&bytes), 0x0102030405060708);
        assert_eq!(Endian::Little.read_u64(&bytes), 0x0807060504030201);
    }

    #[test]
    fn test_write_u16() {
        let mut buf = [0u8; 2];
        Endian::Big.write_u16(&mut buf, 0x0102);
        assert_eq!(buf, [0x01, 0x02]);

        Endian::Little.write_u16(&mut buf, 0x0102);
        assert_eq!(buf, [0x02, 0x01]);
    }

    #[test]
    fn test_write_u32() {
        let mut buf = [0u8; 4];
        Endian::Big.write_u32(&mut buf, 0x01020304);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04]);

        Endian::Little.write_u32(&mut buf, 0x01020304);
        assert_eq!(buf, [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_write_u64() {
        let mut buf = [0u8; 8];
        Endian::Big.write_u64(&mut buf, 0x0102030405060708);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        Endian::Little.write_u64(&mut buf, 0x0102030405060708);
        assert_eq!(buf, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_roundtrip() {
        let original: u32 = 0xDEADBEEF;
        let mut buf = [0u8; 4];

        Endian::Big.write_u32(&mut buf, original);
        let read_back = Endian::Big.read_u32(&buf);
        assert_eq!(read_back, original);

        Endian::Little.write_u32(&mut buf, original);
        let read_back = Endian::Little.read_u32(&buf);
        assert_eq!(read_back, original);
    }
}
