//! Numeric -- MSFT Numeric value types used in PDB symbol and type records.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.Numeric`.

use std::fmt;

/// An MSFT Numeric value.
///
/// PDB records encode numeric values using a variable-length format. If the
/// first `u16` is less than `0x8000`, it is a literal unsigned value. Otherwise
/// the `u16` is a subtype index selecting the actual encoding width and
/// signedness.
///
/// `Numeric` wraps the parsed value as a [`NumericValue`] and preserves the
/// raw subtype index for inspection.
#[derive(Debug, Clone, PartialEq)]
pub struct Numeric {
    sub_type_index: u16,
    value: NumericValue,
}

/// The value held inside a [`Numeric`].
#[derive(Debug, Clone, PartialEq)]
pub enum NumericValue {
    /// An unsigned integer that fits in a `u64`.
    ///
    /// This covers all unsigned and most signed integral types. Signed values
    /// are stored as their two's-complement bit pattern.
    Integral(u64),

    /// A 32-bit IEEE 754 floating point value.
    Float(f32),

    /// A 64-bit IEEE 754 floating point value.
    Double(f64),

    /// Raw bytes for types that are not represented natively (Real80, Real128,
    /// Complex, Decimal, Date, Real16, Real48, etc.).
    Bytes(Vec<u8>),
}

impl Numeric {
    /// Parse a Numeric value from a byte slice at the given offset.
    ///
    /// Returns the parsed `Numeric` and the number of bytes consumed.
    pub fn parse(data: &[u8], offset: usize) -> (Self, usize) {
        if offset + 2 > data.len() {
            return (
                Numeric {
                    sub_type_index: 0,
                    value: NumericValue::Integral(0),
                },
                0,
            );
        }
        let sub = u16::from_le_bytes([data[offset], data[offset + 1]]);
        if sub < 0x8000 {
            return (
                Numeric {
                    sub_type_index: sub,
                    value: NumericValue::Integral(sub as u64),
                },
                2,
            );
        }

        let (consumed, value) = match sub {
            0x8000 => {
                // char (signed i8)
                if offset + 3 > data.len() {
                    return (Self::truncated(sub), 0);
                }
                (3, NumericValue::Integral(data[offset + 2] as u64))
            }
            0x8001 => {
                // short (signed i16)
                if offset + 4 > data.len() {
                    return (Self::truncated(sub), 0);
                }
                let v = i16::from_le_bytes([data[offset + 2], data[offset + 3]]);
                (4, NumericValue::Integral(v as u16 as u64))
            }
            0x8002 => {
                // unsigned short
                if offset + 4 > data.len() {
                    return (Self::truncated(sub), 0);
                }
                let v = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
                (4, NumericValue::Integral(v as u64))
            }
            0x8003 => {
                // int32
                if offset + 6 > data.len() {
                    return (Self::truncated(sub), 0);
                }
                let v = u32::from_le_bytes([
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                ]);
                (6, NumericValue::Integral(v as u64))
            }
            0x8004 => {
                // unsigned int32
                if offset + 6 > data.len() {
                    return (Self::truncated(sub), 0);
                }
                let v = u32::from_le_bytes([
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                ]);
                (6, NumericValue::Integral(v as u64))
            }
            0x8005 => {
                // Real32 (f32)
                if offset + 6 > data.len() {
                    return (Self::truncated(sub), 0);
                }
                let v = f32::from_le_bytes([
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                ]);
                (6, NumericValue::Float(v))
            }
            0x8006 => {
                // Real64 (f64)
                if offset + 10 > data.len() {
                    return (Self::truncated(sub), 0);
                }
                let v = f64::from_le_bytes([
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                    data[offset + 8],
                    data[offset + 9],
                ]);
                (10, NumericValue::Double(v))
            }
            0x8007 => {
                // Real80 (10 bytes)
                Self::parse_bytes(data, offset, sub, 10, 2)
            }
            0x8008 => {
                // Real128 (16 bytes)
                Self::parse_bytes(data, offset, sub, 16, 2)
            }
            0x8009 => {
                // int64
                if offset + 10 > data.len() {
                    return (Self::truncated(sub), 0);
                }
                let v = u64::from_le_bytes([
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                    data[offset + 8],
                    data[offset + 9],
                ]);
                (10, NumericValue::Integral(v))
            }
            0x800A => {
                // unsigned int64
                if offset + 10 > data.len() {
                    return (Self::truncated(sub), 0);
                }
                let v = u64::from_le_bytes([
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                    data[offset + 8],
                    data[offset + 9],
                ]);
                (10, NumericValue::Integral(v))
            }
            0x800B => {
                // Real48 (6 bytes)
                Self::parse_bytes(data, offset, sub, 6, 2)
            }
            0x800C => {
                // Complex32 (2 x f32 = 8 bytes)
                Self::parse_bytes(data, offset, sub, 8, 2)
            }
            0x800D => {
                // Complex64 (2 x f64 = 16 bytes)
                Self::parse_bytes(data, offset, sub, 16, 2)
            }
            0x800E => {
                // Complex80 (2 x 80-bit = 20 bytes)
                Self::parse_bytes(data, offset, sub, 20, 2)
            }
            0x800F => {
                // Complex128 (2 x 128-bit = 32 bytes)
                Self::parse_bytes(data, offset, sub, 32, 2)
            }
            0x8010 => {
                // VarString (variable-length, just store raw bytes)
                Self::parse_bytes(data, offset, sub, 0, 2)
            }
            _ => {
                // Unknown subtype >= 0x8000: treat remaining data as raw bytes
                (2, NumericValue::Integral(0))
            }
        };

        (
            Numeric {
                sub_type_index: sub,
                value,
            },
            consumed,
        )
    }

    fn parse_bytes(
        data: &[u8],
        offset: usize,
        sub: u16,
        num_bytes: usize,
        header_size: usize,
    ) -> (usize, NumericValue) {
        let start = offset + header_size;
        let end = start + num_bytes;
        if end > data.len() {
            return (0, NumericValue::Integral(0));
        }
        (
            header_size + num_bytes,
            NumericValue::Bytes(data[start..end].to_vec()),
        )
    }

    fn truncated(sub: u16) -> Self {
        Numeric {
            sub_type_index: sub,
            value: NumericValue::Integral(0),
        }
    }

    /// Return the subtype index.
    ///
    /// For literal values (< 0x8000) this is the value itself.
    /// For encoded values (>= 0x8000) this selects the encoding.
    pub fn sub_type_index(&self) -> u16 {
        self.sub_type_index
    }

    /// Return a reference to the parsed value.
    pub fn value(&self) -> &NumericValue {
        &self.value
    }

    /// Return `true` if the value is an integral type.
    pub fn is_integral(&self) -> bool {
        matches!(self.value, NumericValue::Integral(_))
    }

    /// Return `true` if the subtype indicates a signed value.
    pub fn is_signed(&self) -> bool {
        matches!(
            self.sub_type_index,
            0x8000 | 0x8001 | 0x8003 | 0x8009
        )
    }

    /// Return the byte size of the encoded value (excluding the 2-byte header).
    ///
    /// Returns `0` for literal values (< 0x8000).
    pub fn encoded_size(&self) -> usize {
        match self.sub_type_index {
            0x8000 => 1,
            0x8001 | 0x8002 => 2,
            0x8003 | 0x8004 | 0x8005 => 4,
            0x8006 => 8,
            0x8007 => 10,
            0x8008 => 16,
            0x8009 | 0x800A => 8,
            0x800B => 6,
            0x800C => 8,
            0x800D => 16,
            0x800E => 20,
            0x800F => 32,
            _ => 0,
        }
    }

    /// Try to interpret the value as a `u64`.
    ///
    /// Returns `Some(v)` for [`NumericValue::Integral`], `None` otherwise.
    pub fn as_u64(&self) -> Option<u64> {
        match self.value {
            NumericValue::Integral(v) => Some(v),
            _ => None,
        }
    }

    /// Try to interpret the value as an `f64`.
    ///
    /// Returns `Some(v)` for float/double values, `None` otherwise.
    pub fn as_f64(&self) -> Option<f64> {
        match self.value {
            NumericValue::Float(v) => Some(v as f64),
            NumericValue::Double(v) => Some(v),
            _ => None,
        }
    }
}

impl fmt::Display for Numeric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            NumericValue::Integral(v) => write!(f, "{}", v),
            NumericValue::Float(v) => write!(f, "{}", v),
            NumericValue::Double(v) => write!(f, "{}", v),
            NumericValue::Bytes(b) => {
                write!(f, "0x")?;
                for byte in b {
                    write!(f, "{:02X}", byte)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_value() {
        // Value 42 encoded as a literal (0x2A, 0x00)
        let data = [0x2A, 0x00];
        let (num, consumed) = Numeric::parse(&data, 0);
        assert_eq!(consumed, 2);
        assert_eq!(num.sub_type_index(), 42);
        assert!(num.is_integral());
        assert_eq!(num.as_u64(), Some(42));
    }

    #[test]
    fn test_char_value() {
        // 0x8000 = char, value = 0x42
        let data = [0x00, 0x80, 0x42];
        let (num, consumed) = Numeric::parse(&data, 0);
        assert_eq!(consumed, 3);
        assert!(num.is_signed());
        assert_eq!(num.as_u64(), Some(0x42));
    }

    #[test]
    fn test_short_value() {
        // 0x8001 = signed short, value = -1 (0xFFFF)
        let data = [0x01, 0x80, 0xFF, 0xFF];
        let (num, consumed) = Numeric::parse(&data, 0);
        assert_eq!(consumed, 4);
        assert!(num.is_signed());
        assert_eq!(num.encoded_size(), 2);
    }

    #[test]
    fn test_u32_value() {
        // 0x8004 = unsigned int32, value = 0x12345678
        let data = [0x04, 0x80, 0x78, 0x56, 0x34, 0x12];
        let (num, consumed) = Numeric::parse(&data, 0);
        assert_eq!(consumed, 6);
        assert!(!num.is_signed());
        assert_eq!(num.as_u64(), Some(0x12345678));
    }

    #[test]
    fn test_float_value() {
        // 0x8005 = Real32, value = 1.0f32
        let bytes = 1.0f32.to_le_bytes();
        let mut data = vec![0x05, 0x80];
        data.extend_from_slice(&bytes);
        let (num, consumed) = Numeric::parse(&data, 0);
        assert_eq!(consumed, 6);
        assert_eq!(num.as_f64(), Some(1.0));
    }

    #[test]
    fn test_double_value() {
        // 0x8006 = Real64, value = 3.14
        let bytes = 3.14f64.to_le_bytes();
        let mut data = vec![0x06, 0x80];
        data.extend_from_slice(&bytes);
        let (num, consumed) = Numeric::parse(&data, 0);
        assert_eq!(consumed, 10);
        assert_eq!(num.as_f64(), Some(3.14));
    }

    #[test]
    fn test_real80_raw_bytes() {
        // 0x8007 = Real80, 10 bytes
        let mut data = vec![0x07, 0x80];
        data.extend_from_slice(&[0u8; 10]);
        let (num, consumed) = Numeric::parse(&data, 0);
        assert_eq!(consumed, 12);
        assert!(!num.is_integral());
    }

    #[test]
    fn test_display_integral() {
        let data = [0x2A, 0x00];
        let (num, _) = Numeric::parse(&data, 0);
        assert_eq!(format!("{}", num), "42");
    }

    #[test]
    fn test_display_bytes() {
        let data = vec![0x07, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let (num, _) = Numeric::parse(&data, 0);
        assert_eq!(format!("{}", num), "0x0102030405060708090A");
    }
}
