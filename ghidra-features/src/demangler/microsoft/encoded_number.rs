//! Encoded number parsing for Microsoft demangling.
//!
//! Ported from `mdemangler.MDEncodedNumber` and `mdemangler.MDSignedEncodedNumber` Java classes.
//!
//! In MSVC mangled names, numbers are encoded using a compact scheme:
//! - Single digit `0`-`9` encodes values 1-10
//! - Hex letter sequences `A`-`P` encode arbitrary-precision unsigned numbers
//! - A `?` prefix indicates a negative (signed) number
//! - The sequence is terminated by `@`

use std::fmt;

// ---------------------------------------------------------------------------
// EncodedNumber
// ---------------------------------------------------------------------------

/// An unsigned encoded number parsed from a Microsoft mangled symbol.
///
/// Ported from `MDEncodedNumber.java`. The number encoding uses:
/// - `0`-`9`: values 1 through 10
/// - `A`-`P` sequences terminated by `@`: hex-encoded arbitrary-precision values
///   where each letter contributes 4 bits (A=0, B=1, ..., P=15)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedNumber {
    /// The parsed value (stored as u128 to handle up to 64-bit unsigned values).
    value: u128,
}

impl EncodedNumber {
    /// Create a new encoded number with the given value.
    pub fn new(value: u128) -> Self {
        Self { value }
    }

    /// Get the parsed value.
    pub fn value(&self) -> u128 {
        self.value
    }

    /// Get the value as u64, saturating at u64::MAX.
    pub fn value_u64(&self) -> u64 {
        if self.value > u64::MAX as u128 {
            u64::MAX
        } else {
            self.value as u64
        }
    }

    /// Get the value as i64, clamping to i64 range.
    pub fn value_i64(&self) -> i64 {
        if self.value > i64::MAX as u128 {
            i64::MAX
        } else {
            self.value as i64
        }
    }

    /// Parse an encoded number from the character stream.
    ///
    /// # Encoding Rules
    /// - If the first character is a digit `0`-`9`, the value is `(digit - '0' + 1)`.
    /// - If the first character is `A`-`P` or `@`, the value is built by reading
    ///   hex nibbles (`A`=0 through `P`=15) until `@` is encountered.
    /// - `@` alone encodes 0.
    ///
    /// # Arguments
    /// * `chars` - The mangled symbol characters
    /// * `index` - Current parse position (updated on return)
    ///
    /// # Errors
    /// Returns an error string if the encoded number is invalid.
    pub fn parse(chars: &[char], index: &mut usize) -> Result<Self, String> {
        if *index >= chars.len() {
            return Err("Unexpected end of symbol in encoded number".to_string());
        }

        let ch = chars[*index];

        if ch >= '0' && ch <= '9' {
            // Single digit: value = digit - '0' + 1
            let val = (ch as u8 - b'0') as u128 + 1;
            *index += 1;
            return Ok(Self::new(val));
        }

        if (ch >= 'A' && ch <= 'P') || ch == '@' {
            // Hex-encoded sequence: each letter A-P is a 4-bit nibble
            let mut value: u128 = 0;
            while *index < chars.len() {
                let c = chars[*index];
                if c == '@' {
                    *index += 1;
                    break;
                }
                if c < 'A' || c > 'P' {
                    return Err(format!(
                        "Invalid character '{}' in encoded number at index {}",
                        c, *index
                    ));
                }
                value = value.checked_shl(4).ok_or_else(|| {
                    "Encoded number overflow: too many hex digits".to_string()
                })?;
                value += (c as u8 - b'A') as u128;
                *index += 1;
            }
            return Ok(Self::new(value));
        }

        Err(format!(
            "Invalid start character '{}' for encoded number at index {}",
            ch, *index
        ))
    }
}

impl fmt::Display for EncodedNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ---------------------------------------------------------------------------
// SignedEncodedNumber
// ---------------------------------------------------------------------------

/// A signed encoded number parsed from a Microsoft mangled symbol.
///
/// Ported from `MDSignedEncodedNumber.java`. Extends `EncodedNumber` with
/// optional negation indicated by a `?` prefix.
///
/// The encoding is:
/// - `?` prefix: the number is negative (value is negated)
/// - Followed by a standard `EncodedNumber`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEncodedNumber {
    /// The underlying unsigned value.
    inner: EncodedNumber,
    /// Whether the number is negative.
    is_negative: bool,
}

impl SignedEncodedNumber {
    /// Create a new signed encoded number.
    pub fn new(value: i128) -> Self {
        if value < 0 {
            Self {
                inner: EncodedNumber::new((-value) as u128),
                is_negative: true,
            }
        } else {
            Self {
                inner: EncodedNumber::new(value as u128),
                is_negative: false,
            }
        }
    }

    /// Get the signed value.
    pub fn value(&self) -> i128 {
        let v = self.inner.value() as i128;
        if self.is_negative {
            -v
        } else {
            v
        }
    }

    /// Get the signed value as i64, clamping to i64 range.
    pub fn value_i64(&self) -> i64 {
        let v = self.inner.value();
        if self.is_negative {
            if v > i64::MAX as u128 + 1 {
                i64::MIN
            } else {
                -(v as i64)
            }
        } else {
            if v > i64::MAX as u128 {
                i64::MAX
            } else {
                v as i64
            }
        }
    }

    /// Get whether the number is negative.
    pub fn is_negative(&self) -> bool {
        self.is_negative
    }

    /// Get the underlying unsigned value.
    pub fn unsigned_value(&self) -> u128 {
        self.inner.value()
    }

    /// Parse a signed encoded number from the character stream.
    ///
    /// # Encoding Rules
    /// - If the first character is `?`, the number is negative. The `?` is consumed
    ///   and the rest is parsed as an unsigned `EncodedNumber`.
    /// - Otherwise, the number is positive and parsed as an unsigned `EncodedNumber`.
    ///
    /// # Arguments
    /// * `chars` - The mangled symbol characters
    /// * `index` - Current parse position (updated on return)
    ///
    /// # Errors
    /// Returns an error string if the encoded number is invalid.
    pub fn parse(chars: &[char], index: &mut usize) -> Result<Self, String> {
        if *index >= chars.len() {
            return Err("Unexpected end of symbol in signed encoded number".to_string());
        }

        let is_negative = if chars[*index] == '?' {
            *index += 1;
            true
        } else {
            false
        };

        let inner = EncodedNumber::parse(chars, index)?;
        Ok(Self { inner, is_negative })
    }
}

impl fmt::Display for SignedEncodedNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_negative {
            write!(f, "-{}", self.inner.value())
        } else {
            write!(f, "{}", self.inner.value())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn to_chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    // --- EncodedNumber ---

    #[test]
    fn test_encoded_number_single_digit() {
        // '0' = 1, '1' = 2, ..., '9' = 10
        for d in '0'..='9' {
            let chars = to_chars(&d.to_string());
            let mut index = 0;
            let num = EncodedNumber::parse(&chars, &mut index).unwrap();
            assert_eq!(num.value(), (d as u8 - b'0') as u128 + 1);
            assert_eq!(index, 1);
        }
    }

    #[test]
    fn test_encoded_number_hex_single() {
        // 'A' = 0, 'B' = 1, ..., 'P' = 15
        for ch in 'A'..='P' {
            let s = format!("{}@", ch);
            let chars = to_chars(&s);
            let mut index = 0;
            let num = EncodedNumber::parse(&chars, &mut index).unwrap();
            assert_eq!(num.value(), (ch as u8 - b'A') as u128);
            assert_eq!(index, 2); // past the '@'
        }
    }

    #[test]
    fn test_encoded_number_hex_multi() {
        // "AB@" = (0 << 4) + 1 = 1
        let chars = to_chars("AB@");
        let mut index = 0;
        let num = EncodedNumber::parse(&chars, &mut index).unwrap();
        assert_eq!(num.value(), 1);
        assert_eq!(index, 3);
    }

    #[test]
    fn test_encoded_number_hex_complex() {
        // "BAA@" = (1 << 8) + (0 << 4) + 0 = 256
        let chars = to_chars("BAA@");
        let mut index = 0;
        let num = EncodedNumber::parse(&chars, &mut index).unwrap();
        assert_eq!(num.value(), 256);
    }

    #[test]
    fn test_encoded_number_at_only() {
        // "@" = 0
        let chars = to_chars("@");
        let mut index = 0;
        let num = EncodedNumber::parse(&chars, &mut index).unwrap();
        assert_eq!(num.value(), 0);
        assert_eq!(index, 1);
    }

    #[test]
    fn test_encoded_number_display() {
        let num = EncodedNumber::new(42);
        assert_eq!(format!("{}", num), "42");
    }

    #[test]
    fn test_encoded_number_value_u64() {
        let num = EncodedNumber::new(u64::MAX as u128);
        assert_eq!(num.value_u64(), u64::MAX);

        let num = EncodedNumber::new(u64::MAX as u128 + 1);
        assert_eq!(num.value_u64(), u64::MAX); // saturated
    }

    #[test]
    fn test_encoded_number_value_i64() {
        let num = EncodedNumber::new(42);
        assert_eq!(num.value_i64(), 42);

        let num = EncodedNumber::new(i64::MAX as u128 + 1);
        assert_eq!(num.value_i64(), i64::MAX); // clamped
    }

    #[test]
    fn test_encoded_number_invalid_start() {
        let chars = to_chars("X");
        let mut index = 0;
        let result = EncodedNumber::parse(&chars, &mut index);
        assert!(result.is_err());
    }

    #[test]
    fn test_encoded_number_invalid_hex() {
        let chars = to_chars("AQ@");
        let mut index = 0;
        let result = EncodedNumber::parse(&chars, &mut index);
        assert!(result.is_err());
    }

    #[test]
    fn test_encoded_number_end_of_input() {
        let chars: Vec<char> = Vec::new();
        let mut index = 0;
        let result = EncodedNumber::parse(&chars, &mut index);
        assert!(result.is_err());
    }

    // --- SignedEncodedNumber ---

    #[test]
    fn test_signed_encoded_number_positive() {
        let chars = to_chars("5");
        let mut index = 0;
        let num = SignedEncodedNumber::parse(&chars, &mut index).unwrap();
        assert!(!num.is_negative());
        assert_eq!(num.value(), 6); // '5' = 6
    }

    #[test]
    fn test_signed_encoded_number_negative() {
        let chars = to_chars("?5");
        let mut index = 0;
        let num = SignedEncodedNumber::parse(&chars, &mut index).unwrap();
        assert!(num.is_negative());
        assert_eq!(num.value(), -6); // -('5' + 1) = -6
    }

    #[test]
    fn test_signed_encoded_number_negative_hex() {
        let chars = to_chars("?BAA@");
        let mut index = 0;
        let num = SignedEncodedNumber::parse(&chars, &mut index).unwrap();
        assert!(num.is_negative());
        assert_eq!(num.value(), -256);
    }

    #[test]
    fn test_signed_encoded_number_zero() {
        // "@" alone = 0 (unsigned)
        let chars = to_chars("@");
        let mut index = 0;
        let num = SignedEncodedNumber::parse(&chars, &mut index).unwrap();
        assert!(!num.is_negative());
        assert_eq!(num.value(), 0);
    }

    #[test]
    fn test_signed_encoded_number_negative_zero() {
        // "?@" = -0 (which is still 0 in our representation)
        let chars = to_chars("?@");
        let mut index = 0;
        let num = SignedEncodedNumber::parse(&chars, &mut index).unwrap();
        assert!(num.is_negative());
        assert_eq!(num.value(), 0); // -0 = 0 in i128
    }

    #[test]
    fn test_signed_encoded_number_display_positive() {
        let num = SignedEncodedNumber::new(42);
        assert_eq!(format!("{}", num), "42");
    }

    #[test]
    fn test_signed_encoded_number_display_negative() {
        let num = SignedEncodedNumber::new(-42);
        assert_eq!(format!("{}", num), "-42");
    }

    #[test]
    fn test_signed_encoded_number_value_i64() {
        let num = SignedEncodedNumber::new(i64::MAX as i128);
        assert_eq!(num.value_i64(), i64::MAX);

        let num = SignedEncodedNumber::new(i64::MIN as i128);
        assert_eq!(num.value_i64(), i64::MIN);
    }

    #[test]
    fn test_signed_encoded_number_in_context() {
        // Simulate parsing "?IAAAAAAAAAAAAAAA" which encodes -9223372036854775808
        // I = 8, then 15 A's = 0 each
        // Value = (8 << 60) = 9223372036854775808
        let mut s = "?I".to_string();
        for _ in 0..15 {
            s.push('A');
        }
        s.push('@');
        let chars = to_chars(&s);
        let mut index = 0;
        let num = SignedEncodedNumber::parse(&chars, &mut index).unwrap();
        assert!(num.is_negative());
        assert_eq!(num.value_i64(), i64::MIN); // -9223372036854775808 = i64::MIN
    }

    #[test]
    fn test_signed_encoded_number_end_of_input() {
        let chars: Vec<char> = Vec::new();
        let mut index = 0;
        let result = SignedEncodedNumber::parse(&chars, &mut index);
        assert!(result.is_err());
    }
}
