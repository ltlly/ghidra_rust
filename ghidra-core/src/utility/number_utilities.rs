//! Numeric conversion and formatting utilities.
//!
//! Port of `ghidra.util.NumberUtilities`.

/// Numeric conversion and formatting utilities.
///
/// Port of `ghidra.util.NumberUtilities`.
pub struct NumberUtilities;

impl NumberUtilities {
    /// Parse an integer from a string, supporting hex (0x), octal (0o), and binary (0b) prefixes,
    /// as well as plain decimal.
    pub fn parse_int(s: &str) -> Option<i64> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        // Handle negative numbers
        let (s, neg) = if let Some(rest) = s.strip_prefix('-') {
            (rest, true)
        } else {
            (s, false)
        };
        let s = s.strip_prefix('+').unwrap_or(s);

        let value = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16).ok()
        } else if let Some(oct) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
            i64::from_str_radix(oct, 8).ok()
        } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
            i64::from_str_radix(bin, 2).ok()
        } else {
            s.parse::<i64>().ok()
        };

        value.map(|v| if neg { -v } else { v })
    }

    /// Parse an unsigned integer from a string with the same prefix support.
    pub fn parse_uint(s: &str) -> Option<u64> {
        let s = s.trim().trim_start_matches('+');
        if s.is_empty() {
            return None;
        }
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else if let Some(oct) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
            u64::from_str_radix(oct, 8).ok()
        } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
            u64::from_str_radix(bin, 2).ok()
        } else {
            s.parse::<u64>().ok()
        }
    }

    /// Format a number in hexadecimal with a minimum number of hex digits.
    pub fn to_hex_string(value: u64, min_digits: usize) -> String {
        format!("{:0width$x}", value, width = min_digits)
    }

    /// Format a number in hexadecimal with a "0x" prefix.
    pub fn to_hex_prefix_string(value: u64, min_digits: usize) -> String {
        format!("0x{:0width$x}", value, width = min_digits)
    }

    /// Format a signed integer in hexadecimal.
    pub fn to_hex_string_signed(value: i64, min_digits: usize) -> String {
        if value < 0 {
            format!("-0x{:0width$x}", (-value) as u64, width = min_digits)
        } else {
            format!("0x{:0width$x}", value as u64, width = min_digits)
        }
    }

    /// Format a number in octal.
    pub fn to_octal_string(value: u64, min_digits: usize) -> String {
        format!("{:0width$o}", value, width = min_digits)
    }

    /// Format a number in binary.
    pub fn to_binary_string(value: u64, min_digits: usize) -> String {
        format!("{:0width$b}", value, width = min_digits)
    }

    /// Convert a byte to a two-character hex string.
    pub fn byte_to_hex(byte: u8) -> String {
        format!("{:02x}", byte)
    }

    /// Convert a hex character to its numeric value (0-15).
    ///
    /// Returns `None` if the character is not a valid hex digit.
    pub fn hex_char_value(c: char) -> Option<u8> {
        match c {
            '0'..='9' => Some(c as u8 - b'0'),
            'a'..='f' => Some(c as u8 - b'a' + 10),
            'A'..='F' => Some(c as u8 - b'A' + 10),
            _ => None,
        }
    }

    /// Convert a numeric value (0-15) to its hex character.
    pub fn hex_char(value: u8) -> char {
        match value {
            0..=9 => (b'0' + value) as char,
            10..=15 => (b'a' + value - 10) as char,
            _ => '?',
        }
    }

    /// Get the number of hex digits needed to represent a value.
    pub fn hex_digit_count(value: u64) -> usize {
        if value == 0 {
            1
        } else {
            ((64 - value.leading_zeros()) as usize + 3) / 4
        }
    }

    /// Get the number of binary digits needed to represent a value.
    pub fn binary_digit_count(value: u64) -> usize {
        if value == 0 {
            1
        } else {
            (64 - value.leading_zeros()) as usize
        }
    }

    /// Convert a float to a string with the given number of decimal places.
    pub fn format_float(value: f64, decimal_places: usize) -> String {
        format!("{:.*}", decimal_places, value)
    }

    /// Check if a value is a power of two.
    pub fn is_power_of_two(value: u64) -> bool {
        value != 0 && (value & (value - 1)) == 0
    }

    /// Round up to the next power of two.
    ///
    /// Returns the value itself if it is already a power of two.
    /// Returns 0 for input 0.
    pub fn next_power_of_two(value: u64) -> u64 {
        if value == 0 {
            return 0;
        }
        if Self::is_power_of_two(value) {
            return value;
        }
        let mut v = value - 1;
        v |= v >> 1;
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;
        v |= v >> 32;
        v + 1
    }

    /// Clamp a value to the range [min, max].
    pub fn clamp<T: PartialOrd>(value: T, min: T, max: T) -> T {
        if value < min {
            min
        } else if value > max {
            max
        } else {
            value
        }
    }

    /// Get the minimum of two values.
    pub fn min<T: PartialOrd>(a: T, b: T) -> T {
        if a < b { a } else { b }
    }

    /// Get the maximum of two values.
    pub fn max<T: PartialOrd>(a: T, b: T) -> T {
        if a > b { a } else { b }
    }

    /// Compute the unsigned average of two u64 values without overflow.
    pub fn unsigned_average(a: u64, b: u64) -> u64 {
        (a & b) + (a ^ b) / 2
    }
}

/// A type for representing and manipulating unsigned integer values of various sizes.
///
/// Port of Ghidra's `GenericInteger` concept for flexible-sized integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlexInteger {
    value: u64,
    bit_size: u32,
}

impl FlexInteger {
    /// Create a new FlexInteger with the given bit size.
    ///
    /// The value is masked to fit within the specified bit size.
    pub fn new(value: u64, bit_size: u32) -> Self {
        assert!(bit_size > 0 && bit_size <= 64, "bit_size must be 1..=64");
        let mask = if bit_size >= 64 {
            u64::MAX
        } else {
            (1u64 << bit_size) - 1
        };
        Self {
            value: value & mask,
            bit_size,
        }
    }

    /// Get the raw value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Get the bit size.
    pub fn bit_size(&self) -> u32 {
        self.bit_size
    }

    /// Get the maximum value for this bit size.
    pub fn max_value(&self) -> u64 {
        if self.bit_size >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_size) - 1
        }
    }

    /// Get the value as a signed integer.
    pub fn signed_value(&self) -> i64 {
        let shift = 64 - self.bit_size;
        ((self.value << shift) as i64) >> shift
    }
}

impl fmt::Display for FlexInteger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl fmt::LowerHex for FlexInteger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_digits = (self.bit_size as usize + 3) / 4;
        write!(f, "{:0width$x}", self.value, width = hex_digits)
    }
}

impl fmt::UpperHex for FlexInteger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_digits = (self.bit_size as usize + 3) / 4;
        write!(f, "{:0width$X}", self.value, width = hex_digits)
    }
}

impl fmt::Binary for FlexInteger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0width$b}", self.value, width = self.bit_size as usize)
    }
}

use std::fmt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_int() {
        assert_eq!(NumberUtilities::parse_int("42"), Some(42));
        assert_eq!(NumberUtilities::parse_int("-1"), Some(-1));
        assert_eq!(NumberUtilities::parse_int("0xFF"), Some(255));
        assert_eq!(NumberUtilities::parse_int("0xFF"), Some(255));
        assert_eq!(NumberUtilities::parse_int("0b1010"), Some(10));
        assert_eq!(NumberUtilities::parse_int("0o17"), Some(15));
        assert_eq!(NumberUtilities::parse_int("  42  "), Some(42));
        assert_eq!(NumberUtilities::parse_int("not_a_number"), None);
    }

    #[test]
    fn test_parse_uint() {
        assert_eq!(NumberUtilities::parse_uint("42"), Some(42));
        assert_eq!(NumberUtilities::parse_uint("0xFF"), Some(255));
        assert_eq!(NumberUtilities::parse_uint("0b1010"), Some(10));
        assert_eq!(NumberUtilities::parse_uint("-1"), None); // unsigned
    }

    #[test]
    fn test_hex_string() {
        assert_eq!(NumberUtilities::to_hex_string(255, 4), "00ff");
        assert_eq!(NumberUtilities::to_hex_prefix_string(255, 4), "0x00ff");
        assert_eq!(NumberUtilities::to_hex_string_signed(-1, 4), "-0x0001");
    }

    #[test]
    fn test_octal_binary() {
        assert_eq!(NumberUtilities::to_octal_string(8, 4), "0010");
        assert_eq!(NumberUtilities::to_binary_string(5, 8), "00000101");
    }

    #[test]
    fn test_hex_char() {
        assert_eq!(NumberUtilities::hex_char_value('a'), Some(10));
        assert_eq!(NumberUtilities::hex_char_value('F'), Some(15));
        assert_eq!(NumberUtilities::hex_char_value('9'), Some(9));
        assert_eq!(NumberUtilities::hex_char_value('x'), None);
        assert_eq!(NumberUtilities::hex_char(10), 'a');
        assert_eq!(NumberUtilities::hex_char(15), 'f');
    }

    #[test]
    fn test_digit_counts() {
        assert_eq!(NumberUtilities::hex_digit_count(0), 1);
        assert_eq!(NumberUtilities::hex_digit_count(0xFF), 2);
        assert_eq!(NumberUtilities::hex_digit_count(0x100), 3);
        assert_eq!(NumberUtilities::binary_digit_count(0), 1);
        assert_eq!(NumberUtilities::binary_digit_count(8), 4);
    }

    #[test]
    fn test_format_float() {
        assert_eq!(NumberUtilities::format_float(3.14159, 2), "3.14");
        assert_eq!(NumberUtilities::format_float(1.0, 0), "1");
    }

    #[test]
    fn test_power_of_two() {
        assert!(NumberUtilities::is_power_of_two(1));
        assert!(NumberUtilities::is_power_of_two(1024));
        assert!(!NumberUtilities::is_power_of_two(0));
        assert!(!NumberUtilities::is_power_of_two(3));
        assert_eq!(NumberUtilities::next_power_of_two(5), 8);
        assert_eq!(NumberUtilities::next_power_of_two(8), 8);
        assert_eq!(NumberUtilities::next_power_of_two(0), 0);
    }

    #[test]
    fn test_clamp() {
        assert_eq!(NumberUtilities::clamp(5, 0, 10), 5);
        assert_eq!(NumberUtilities::clamp(-1, 0, 10), 0);
        assert_eq!(NumberUtilities::clamp(15, 0, 10), 10);
    }

    #[test]
    fn test_unsigned_average() {
        assert_eq!(NumberUtilities::unsigned_average(10, 20), 15);
        assert_eq!(NumberUtilities::unsigned_average(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(NumberUtilities::unsigned_average(0, 0), 0);
    }

    #[test]
    fn test_flex_integer() {
        let fi = FlexInteger::new(0xFF, 8);
        assert_eq!(fi.value(), 0xFF);
        assert_eq!(fi.bit_size(), 8);
        assert_eq!(fi.max_value(), 0xFF);
        assert_eq!(fi.signed_value(), -1);

        let fi = FlexInteger::new(0x1FF, 8);
        assert_eq!(fi.value(), 0xFF); // masked

        let fi = FlexInteger::new(5, 4);
        assert_eq!(format!("{:b}", fi), "0101");
    }
}
