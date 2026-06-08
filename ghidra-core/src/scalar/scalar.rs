//! Scalar integer type for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.scalar.Scalar`.
//!
//! A [`Scalar`] is an immutable integer stored in an arbitrary number of bits
//! (0..64), along with a preferred signed-ness attribute. This is used
//! throughout Ghidra to represent immediate values in instructions, constant
//! operands, and other contexts where bit-width matters.

use std::fmt;

/// An immutable integer stored in an arbitrary number of bits (0..64).
///
/// Corresponds to `ghidra.program.model.scalar.Scalar`.
///
/// The value is stored with its upper unused bits masked off. The `signed`
/// flag controls whether display and comparison operations treat the value
/// as signed or unsigned.
///
/// # Examples
///
/// ```
/// use ghidra_core::scalar::Scalar;
///
/// let s = Scalar::new_signed(8, 0xFF);
/// assert_eq!(s.get_signed_value(), -1i64);
/// assert_eq!(s.get_unsigned_value(), 255u64);
/// assert_eq!(s.bit_length(), 8);
/// ```
#[derive(Clone, Copy)]
pub struct Scalar {
    /// The value with upper unused bits masked off.
    value: u64,
    /// Number of bits used by this scalar (0..=64).
    bit_length: u8,
    /// Complement of bit_length: 64 - bit_length.
    unused_bits: u8,
    /// Whether this scalar is preferred as signed.
    signed: bool,
}

impl Scalar {
    /// Construct a new signed scalar.
    ///
    /// `bit_length` must be 1..=64, or 0 if `value` is also 0.
    /// Bits above `bit_length` in `value` are masked off.
    pub fn new_signed(bit_length: u32, value: u64) -> Self {
        Self::new(bit_length, value, true)
    }

    /// Construct a new unsigned scalar.
    ///
    /// `bit_length` must be 1..=64, or 0 if `value` is also 0.
    pub fn new_unsigned(bit_length: u32, value: u64) -> Self {
        Self::new(bit_length, value, false)
    }

    /// Construct a new scalar.
    ///
    /// `bit_length` must be 1..=64, or 0 if `value` is also 0.
    /// `signed` controls preferred signed-ness.
    ///
    /// # Panics
    ///
    /// Panics if `bit_length` is outside 1..=64 (unless both `bit_length`
    /// and `value` are 0).
    pub fn new(bit_length: u32, value: u64, signed: bool) -> Self {
        if !(bit_length == 0 && value == 0) && (bit_length < 1 || bit_length > 64) {
            panic!("Bit length must be >= 1 and <= 64, got {}", bit_length);
        }
        let unused_bits = (64u8).wrapping_sub(bit_length as u8);
        // Mask off upper bits that are outside bit_length.
        let masked = if bit_length == 64 {
            value
        } else if bit_length == 0 {
            0
        } else {
            (value << unused_bits) >> unused_bits
        };
        Self {
            value: masked,
            bit_length: bit_length as u8,
            unused_bits,
            signed,
        }
    }

    /// Returns `true` if this scalar was created as a signed value.
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    /// Get the value as a signed `i64`, sign-extening from `bit_length`.
    ///
    /// If the highest bit of the value (within `bit_length`) is set, it will
    /// be extended to fill a full 64-bit signed integer.
    pub fn get_signed_value(&self) -> i64 {
        if self.bit_length == 0 {
            return 0;
        }
        let shift = self.unused_bits;
        // Sign-extend: shift left then arithmetic-shift right.
        ((self.value as i64) << shift) >> shift
    }

    /// Get the value as an unsigned `u64`.
    pub fn get_unsigned_value(&self) -> u64 {
        self.value
    }

    /// Returns the value in its preferred signed-ness.
    ///
    /// Equivalent to `get_signed_value()` if signed, or
    /// `get_unsigned_value()` if unsigned.
    pub fn get_value(&self) -> i64 {
        if self.signed {
            self.get_signed_value()
        } else {
            self.value as i64
        }
    }

    /// Returns the value, using the specified signedness override.
    pub fn get_value_with_sign(&self, signed: bool) -> i64 {
        if signed {
            self.get_signed_value()
        } else {
            self.value as i64
        }
    }

    /// Returns the `BigInt` (as `(sign, magnitude_bytes)`) representation
    /// of the value.
    ///
    /// The returned tuple is `(signum, magnitude_big_endian_bytes)` where
    /// `signum` is -1, 0, or 1.
    pub fn get_big_integer(&self) -> (i8, Vec<u8>) {
        let signum = if self.signed && self.test_bit(self.bit_length.saturating_sub(1) as u32) {
            -1i8
        } else {
            1i8
        };

        let num_bytes = if self.bit_length == 0 {
            1
        } else {
            ((self.bit_length - 1) / 8 + 1) as usize
        };

        let mut tmp_val = self.get_value();
        if self.signed && tmp_val < 0 {
            tmp_val = -tmp_val;
        }
        let mut data = vec![0u8; num_bytes];
        for i in (0..num_bytes).rev() {
            data[i] = tmp_val as u8;
            tmp_val >>= 8;
        }

        (signum, data)
    }

    /// Returns a big-endian byte array representing this scalar.
    ///
    /// The size of the byte array is the number of bytes required to hold
    /// the number of bits returned by `bit_length()`.
    pub fn byte_array_value(&self) -> Vec<u8> {
        if self.bit_length == 0 {
            return Vec::new();
        }
        let num_bytes = ((self.bit_length - 1) / 8 + 1) as usize;
        let mut tmp_val = self.get_value();
        let mut data = vec![0u8; num_bytes];
        for i in (0..num_bytes).rev() {
            data[i] = tmp_val as u8;
            tmp_val >>= 8;
        }
        data
    }

    /// The size of this scalar in bits.
    ///
    /// This is constant for a given scalar and is not dependent on
    /// the particular value. For example, a 16-bit scalar always returns 16.
    pub fn bit_length(&self) -> u32 {
        self.bit_length as u32
    }

    /// Returns `true` if and only if the designated bit is set.
    ///
    /// Computes `((this & (1 << n)) != 0)`. Bits are numbered 0..bit_length-1
    /// with 0 being the least significant bit.
    ///
    /// # Panics
    ///
    /// Panics if `n >= bit_length()`.
    pub fn test_bit(&self, n: u32) -> bool {
        if n >= self.bit_length as u32 {
            panic!(
                "Bit index {} out of range for scalar with bit_length {}",
                n, self.bit_length
            );
        }
        (self.value & (1u64 << n)) != 0
    }

    /// Format the scalar as a string with the given radix.
    ///
    /// `radix` must be 2, 8, 10, or 16.
    /// `zero_padded` left-pads with zeros to the width necessary to hold the
    /// maximum value.
    /// `show_sign` prepends '-' for negative values (only when signed).
    /// `pre` is appended after the sign (if signed) but before the digits.
    /// `post` is appended after the digits.
    pub fn to_string_fmt(
        &self,
        radix: u32,
        zero_padded: bool,
        show_sign: bool,
        pre: &str,
        post: &str,
    ) -> String {
        if !matches!(radix, 2 | 8 | 10 | 16) {
            panic!("Invalid radix: {}", radix);
        }

        let show_sign = show_sign && self.signed;

        let val: i64 = if show_sign {
            self.get_signed_value()
        } else {
            self.get_unsigned_value() as i64
        };

        let b: String;
        let mut buf = String::with_capacity(32);

        if self.bit_length == 64 && !self.signed {
            // For unsigned 64-bit, use unsigned formatting
            b = format_radix_u64(self.value, radix);
        } else if radix == 10 {
            b = val.to_string();
        } else {
            if show_sign && val < 0 {
                let abs_val = if val == i64::MIN {
                    // Handle i64::MIN special case
                    (val as u64).wrapping_neg()
                } else {
                    (-val) as u64
                };
                buf.push('-');
                b = format_radix_u64(abs_val, radix);
            } else {
                b = format_radix_u64(val as u64, radix);
            }
        }

        buf.push_str(pre);
        if zero_padded {
            let num_digits = self.get_digits(radix) as usize;
            let padding = num_digits.saturating_sub(b.len());
            for _ in 0..padding {
                buf.push('0');
            }
        }
        buf.push_str(&b);
        buf.push_str(post);
        buf
    }

    /// Returns the number of digits needed to represent this scalar in
    /// the given radix.
    fn get_digits(&self, radix: u32) -> u32 {
        match radix {
            2 => self.bit_length as u32,
            8 => (self.bit_length as u32 - 1) / 3 + 1,
            16 => (self.bit_length as u32 - 1) / 4 + 1,
            _ => 0,
        }
    }
}

/// Format a `u64` in the given radix (2, 8, or 16).
fn format_radix_u64(mut val: u64, radix: u32) -> String {
    if val == 0 {
        return "0".to_string();
    }
    let digits = b"0123456789abcdef";
    let mut buf = Vec::new();
    while val > 0 {
        buf.push(digits[(val % radix as u64) as usize]);
        val /= radix as u64;
    }
    buf.reverse();
    String::from_utf8(buf).unwrap()
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        let v = self.get_value();
        if v != other.get_value() {
            return false;
        }
        if v < 0 {
            if self.bit_length == 64 || other.bit_length == 64 {
                // If both values are negative ensure same signed-ness
                return self.signed == other.signed;
            }
        }
        true
    }
}

impl Eq for Scalar {}

impl std::hash::Hash for Scalar {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar")
            .field("value", &self.value)
            .field("bit_length", &self.bit_length)
            .field("signed", &self.signed)
            .finish()
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_fmt(16, false, true, "0x", ""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_signed_8bit() {
        let s = Scalar::new_signed(8, 0xFF);
        assert_eq!(s.get_signed_value(), -1);
        assert_eq!(s.get_unsigned_value(), 255);
        assert_eq!(s.bit_length(), 8);
        assert!(s.is_signed());
    }

    #[test]
    fn test_scalar_unsigned_8bit() {
        let s = Scalar::new_unsigned(8, 0xFF);
        assert_eq!(s.get_unsigned_value(), 255);
        assert_eq!(s.bit_length(), 8);
        assert!(!s.is_signed());
    }

    #[test]
    fn test_scalar_16bit() {
        let s = Scalar::new_signed(16, 0x1234);
        assert_eq!(s.get_signed_value(), 0x1234);
        assert_eq!(s.get_unsigned_value(), 0x1234);
        assert_eq!(s.bit_length(), 16);
    }

    #[test]
    fn test_scalar_zero_length() {
        let s = Scalar::new_signed(0, 0);
        assert_eq!(s.bit_length(), 0);
        assert_eq!(s.get_signed_value(), 0);
    }

    #[test]
    fn test_scalar_masking() {
        // A 4-bit scalar with value 0xFF should mask to 0x0F
        let s = Scalar::new_signed(4, 0xFF);
        assert_eq!(s.get_unsigned_value(), 0x0F);
        assert_eq!(s.get_signed_value(), -1); // 0x0F sign-extended in 4 bits = -1
    }

    #[test]
    fn test_scalar_test_bit() {
        let s = Scalar::new_signed(8, 0b10101010);
        assert!(!s.test_bit(0));
        assert!(s.test_bit(1));
        assert!(!s.test_bit(2));
        assert!(s.test_bit(3));
        assert!(!s.test_bit(4));
        assert!(s.test_bit(5));
        assert!(!s.test_bit(6));
        assert!(s.test_bit(7));
    }

    #[test]
    fn test_scalar_byte_array() {
        let s = Scalar::new_signed(16, 0x1234);
        let bytes = s.byte_array_value();
        assert_eq!(bytes, vec![0x12, 0x34]);
    }

    #[test]
    fn test_scalar_display() {
        let s = Scalar::new_signed(8, 0x42);
        assert_eq!(format!("{}", s), "0x42");
    }

    #[test]
    fn test_scalar_hex_fmt() {
        // 0xABCD in 16 bits signed is negative (bit 15 set = -21555)
        let s = Scalar::new_signed(16, 0xABCD);
        let hex = s.to_string_fmt(16, true, true, "0x", "");
        assert_eq!(hex, "-0x5433"); // -21555 in hex

        // Show unsigned instead
        let hex_unsigned = s.to_string_fmt(16, true, false, "0x", "");
        assert_eq!(hex_unsigned, "0xabcd");

        // Positive value
        let s2 = Scalar::new_signed(16, 0x1234);
        let hex2 = s2.to_string_fmt(16, true, true, "0x", "");
        assert_eq!(hex2, "0x1234");
    }

    #[test]
    fn test_scalar_binary_fmt() {
        let s = Scalar::new_signed(8, 0b10101010);
        let bin = s.to_string_fmt(2, true, false, "", "");
        assert_eq!(bin, "10101010");
    }

    #[test]
    fn test_scalar_octal_fmt() {
        let s = Scalar::new_signed(16, 0o12345);
        let oct = s.to_string_fmt(8, false, false, "", "");
        assert_eq!(oct, "12345");
    }

    #[test]
    fn test_scalar_64bit_unsigned() {
        let s = Scalar::new_unsigned(64, u64::MAX);
        assert_eq!(s.get_unsigned_value(), u64::MAX);
    }

    #[test]
    fn test_scalar_64bit_signed() {
        let s = Scalar::new_signed(64, i64::MIN as u64);
        assert_eq!(s.get_signed_value(), i64::MIN);
    }

    #[test]
    fn test_scalar_equality() {
        let a = Scalar::new_signed(8, 42);
        let b = Scalar::new_signed(8, 42);
        assert_eq!(a, b);

        let c = Scalar::new_unsigned(8, 42);
        assert_eq!(a, c); // Same value, different signed-ness -> still equal
    }

    #[test]
    fn test_scalar_big_integer() {
        let s = Scalar::new_signed(8, 0xFF);
        let (signum, magnitude) = s.get_big_integer();
        assert_eq!(signum, -1);
        assert_eq!(magnitude, vec![1]); // magnitude of -1 is 1
    }

    #[test]
    fn test_scalar_value_with_sign() {
        let s = Scalar::new_signed(8, 0x80);
        assert_eq!(s.get_value_with_sign(true), -128);
        assert_eq!(s.get_value_with_sign(false), 128);
    }
}
