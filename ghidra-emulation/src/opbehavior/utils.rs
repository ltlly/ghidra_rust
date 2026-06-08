//! Utility functions for P-code operation behavior.
//!
//! Ported from Java: `ghidra.pcode.utils.Utils`.

use num_bigint::BigInt;

/// Calculate a bitmask for a given size in bytes.
///
/// For size N, returns a mask with the low N*8 bits set.
///
/// # Examples
/// - `calc_mask(1)` = `0xFF`
/// - `calc_mask(2)` = `0xFFFF`
/// - `calc_mask(4)` = `0xFFFFFFFF`
/// - `calc_mask(8)` = `0xFFFFFFFFFFFFFFFF`
pub fn calc_mask(size: usize) -> u64 {
    if size >= 8 {
        return u64::MAX;
    }
    (1u64 << (size * 8)) - 1
}

/// Calculate a bitmask for a given size in bytes as a BigInt.
pub fn calc_bigmask(size: usize) -> BigInt {
    if size >= 8 {
        return BigInt::from(u64::MAX);
    }
    BigInt::from((1u128 << (size * 8)) - 1)
}

/// Bitwise negate (NOT) an unsigned value, masked to the given size.
pub fn uintb_negate(val: u64, size: usize) -> u64 {
    !val & calc_mask(size)
}

/// Sign-extend a value from `from_size` bytes to `to_size` bytes.
///
/// The sign bit is at position `from_size * 8 - 1`.
pub fn sign_extend(val: u64, from_size: usize, to_size: usize) -> u64 {
    if from_size >= to_size {
        return val & calc_mask(to_size);
    }
    let sign_bit = from_size * 8 - 1;
    let sign = (val >> sign_bit) & 1;
    if sign == 0 {
        val & calc_mask(from_size)
    } else {
        let extension = calc_mask(to_size) ^ calc_mask(from_size);
        val | extension
    }
}

/// Check if the sign bit of a value (interpreted as `size` bytes) is set.
pub fn signbit_negative(val: u64, size: usize) -> bool {
    let sign_bit = (size * 8) - 1;
    ((val >> sign_bit) & 1) != 0
}

/// Sign-extend a value as used by `zzz_sign_extend` in Ghidra.
///
/// This extends from bit position `bitpos` (0-indexed from LSB).
pub fn zzz_sign_extend(val: u64, bitpos: usize) -> u64 {
    if bitpos >= 63 {
        return val; // full-width u64, nothing to extend
    }
    let sign_bit = 1u64 << bitpos;
    if val & sign_bit != 0 {
        // Set all bits above bitpos
        val | (!0u64 << bitpos)
    } else {
        val & ((1u64 << (bitpos + 1)) - 1)
    }
}

/// Zero-extend a value as used by `zzz_zero_extend` in Ghidra.
///
/// This clears all bits above position `bitpos`.
pub fn zzz_zero_extend(val: u64, bitpos: usize) -> u64 {
    if bitpos >= 63 {
        return val; // full-width u64, nothing to clear
    }
    val & ((1u64 << (bitpos + 1)) - 1)
}

/// Convert an unsigned BigInt to its signed representation for a given size.
///
/// If the sign bit (at position `size*8-1`) is set, the value is interpreted
/// as negative by performing two's complement.
pub fn convert_to_signed_value(val: &BigInt, size: usize) -> BigInt {
    let sign_bit = size * 8 - 1;
    if val.bit(sign_bit as u64) {
        // Two's complement: negate and add 1, then negate
        let mask = calc_bigmask(size);
        let unsigned = val & mask;
        let max_val = BigInt::from(1) << sign_bit;
        unsigned - (max_val << 1)
    } else {
        val.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_mask() {
        assert_eq!(calc_mask(0), 0);
        assert_eq!(calc_mask(1), 0xFF);
        assert_eq!(calc_mask(2), 0xFFFF);
        assert_eq!(calc_mask(4), 0xFFFFFFFF);
        assert_eq!(calc_mask(8), 0xFFFFFFFFFFFFFFFF);
    }

    #[test]
    fn test_uintb_negate() {
        assert_eq!(uintb_negate(0x00, 1), 0xFF);
        assert_eq!(uintb_negate(0xFF, 1), 0x00);
        assert_eq!(uintb_negate(0x0F, 1), 0xF0);
    }

    #[test]
    fn test_sign_extend_positive() {
        // 0x7F positive in 1 byte -> 0x007F in 2 bytes
        assert_eq!(sign_extend(0x7F, 1, 2), 0x007F);
    }

    #[test]
    fn test_sign_extend_negative() {
        // 0x80 negative in 1 byte -> 0xFF80 in 2 bytes
        assert_eq!(sign_extend(0x80, 1, 2), 0xFF80);
    }

    #[test]
    fn test_sign_extend_4_to_8() {
        // 0x80000000 negative in 4 bytes -> 0xFFFFFFFF80000000 in 8 bytes
        assert_eq!(sign_extend(0x80000000, 4, 8), 0xFFFFFFFF80000000);
    }

    #[test]
    fn test_signbit_negative() {
        assert!(!signbit_negative(0x7F, 1));
        assert!(signbit_negative(0x80, 1));
        assert!(signbit_negative(0xFF, 1));
    }

    #[test]
    fn test_zzz_sign_extend() {
        // Sign extend from bit 7 (1 byte)
        assert_eq!(zzz_sign_extend(0x80, 7), 0xFFFFFFFFFFFFFF80);
        assert_eq!(zzz_sign_extend(0x7F, 7), 0x7F);
    }

    #[test]
    fn test_zzz_zero_extend() {
        assert_eq!(zzz_zero_extend(0xFF, 7), 0xFF);
        assert_eq!(zzz_zero_extend(0x1FF, 7), 0xFF);
    }
}
