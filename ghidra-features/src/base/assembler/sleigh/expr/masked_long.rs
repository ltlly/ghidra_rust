//! A 64-bit value with an associated bit mask.
//!
//! Corresponds to Java's `MaskedLong`.  A `MaskedLong` represents a
//! 64-bit value where some bits may be unknown.  The `mask` field
//! indicates which bits are known (1 = known, 0 = unknown).

use std::fmt;

/// A 64-bit value with an associated bit mask.
///
/// The `mask` indicates which bits of `val` are significant.
/// Operations on `MaskedLong` propagate masks correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MaskedLong {
    /// The value.
    val: u64,
    /// The mask (1 = known bit, 0 = unknown).
    mask: u64,
}

impl MaskedLong {
    /// All bits unknown.
    pub const UNKNOWN: Self = Self { val: 0, mask: 0 };

    /// Create a fully-known value.
    pub const fn from_u64(val: u64) -> Self {
        Self {
            val,
            mask: u64::MAX,
        }
    }

    /// Create a fully-known value from i64.
    pub const fn from_i64(val: i64) -> Self {
        Self::from_u64(val as u64)
    }

    /// Create from raw value and mask.
    ///
    /// The value is masked so only known bits are stored.
    pub const fn new(val: u64, mask: u64) -> Self {
        Self {
            val: val & mask,
            mask,
        }
    }

    /// Get the raw value (only meaningful where mask bits are set).
    pub const fn get_unsigned(self) -> u64 {
        self.val
    }

    /// Get the value as a signed i64.
    pub const fn get_signed(self) -> i64 {
        self.val as i64
    }

    /// Get the mask.
    pub const fn get_mask(self) -> u64 {
        self.mask
    }

    /// Check if all bits are known (mask is all 1s).
    pub const fn is_full_mask(self) -> bool {
        self.mask == u64::MAX
    }

    /// Check if the value is completely unknown.
    pub const fn is_unknown(self) -> bool {
        self.mask == 0
    }

    /// Check if this value matches another, taking masks into account.
    ///
    /// Returns true if, for every bit known in both values, the
    /// corresponding value bits are equal.
    pub fn matches(self, other: Self) -> bool {
        let common_mask = self.mask & other.mask;
        (self.val & common_mask) == (other.val & common_mask)
    }

    /// Fill unknown bits with 0 (set mask to all 1s).
    pub const fn fill_mask(self) -> Self {
        Self {
            val: self.val,
            mask: u64::MAX,
        }
    }

    /// Combine two masked longs, checking for compatibility.
    ///
    /// Returns `None` if the known bits conflict.
    pub fn combine(self, other: Self) -> Option<Self> {
        let common = self.mask & other.mask;
        if (self.val & common) != (other.val & common) {
            return None;
        }
        Some(Self {
            val: self.val | other.val,
            mask: self.mask | other.mask,
        })
    }

    /// Set specific bits in the value and mask.
    pub fn set_bits(self, val: u64, mask: u64) -> Self {
        Self {
            val: (self.val & !mask) | (val & mask),
            mask: self.mask | mask,
        }
    }

    /// Clear bits indicated by the given mask.
    pub fn clear_mask(self, clear: u64) -> Self {
        Self {
            val: self.val & !clear,
            mask: self.mask & !clear,
        }
    }

    /// Length in bytes needed to represent this value.
    ///
    /// Returns the number of bytes needed to hold the significant
    /// bits of the value (after masking).
    pub fn length(self) -> usize {
        let val = self.val; // already masked
        if val == 0 {
            return 0;
        }
        let highest = 63 - val.leading_zeros() as usize;
        (highest / 8) + 1
    }

    // ---- Arithmetic operations (mask-aware) ----

    /// Addition.
    pub fn add(self, other: Self) -> Self {
        let result_val = self.val.wrapping_add(other.val);
        // For addition, we can only keep full mask if both are fully known
        let result_mask = if self.is_full_mask() && other.is_full_mask() {
            u64::MAX
        } else {
            // Conservative: result mask is the intersection
            self.mask & other.mask
        };
        Self::new(result_val, result_mask)
    }

    /// Subtraction.
    pub fn sub(self, other: Self) -> Self {
        let result_val = self.val.wrapping_sub(other.val);
        let result_mask = if self.is_full_mask() && other.is_full_mask() {
            u64::MAX
        } else {
            self.mask & other.mask
        };
        Self::new(result_val, result_mask)
    }

    /// Multiplication.
    pub fn mult(self, other: Self) -> Self {
        let result_val = self.val.wrapping_mul(other.val);
        let result_mask = if self.is_full_mask() && other.is_full_mask() {
            u64::MAX
        } else {
            self.mask & other.mask
        };
        Self::new(result_val, result_mask)
    }

    /// Division (unsigned).
    pub fn div(self, other: Self) -> Self {
        let other_val = other.val;
        if other_val == 0 {
            return Self::UNKNOWN;
        }
        let result_val = self.val.wrapping_div(other_val);
        let result_mask = if self.is_full_mask() && other.is_full_mask() {
            u64::MAX
        } else {
            self.mask & other.mask
        };
        Self::new(result_val, result_mask)
    }

    /// Bitwise AND.
    pub fn and(self, other: Self) -> Self {
        Self::new(self.val & other.val, self.mask & other.mask)
    }

    /// Bitwise AND-NOT (self & !other).
    pub fn and_not(self, other: Self) -> Self {
        Self::new(self.val & !other.val, self.mask & !other.mask)
    }

    /// Bitwise OR.
    pub fn or(self, other: Self) -> Self {
        Self::new(self.val | other.val, self.mask | other.mask)
    }

    /// Bitwise XOR.
    pub fn xor(self, other: Self) -> Self {
        Self::new(self.val ^ other.val, self.mask | other.mask)
    }

    /// Bitwise NOT.
    pub fn not(self) -> Self {
        Self::new(!self.val, self.mask)
    }

    /// Left shift.
    pub fn left_shift(self, amount: u32) -> Self {
        if amount >= 64 {
            return Self::new(0, self.mask);
        }
        Self::new(
            self.val.wrapping_shl(amount),
            self.mask.wrapping_shl(amount),
        )
    }

    /// Right shift (logical).
    pub fn right_shift(self, amount: u32) -> Self {
        if amount >= 64 {
            return Self::new(0, self.mask);
        }
        Self::new(
            self.val.wrapping_shr(amount),
            self.mask.wrapping_shr(amount),
        )
    }

    /// Extract bits [lsb, msb] from this value.
    pub fn extract_bits(self, lsb: u32, msb: u32) -> Self {
        let width = msb - lsb + 1;
        if width >= 64 {
            return self;
        }
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        Self::new((self.val >> lsb) & mask, (self.mask >> lsb) & mask)
    }

    /// Convert to big-endian bytes of the given length.
    pub fn to_be_bytes(self, len: usize) -> Vec<u8> {
        let bytes = self.val.to_be_bytes();
        let start = 8_usize.saturating_sub(len);
        bytes[start..].to_vec()
    }

    /// Convert to little-endian bytes of the given length.
    pub fn to_le_bytes(self, len: usize) -> Vec<u8> {
        let bytes = self.val.to_le_bytes();
        bytes[..len.min(8)].to_vec()
    }
}

impl fmt::Display for MaskedLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_full_mask() {
            write!(f, "{:#x}", self.val)
        } else if self.is_unknown() {
            write!(f, "???")
        } else {
            write!(f, "{:#x}/mask={:#x}", self.val, self.mask)
        }
    }
}

impl Default for MaskedLong {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

impl From<u64> for MaskedLong {
    fn from(v: u64) -> Self {
        Self::from_u64(v)
    }
}

impl From<i64> for MaskedLong {
    fn from(v: i64) -> Self {
        Self::from_i64(v)
    }
}

impl From<u32> for MaskedLong {
    fn from(v: u32) -> Self {
        Self::from_u64(v as u64)
    }
}

impl From<i32> for MaskedLong {
    fn from(v: i32) -> Self {
        Self::from_i64(v as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_construction() {
        let v = MaskedLong::from_u64(0x42);
        assert_eq!(v.get_unsigned(), 0x42);
        assert!(v.is_full_mask());

        let u = MaskedLong::UNKNOWN;
        assert!(u.is_unknown());
        assert_eq!(u.get_unsigned(), 0);
    }

    #[test]
    fn test_matches() {
        let a = MaskedLong::new(0xFF, 0xFF); // val=0xFF, mask=0xFF
        // Use a value whose low nibble matches a's low nibble (0xF)
        let b = MaskedLong::new(0x0F, 0x0F); // val=0x0F, mask=0x0F
        assert!(a.matches(b)); // common mask=0x0F, a.val&0x0F==b.val&0x0F
        assert!(b.matches(a)); // same check reversed

        let c = MaskedLong::new(0xFE, 0xFF);
        assert!(!a.matches(c)); // 0xFF & 0xFF != 0xFE & 0xFF
    }

    #[test]
    fn test_combine() {
        // a: val=0xAB (full mask), b: val whose low nibble matches a's
        let a = MaskedLong::new(0xAB, 0xFF); // val=0xAB, mask=0xFF
        let b = MaskedLong::new(0xFB, 0x0F); // val=0x0B, mask=0x0F (low nibble matches 0xAB)
        let combined = a.combine(b).unwrap();
        assert_eq!(combined.get_mask(), 0xFF);
        // val = 0xAB | 0x0B = 0xAB
        assert_eq!(combined.get_unsigned(), 0xAB);

        // Conflicting
        let c = MaskedLong::new(0x01, 0xFF);
        let d = MaskedLong::new(0x00, 0xFF);
        assert!(c.combine(d).is_none());
    }

    #[test]
    fn test_arithmetic() {
        let a = MaskedLong::from_u64(10);
        let b = MaskedLong::from_u64(3);
        assert_eq!(a.add(b).get_unsigned(), 13);
        assert_eq!(a.sub(b).get_unsigned(), 7);
        assert_eq!(a.mult(b).get_unsigned(), 30);
        assert_eq!(a.div(b).get_unsigned(), 3);
    }

    #[test]
    fn test_bitwise() {
        let a = MaskedLong::from_u64(0b1010);
        let b = MaskedLong::from_u64(0b1100);
        assert_eq!(a.and(b).get_unsigned(), 0b1000);
        assert_eq!(a.or(b).get_unsigned(), 0b1110);
        assert_eq!(a.xor(b).get_unsigned(), 0b0110);
        assert_eq!(a.not().get_unsigned(), !0b1010u64);
    }

    #[test]
    fn test_shifts() {
        let v = MaskedLong::from_u64(1);
        assert_eq!(v.left_shift(4).get_unsigned(), 16);
        assert_eq!(MaskedLong::from_u64(16).right_shift(2).get_unsigned(), 4);
    }

    #[test]
    fn test_extract_bits() {
        let v = MaskedLong::from_u64(0xDEADBEEF);
        assert_eq!(v.extract_bits(0, 7).get_unsigned(), 0xEF);
        assert_eq!(v.extract_bits(8, 15).get_unsigned(), 0xBE);
        assert_eq!(v.extract_bits(16, 31).get_unsigned(), 0xDEAD);
    }

    #[test]
    fn test_length() {
        assert_eq!(MaskedLong::from_u64(0xFF).length(), 1);
        assert_eq!(MaskedLong::from_u64(0x1FF).length(), 2);
        assert_eq!(MaskedLong::from_u64(0x1_0000).length(), 3);
        assert_eq!(MaskedLong::UNKNOWN.length(), 0);
    }

    #[test]
    fn test_fill_mask() {
        // new(0xAB, 0x0F) stores val = 0x0B (masked)
        let v = MaskedLong::new(0xAB, 0x0F);
        assert_eq!(v.get_unsigned(), 0x0B);
        let filled = v.fill_mask();
        assert!(filled.is_full_mask());
        assert_eq!(filled.get_unsigned(), 0x0B); // preserved masked value
    }

    #[test]
    fn test_set_and_clear() {
        let v = MaskedLong::new(0, 0);
        let v = v.set_bits(0xFF, 0x0F);
        assert_eq!(v.get_unsigned(), 0x0F);
        assert_eq!(v.get_mask(), 0x0F);

        let v = v.clear_mask(0x03);
        assert_eq!(v.get_unsigned(), 0x0C);
        assert_eq!(v.get_mask(), 0x0C);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", MaskedLong::from_u64(42)), "0x2a");
        assert_eq!(format!("{}", MaskedLong::UNKNOWN), "???");
    }
}
