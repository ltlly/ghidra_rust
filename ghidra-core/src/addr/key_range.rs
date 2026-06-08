//! Key range for database operations.
//!
//! Direct translation of `ghidra.program.model.address.KeyRange`.
//!
//! A [`KeyRange`] holds a contiguous range of database keys (unsigned `u64`
//! values), used internally for efficient database scanning.

use serde::{Deserialize, Serialize};

/// A contiguous range of database keys.
///
/// Corresponds to `ghidra.program.model.address.KeyRange`. Keys are
/// unsigned and ordered: `min_key <= max_key`. Both endpoints are inclusive.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::key_range::KeyRange;
///
/// let kr = KeyRange::new(100, 200);
/// assert!(kr.contains(150));
/// assert!(!kr.contains(201));
/// assert_eq!(kr.length(), 101);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyRange {
    /// Minimum key (inclusive).
    pub min_key: u64,
    /// Maximum key (inclusive).
    pub max_key: u64,
}

impl KeyRange {
    /// Constructs a new key range.
    ///
    /// Both keys are inclusive. The caller must ensure `min_key <= max_key`.
    pub fn new(min_key: u64, max_key: u64) -> Self {
        Self { min_key, max_key }
    }

    /// Returns `true` if `key` is within this range `[min_key, max_key]`.
    pub fn contains(&self, key: u64) -> bool {
        key >= self.min_key && key <= self.max_key
    }

    /// Returns the number of keys contained within this range.
    pub fn length(&self) -> u64 {
        self.max_key - self.min_key + 1
    }

    /// Returns `true` if this range is empty (min_key > max_key).
    pub fn is_empty(&self) -> bool {
        self.min_key > self.max_key
    }

    /// Returns `true` if this range overlaps with another range.
    pub fn intersects(&self, other: &KeyRange) -> bool {
        self.min_key <= other.max_key && other.min_key <= self.max_key
    }

    /// Returns the intersection of this range with another, if any.
    pub fn intersection(&self, other: &KeyRange) -> Option<KeyRange> {
        let lo = self.min_key.max(other.min_key);
        let hi = self.max_key.min(other.max_key);
        if lo <= hi {
            Some(KeyRange::new(lo, hi))
        } else {
            None
        }
    }
}

impl std::fmt::Display for KeyRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, {}]", self.min_key, self.max_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_range_basic() {
        let kr = KeyRange::new(100, 200);
        assert!(kr.contains(100));
        assert!(kr.contains(200));
        assert!(kr.contains(150));
        assert!(!kr.contains(99));
        assert!(!kr.contains(201));
        assert_eq!(kr.length(), 101);
    }

    #[test]
    fn test_key_range_singleton() {
        let kr = KeyRange::new(42, 42);
        assert!(kr.contains(42));
        assert_eq!(kr.length(), 1);
    }

    #[test]
    fn test_key_range_intersection() {
        let a = KeyRange::new(100, 200);
        let b = KeyRange::new(150, 250);
        let i = a.intersection(&b).unwrap();
        assert_eq!(i.min_key, 150);
        assert_eq!(i.max_key, 200);

        let c = KeyRange::new(300, 400);
        assert!(a.intersection(&c).is_none());
    }

    #[test]
    fn test_key_range_intersects() {
        let a = KeyRange::new(100, 200);
        let b = KeyRange::new(150, 250);
        assert!(a.intersects(&b));

        let c = KeyRange::new(300, 400);
        assert!(!a.intersects(&c));
    }
}
