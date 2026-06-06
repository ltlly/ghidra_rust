//! Simple data structures: Duo, Range, and Location.
//!
//! Port of `ghidra.util.datastruct.Duo`, `ghidra.util.datastruct.Range`,
//! and `ghidra.util.Location`.

use std::fmt;

/// A pair of two values.
///
/// Port of `ghidra.util.datastruct.Duo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Duo<T> {
    /// The first element.
    pub first: T,
    /// The second element.
    pub second: T,
}

impl<T> Duo<T> {
    /// Create a new Duo.
    pub fn new(first: T, second: T) -> Self {
        Self { first, second }
    }

    /// Swap the two elements.
    pub fn swap(self) -> Duo<T> {
        Duo {
            first: self.second,
            second: self.first,
        }
    }
}

impl<T: fmt::Display> fmt::Display for Duo<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.first, self.second)
    }
}

/// An inclusive range of long values.
///
/// Port of `ghidra.util.datastruct.Range`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Range {
    /// The minimum (inclusive) value.
    pub min: i64,
    /// The maximum (inclusive) value.
    pub max: i64,
}

impl Range {
    /// Create a new range. The min is clamped to be <= max.
    pub fn new(min: i64, max: i64) -> Self {
        Self {
            min: min.min(max),
            max: min.max(max),
        }
    }

    /// Get the minimum value.
    pub fn min(&self) -> i64 {
        self.min
    }

    /// Get the maximum value.
    pub fn max(&self) -> i64 {
        self.max
    }

    /// Check if a value is within the range (inclusive).
    pub fn contains(&self, value: i64) -> bool {
        value >= self.min && value <= self.max
    }

    /// Check if this range overlaps with another.
    pub fn overlaps(&self, other: &Range) -> bool {
        self.min <= other.max && other.min <= self.max
    }

    /// Get the length of the range (max - min + 1 for inclusive).
    pub fn length(&self) -> i64 {
        self.max - self.min + 1
    }

    /// Create the intersection of two ranges, if they overlap.
    pub fn intersection(&self, other: &Range) -> Option<Range> {
        if self.overlaps(other) {
            Some(Range::new(
                self.min.max(other.min),
                self.max.min(other.max),
            ))
        } else {
            None
        }
    }

    /// Create the union (bounding range) of two ranges.
    pub fn union(&self, other: &Range) -> Range {
        Range::new(self.min.min(other.min), self.max.max(other.max))
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.min, self.max)
    }
}

/// A memory location (address and optional component path).
///
/// Port of `ghidra.util.Location`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Location {
    /// The address (as a u64 for simplicity).
    pub address: u64,
    /// Optional component path for hierarchical addressing.
    pub component_path: Option<String>,
}

impl Location {
    /// Create a new location at the given address.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            component_path: None,
        }
    }

    /// Create a location with a component path.
    pub fn with_component(address: u64, component_path: impl Into<String>) -> Self {
        Self {
            address,
            component_path: Some(component_path.into()),
        }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.address)?;
        if let Some(ref path) = self.component_path {
            write!(f, "[{}]", path)?;
        }
        Ok(())
    }
}

/// Fixup utilities for common address calculations.
///
/// Port of `ghidra.util.Fixup`.
pub struct Fixup;

impl Fixup {
    /// Align an address to the given alignment.
    pub fn align(address: u64, alignment: u64) -> u64 {
        if alignment == 0 || alignment == 1 {
            return address;
        }
        let mask = alignment - 1;
        (address + mask) & !mask
    }

    /// Compute a relative offset from base to target.
    pub fn relative_offset(base: u64, target: u64) -> i64 {
        target.wrapping_sub(base) as i64
    }
}

/// User-facing search utilities.
///
/// Port of `ghidra.util.UserSearchUtils`.
pub struct UserSearchUtils;

impl UserSearchUtils {
    /// Convert a user glob pattern to a regex pattern string.
    pub fn glob_to_regex(glob: &str) -> String {
        let mut regex = String::from("^");
        for ch in glob.chars() {
            match ch {
                '*' => regex.push_str(".*"),
                '?' => regex.push('.'),
                '.' => regex.push_str("\\."),
                '[' => regex.push('['),
                ']' => regex.push(']'),
                _ => regex.push(ch),
            }
        }
        regex.push('$');
        regex
    }

    /// Case-insensitive string contains.
    pub fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
        haystack.to_lowercase().contains(&needle.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duo() {
        let d = Duo::new(1, 2);
        assert_eq!(d.first, 1);
        assert_eq!(d.second, 2);
        let swapped = d.swap();
        assert_eq!(swapped.first, 2);
        assert_eq!(swapped.second, 1);
    }

    #[test]
    fn test_range() {
        let r = Range::new(10, 20);
        assert!(r.contains(15));
        assert!(!r.contains(5));
        assert!(!r.contains(25));
        assert_eq!(r.length(), 11);
    }

    #[test]
    fn test_range_overlap() {
        let r1 = Range::new(10, 20);
        let r2 = Range::new(15, 25);
        assert!(r1.overlaps(&r2));
        let inter = r1.intersection(&r2).unwrap();
        assert_eq!(inter.min, 15);
        assert_eq!(inter.max, 20);

        let r3 = Range::new(30, 40);
        assert!(!r1.overlaps(&r3));
        assert!(r1.intersection(&r3).is_none());
    }

    #[test]
    fn test_range_union() {
        let r1 = Range::new(10, 20);
        let r2 = Range::new(15, 25);
        let u = r1.union(&r2);
        assert_eq!(u.min, 10);
        assert_eq!(u.max, 25);
    }

    #[test]
    fn test_location() {
        let loc = Location::new(0x1000);
        assert_eq!(format!("{}", loc), "0x1000");

        let loc = Location::with_component(0x1000, "field.x");
        assert_eq!(format!("{}", loc), "0x1000[field.x]");
    }

    #[test]
    fn test_fixup() {
        assert_eq!(Fixup::align(0x1005, 4), 0x1008);
        assert_eq!(Fixup::align(0x1000, 4), 0x1000);
        assert_eq!(Fixup::align(0x1000, 0), 0x1000);
    }

    #[test]
    fn test_glob_to_regex() {
        let re = UserSearchUtils::glob_to_regex("*.java");
        assert_eq!(re, "^.*\\.java$");
    }

    #[test]
    fn test_contains_ignore_case() {
        assert!(UserSearchUtils::contains_ignore_case("Hello World", "hello"));
        assert!(!UserSearchUtils::contains_ignore_case("Hello World", "xyz"));
    }
}
