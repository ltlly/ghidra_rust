//! Go version representation ported from Ghidra's
//! `ghidra.app.util.bin.format.golang.GoVer`.
//!
//! Represents a Go version number as `major.minor.patch`, with special sentinel
//! values for wildcarding and invalid states.

use std::cmp::Ordering;
use std::fmt;

/// Represents a Go version number (major.minor.patch).
///
/// Ported from `ghidra.app.util.bin.format.golang.GoVer`. Supports special
/// sentinel values:
/// - `INVALID` (0.0.0) -- represents a failed parse or missing version.
/// - `ANY` (-1.-1.-1) -- wildcard matching any version.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct GoVer {
    major: i32,
    minor: i32,
    patch: i32,
}

/// Program info property name for the Go version string.
pub const GOLANG_VERSION_PROPERTY_NAME: &str = "Golang go version";

impl GoVer {
    /// Invalid version sentinel (0.0.0).
    pub const INVALID: GoVer = GoVer {
        major: 0,
        minor: 0,
        patch: 0,
    };

    /// Wildcard version sentinel (-1.-1.-1), matches any version.
    pub const ANY: GoVer = GoVer {
        major: -1,
        minor: -1,
        patch: -1,
    };

    /// Creates a new `GoVer` with the given components.
    pub const fn new(major: i32, minor: i32, patch: i32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parses a version string ("1.2.3" or "1.2") and returns a `GoVer`.
    ///
    /// Missing patch numbers default to 0. Returns `INVALID` on bad input.
    pub fn parse(s: &str) -> Self {
        Self::parse_inner(s, 0)
    }

    /// Parses a version string and uses -1 (wildcard) for missing patch numbers.
    ///
    /// Useful for version range specifications like "1.2-" where the patch
    /// should match any value.
    pub fn parse_wildcard_patch(s: &str) -> Self {
        Self::parse_inner(s, -1)
    }

    /// Internal parser. Strips trailing non-numeric info (e.g. "1.22.8 X:rangefunc")
    /// and splits on '.' to extract major, minor, patch.
    fn parse_inner(s: &str, missing_patch_value: i32) -> Self {
        // Strip anything after the last digit/dot sequence (e.g. "1.22.8 X:rangefunc")
        let cleaned: String = s
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();

        let parts: Vec<&str> = cleaned.split('.').collect();
        if parts.len() < 2 {
            return Self::INVALID;
        }

        let major = match parts[0].parse::<i32>() {
            Ok(v) => v,
            Err(_) => return Self::INVALID,
        };
        let minor = match parts[1].parse::<i32>() {
            Ok(v) => v,
            Err(_) => return Self::INVALID,
        };
        let patch = if parts.len() > 2 {
            match parts[2].parse::<i32>() {
                Ok(v) => v,
                Err(_) => return Self::INVALID,
            }
        } else {
            missing_patch_value
        };

        Self::new(major, minor, patch)
    }

    /// Returns true if this version is the invalid sentinel (0.0.0).
    pub fn is_invalid(&self) -> bool {
        self.major == 0 && self.minor == 0
    }

    /// Returns true if this version is the wildcard sentinel (-1.-1.-1).
    pub fn is_wildcard(&self) -> bool {
        self.major == -1 && self.minor == -1
    }

    /// Returns the major version number.
    pub fn major(&self) -> i32 {
        self.major
    }

    /// Returns the minor version number.
    pub fn minor(&self) -> i32 {
        self.minor
    }

    /// Returns the patch version number.
    pub fn patch(&self) -> i32 {
        self.patch
    }

    /// Returns a new `GoVer` with the patch decremented by 1 (minimum 0).
    pub fn prev_patch(&self) -> Self {
        Self::new(self.major, self.minor, if self.patch > 0 { self.patch - 1 } else { 0 })
    }

    /// Returns a new `GoVer` with the given patch number.
    pub fn with_patch(&self, new_patch: i32) -> Self {
        Self::new(self.major, self.minor, new_patch)
    }
}

impl PartialOrd for GoVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GoVer {
    /// Compares two versions. Wildcard patches (-1) are treated as equal to
    /// any other patch value during comparison.
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        // Wildcard patches (-1) match anything
        if self.patch == -1 || other.patch == -1 {
            Ordering::Equal
        } else {
            self.patch.cmp(&other.patch)
        }
    }
}

impl fmt::Display for GoVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.patch != -1 {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let v = GoVer::parse("1.2.3");
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 2);
        assert_eq!(v.patch(), 3);
        assert!(!v.is_invalid());
        assert!(!v.is_wildcard());
    }

    #[test]
    fn test_parse_no_patch() {
        let v = GoVer::parse("1.5");
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 5);
        assert_eq!(v.patch(), 0); // defaults to 0
    }

    #[test]
    fn test_parse_wildcard_patch() {
        let v = GoVer::parse_wildcard_patch("1.5");
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 5);
        assert_eq!(v.patch(), -1); // wildcard
    }

    #[test]
    fn test_parse_with_trailing_info() {
        let v = GoVer::parse("1.22.8 X:rangefunc");
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 22);
        assert_eq!(v.patch(), 8);
    }

    #[test]
    fn test_parse_invalid() {
        assert!(GoVer::parse("").is_invalid());
        assert!(GoVer::parse("abc").is_invalid());
        assert!(GoVer::parse("1").is_invalid()); // needs at least major.minor
    }

    #[test]
    fn test_invalid_sentinel() {
        let v = GoVer::INVALID;
        assert!(v.is_invalid());
        assert!(!v.is_wildcard());
    }

    #[test]
    fn test_any_sentinel() {
        let v = GoVer::ANY;
        assert!(!v.is_invalid());
        assert!(v.is_wildcard());
    }

    #[test]
    fn test_comparison() {
        let v1 = GoVer::parse("1.2.3");
        let v2 = GoVer::parse("1.2.4");
        let v3 = GoVer::parse("1.3.0");
        let v4 = GoVer::parse("2.0.0");

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
    }

    #[test]
    fn test_comparison_wildcard_patch() {
        let v1 = GoVer::parse("1.2.3");
        let v2 = GoVer::new(1, 2, -1); // wildcard patch
        assert_eq!(v1.cmp(&v2), Ordering::Equal);
    }

    #[test]
    fn test_prev_patch() {
        let v = GoVer::parse("1.2.3");
        assert_eq!(v.prev_patch(), GoVer::new(1, 2, 2));

        let v0 = GoVer::parse("1.2.0");
        assert_eq!(v0.prev_patch(), GoVer::new(1, 2, 0)); // clamped at 0
    }

    #[test]
    fn test_with_patch() {
        let v = GoVer::parse("1.2.3");
        assert_eq!(v.with_patch(5), GoVer::new(1, 2, 5));
    }

    #[test]
    fn test_display() {
        assert_eq!(GoVer::parse("1.2.3").to_string(), "1.2.3");
        assert_eq!(GoVer::new(1, 5, -1).to_string(), "1.5");
    }

    #[test]
    fn test_ordering_sort() {
        let mut versions = vec![
            GoVer::parse("1.3.0"),
            GoVer::parse("1.1.0"),
            GoVer::parse("1.2.0"),
            GoVer::parse("2.0.0"),
        ];
        versions.sort();
        assert_eq!(versions[0], GoVer::parse("1.1.0"));
        assert_eq!(versions[1], GoVer::parse("1.2.0"));
        assert_eq!(versions[2], GoVer::parse("1.3.0"));
        assert_eq!(versions[3], GoVer::parse("2.0.0"));
    }
}
