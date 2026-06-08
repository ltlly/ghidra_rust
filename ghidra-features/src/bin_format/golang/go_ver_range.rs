//! Go version range representation ported from Ghidra's
//! `ghidra.app.util.bin.format.golang.GoVerRange`.
//!
//! Represents a contiguous range of Go versions (e.g. "1.2-1.5") with support
//! for wildcard boundaries. A range can be open-ended on either side using
//! `GoVer::ANY` as the start or end.

use std::fmt;

use super::go_ver::GoVer;

/// Represents a range of Go versions.
///
/// Ported from `ghidra.app.util.bin.format.golang.GoVerRange`. A range is
/// defined by a `start` and `end` version (both inclusive). Wildcard versions
/// (`GoVer::ANY`) can be used for open-ended ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GoVerRange {
    start: GoVer,
    end: GoVer,
}

impl GoVerRange {
    /// A range that matches all versions.
    pub const ALL: GoVerRange = GoVerRange {
        start: GoVer::ANY,
        end: GoVer::ANY,
    };

    /// An empty/invalid range.
    pub const EMPTY: GoVerRange = GoVerRange {
        start: GoVer::INVALID,
        end: GoVer::INVALID,
    };

    /// Creates a new version range with the given start and end.
    pub const fn new(start: GoVer, end: GoVer) -> Self {
        Self { start, end }
    }

    /// Returns the start version of this range.
    pub fn start(&self) -> GoVer {
        self.start
    }

    /// Returns the end version of this range.
    pub fn end(&self) -> GoVer {
        self.end
    }

    /// Parses a version range string.
    ///
    /// Supported formats:
    /// - `"1.2-1.5"` -- specific range from 1.2 to 1.5
    /// - `"-1.5"` -- from any version up to 1.5
    /// - `"1.2+"` -- from 1.2 onwards
    /// - `"1.2-"` -- from 1.2 onwards (same as `+`)
    /// - `"1.2"` -- single version (start == end)
    ///
    /// Returns `EMPTY` if the string is invalid.
    pub fn parse(s: &str) -> Self {
        // Split on '+' or '-'.  "1.2-1.5" or "1.2+" or "-1.2"
        let parts: Vec<&str> = s.splitn(2, |c: char| c == '+' || c == '-').collect();
        let start_str = parts[0];
        let end_str = if parts.len() > 1 { parts[1] } else { parts[0] };

        let start = if start_str.is_empty() {
            GoVer::ANY
        } else {
            GoVer::parse_wildcard_patch(start_str)
        };

        let end = if std::ptr::eq(end_str, start_str) {
            // Same string reference means no separator was found; single version
            start
        } else if end_str.is_empty() {
            GoVer::ANY
        } else {
            GoVer::parse_wildcard_patch(end_str)
        };

        // Return EMPTY if both are ANY (unbounded both ways) or either is invalid
        if (start == GoVer::ANY && end == GoVer::ANY) || start.is_invalid() || end.is_invalid() {
            Self::EMPTY
        } else {
            Self::new(start, end)
        }
    }

    /// Returns true if this range is empty (invalid start or end).
    pub fn is_empty(&self) -> bool {
        self.start.is_invalid() || self.end.is_invalid()
    }

    /// Returns true if this range has a wildcard start or end.
    pub fn has_wildcard(&self) -> bool {
        self.start.is_wildcard() || self.end.is_wildcard()
    }

    /// Returns true if this range contains the specified version.
    ///
    /// A version is contained if:
    /// - Neither start nor end is invalid, AND
    /// - start is wildcard OR start <= ver, AND
    /// - end is wildcard OR end >= ver
    pub fn contains(&self, ver: GoVer) -> bool {
        !self.start.is_invalid()
            && !self.end.is_invalid()
            && (self.start.is_wildcard() || self.start <= ver)
            && (self.end.is_wildcard() || self.end >= ver)
    }

    /// Returns a list of minor Go versions between start and end (inclusive).
    ///
    /// Returns an error if start and end have different major versions, or
    /// if the range is empty or has wildcards.
    pub fn as_list(&self) -> Result<Vec<GoVer>, String> {
        if self.start.major() != self.end.major() || self.is_empty() || self.has_wildcard() {
            return Err(
                "Unable to make version list, invalid or wildcard or spans versions".to_string(),
            );
        }
        let mut result = Vec::new();
        for minor in self.start.minor()..=self.end.minor() {
            result.push(GoVer::new(1, minor, 0));
        }
        Ok(result)
    }
}

impl fmt::Display for GoVerRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else if self.start.is_wildcard() {
            write!(f, "-{}", self.end)
        } else if self.end.is_wildcard() {
            write!(f, "{}+", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_specific_range() {
        let r = GoVerRange::parse("1.2-1.5");
        assert_eq!(r.start(), GoVer::new(1, 2, -1));
        assert_eq!(r.end(), GoVer::new(1, 5, -1));
        assert!(!r.is_empty());
        assert!(!r.has_wildcard());
    }

    #[test]
    fn test_parse_open_end() {
        let r = GoVerRange::parse("1.2+");
        assert_eq!(r.start(), GoVer::new(1, 2, -1));
        assert_eq!(r.end(), GoVer::ANY);
        assert!(r.has_wildcard());
    }

    #[test]
    fn test_parse_open_start() {
        let r = GoVerRange::parse("-1.5");
        assert_eq!(r.start(), GoVer::ANY);
        assert_eq!(r.end(), GoVer::new(1, 5, -1));
        assert!(r.has_wildcard());
    }

    #[test]
    fn test_parse_single_version() {
        let r = GoVerRange::parse("1.5");
        assert_eq!(r.start(), GoVer::new(1, 5, -1));
        assert_eq!(r.end(), GoVer::new(1, 5, -1));
    }

    #[test]
    fn test_parse_invalid() {
        let r = GoVerRange::parse("");
        assert!(r.is_empty());

        let r2 = GoVerRange::parse("abc");
        assert!(r2.is_empty());
    }

    #[test]
    fn test_contains_specific_range() {
        let r = GoVerRange::parse("1.2-1.5");
        assert!(r.contains(GoVer::parse("1.2.0")));
        assert!(r.contains(GoVer::parse("1.3.5")));
        assert!(r.contains(GoVer::parse("1.5.0")));
        assert!(!r.contains(GoVer::parse("1.1.0")));
        assert!(!r.contains(GoVer::parse("1.6.0")));
        assert!(!r.contains(GoVer::parse("2.0.0")));
    }

    #[test]
    fn test_contains_open_end() {
        let r = GoVerRange::parse("1.8+");
        assert!(r.contains(GoVer::parse("1.8.0")));
        assert!(r.contains(GoVer::parse("1.22.5")));
        assert!(!r.contains(GoVer::parse("1.7.0")));
    }

    #[test]
    fn test_contains_open_start() {
        let r = GoVerRange::parse("-1.20");
        assert!(r.contains(GoVer::parse("1.0.0")));
        assert!(r.contains(GoVer::parse("1.20.0")));
        assert!(!r.contains(GoVer::parse("1.21.0")));
    }

    #[test]
    fn test_all_range() {
        let r = GoVerRange::ALL;
        assert!(r.contains(GoVer::parse("1.0.0")));
        assert!(r.contains(GoVer::parse("2.0.0")));
        assert!(r.has_wildcard());
    }

    #[test]
    fn test_empty_range() {
        let r = GoVerRange::EMPTY;
        assert!(r.is_empty());
        assert!(!r.contains(GoVer::parse("1.0.0")));
    }

    #[test]
    fn test_as_list() {
        let r = GoVerRange::new(GoVer::new(1, 2, 0), GoVer::new(1, 5, 0));
        let list = r.as_list().unwrap();
        assert_eq!(list.len(), 4);
        assert_eq!(list[0], GoVer::new(1, 2, 0));
        assert_eq!(list[1], GoVer::new(1, 3, 0));
        assert_eq!(list[2], GoVer::new(1, 4, 0));
        assert_eq!(list[3], GoVer::new(1, 5, 0));
    }

    #[test]
    fn test_as_list_errors() {
        // Wildcard range
        assert!(GoVerRange::ALL.as_list().is_err());
        // Empty range
        assert!(GoVerRange::EMPTY.as_list().is_err());
        // Different major versions
        let r = GoVerRange::new(GoVer::new(1, 2, 0), GoVer::new(2, 5, 0));
        assert!(r.as_list().is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(GoVerRange::parse("1.2-1.5").to_string(), "1.2-1.5");
        assert_eq!(GoVerRange::parse("1.2+").to_string(), "1.2+");
        assert_eq!(GoVerRange::parse("-1.5").to_string(), "-1.5");
    }
}
