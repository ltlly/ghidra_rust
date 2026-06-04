//! Java version parsing and comparison.
//!
//! Port of `ghidra.launch.JavaVersion`.

use std::cmp::Ordering;
use std::fmt;

/// Parsed Java version with major, minor, patch, and architecture.
///
/// Note: comparison (via `Ord`) ignores the architecture field,
/// matching the Java source behavior where `compareTo` disregards arch.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct JavaVersion {
    major: u32,
    minor: u32,
    patch: u32,
    arch: u32,
}

/// Error type for version parsing failures.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ParseVersionError(pub String);

impl JavaVersion {
    /// Creates a new `JavaVersion` from version and architecture strings.
    ///
    /// Handles both old-style `1.major.minor` and new-style `major.minor.patch` formats.
    /// Strips surrounding quotes and trailing dash sections (e.g., `9-Ubuntu`).
    pub fn new(version: &str, architecture: &str) -> Result<Self, ParseVersionError> {
        let major;
        let minor;
        let patch;

        let version = version.trim();
        if version.is_empty() {
            return Err(ParseVersionError("Version is empty".to_string()));
        }

        // Remove surrounding quotes
        let version = if version.starts_with('"') && version.ends_with('"') {
            &version[1..version.len() - 1]
        } else {
            version
        };

        // Remove trailing dash section
        let version = match version.find('-') {
            Some(idx) if idx > 0 => &version[..idx],
            _ => version,
        };

        let parts: Vec<&str> = version.split(&['.', '_'][..]).collect();
        if parts.is_empty() {
            return Err(ParseVersionError("Failed to parse version".to_string()));
        }

        let first = parse_part(parts[0], "first value")?;

        if first == 1 {
            // Old format: 1.major.minor_patch
            major = if parts.len() > 1 {
                parse_part(parts[1], "major")?
            } else {
                0
            };
            minor = if parts.len() > 2 {
                parse_part(parts[2], "minor")?
            } else {
                0
            };
            patch = if parts.len() > 3 {
                parse_part(parts[3], "patch")?
            } else {
                0
            };
        } else if first >= 9 {
            // New format: major.minor.patch
            major = first;
            minor = if parts.len() > 1 {
                parse_part(parts[1], "minor")?
            } else {
                0
            };
            patch = if parts.len() > 2 {
                parse_part(parts[2], "patch")?
            } else {
                0
            };
        } else {
            return Err(ParseVersionError(format!(
                "Failed to parse version: {version}"
            )));
        }

        let arch = parse_part(architecture, "architecture")?;

        Ok(Self {
            major,
            minor,
            patch,
            arch,
        })
    }

    /// Gets the major version.
    pub fn major(&self) -> u32 {
        self.major
    }

    /// Gets the minor version.
    pub fn minor(&self) -> u32 {
        self.minor
    }

    /// Gets the patch version.
    pub fn patch(&self) -> u32 {
        self.patch
    }

    /// Gets the architecture (e.g., 32 or 64).
    pub fn architecture(&self) -> u32 {
        self.arch
    }
}

impl fmt::Display for JavaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.major < 9 {
            write!(
                f,
                "1.{}.{}_{} ({}-bit)",
                self.major, self.minor, self.patch, self.arch
            )
        } else {
            write!(
                f,
                "{}.{}.{} ({}-bit)",
                self.major, self.minor, self.patch, self.arch
            )
        }
    }
}

/// Comparison ignores architecture, matching the Java source.
impl PartialOrd for JavaVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JavaVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

fn parse_part(s: &str, name: &str) -> Result<u32, ParseVersionError> {
    let val: u32 = s.parse().map_err(|_| {
        ParseVersionError(format!(
            "Failed to convert {name} version to integer: {s}"
        ))
    })?;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_format() {
        let v = JavaVersion::new("17.0.1", "64").unwrap();
        assert_eq!(v.major(), 17);
        assert_eq!(v.minor(), 0);
        assert_eq!(v.patch(), 1);
        assert_eq!(v.architecture(), 64);
    }

    #[test]
    fn test_old_format() {
        let v = JavaVersion::new("1.8.0_312", "64").unwrap();
        assert_eq!(v.major(), 8);
        assert_eq!(v.minor(), 0);
        assert_eq!(v.patch(), 312);
        assert_eq!(v.architecture(), 64);
    }

    #[test]
    fn test_major_only() {
        let v = JavaVersion::new("11", "64").unwrap();
        assert_eq!(v.major(), 11);
        assert_eq!(v.minor(), 0);
        assert_eq!(v.patch(), 0);
    }

    #[test]
    fn test_dash_stripped() {
        let v = JavaVersion::new("9-Ubuntu", "64").unwrap();
        assert_eq!(v.major(), 9);
    }

    #[test]
    fn test_quoted() {
        let v = JavaVersion::new("\"17.0.1\"", "64").unwrap();
        assert_eq!(v.major(), 17);
    }

    #[test]
    fn test_display_new() {
        let v = JavaVersion::new("17.0.1", "64").unwrap();
        assert_eq!(v.to_string(), "17.0.1 (64-bit)");
    }

    #[test]
    fn test_display_old() {
        let v = JavaVersion::new("1.8.0_312", "64").unwrap();
        assert_eq!(v.to_string(), "1.8.0_312 (64-bit)");
    }

    #[test]
    fn test_ordering() {
        let v17 = JavaVersion::new("17.0.0", "64").unwrap();
        let v11 = JavaVersion::new("11.0.0", "64").unwrap();
        let v8 = JavaVersion::new("1.8.0", "64").unwrap();
        assert!(v8 < v11);
        assert!(v11 < v17);
    }

    #[test]
    fn test_ordering_ignores_arch() {
        let a = JavaVersion::new("17.0.0", "64").unwrap();
        let b = JavaVersion::new("17.0.0", "32").unwrap();
        assert_eq!(a.cmp(&b), Ordering::Equal);
        // But they are not equal (arch differs)
        assert_ne!(a, b);
    }

    #[test]
    fn test_invalid_version() {
        assert!(JavaVersion::new("abc", "64").is_err());
    }

    #[test]
    fn test_invalid_arch() {
        assert!(JavaVersion::new("17.0.0", "abc").is_err());
    }

    #[test]
    fn test_empty_version() {
        assert!(JavaVersion::new("", "64").is_err());
    }
}
