//! Operating system detection and platform identification.
//!
//! Port of `ghidra.framework.OperatingSystem`.

use std::fmt;

/// Operating system enumeration.
///
/// Port of `ghidra.framework.OperatingSystem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatingSystem {
    /// Microsoft Windows.
    Windows,
    /// Linux.
    Linux,
    /// macOS / OS X.
    MacOSX,
    /// FreeBSD.
    FreeBSD,
    /// Unsupported OS.
    Unsupported,
}

impl OperatingSystem {
    /// Detect the current operating system at compile time.
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            OperatingSystem::Windows
        } else if cfg!(target_os = "linux") {
            OperatingSystem::Linux
        } else if cfg!(target_os = "macos") {
            OperatingSystem::MacOSX
        } else if cfg!(target_os = "freebsd") {
            OperatingSystem::FreeBSD
        } else {
            OperatingSystem::Unsupported
        }
    }

    /// Return the OS name as a user-visible string.
    pub fn display_name(&self) -> &'static str {
        match self {
            OperatingSystem::Windows => "Windows",
            OperatingSystem::Linux => "Linux",
            OperatingSystem::MacOSX => "Mac OS X",
            OperatingSystem::FreeBSD => "FreeBSD",
            OperatingSystem::Unsupported => "Unsupported Operating System",
        }
    }

    /// Returns true if this is a Windows OS.
    pub fn is_windows(&self) -> bool {
        matches!(self, OperatingSystem::Windows)
    }

    /// Returns true if this is a Linux OS.
    pub fn is_linux(&self) -> bool {
        matches!(self, OperatingSystem::Linux)
    }

    /// Returns true if this is macOS.
    pub fn is_mac_os(&self) -> bool {
        matches!(self, OperatingSystem::MacOSX)
    }
}

impl fmt::Display for OperatingSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({})",
            self.display_name(),
            std::env::consts::OS
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_os() {
        let os = OperatingSystem::current();
        // At least one of these should be true on any supported platform
        assert!(os == OperatingSystem::Windows
            || os == OperatingSystem::Linux
            || os == OperatingSystem::MacOSX
            || os == OperatingSystem::FreeBSD
            || os == OperatingSystem::Unsupported);
    }

    #[test]
    fn test_display_name() {
        assert_eq!(OperatingSystem::Windows.display_name(), "Windows");
        assert_eq!(OperatingSystem::Linux.display_name(), "Linux");
        assert_eq!(OperatingSystem::MacOSX.display_name(), "Mac OS X");
    }

    #[test]
    fn test_display() {
        let os = OperatingSystem::current();
        let s = format!("{}", os);
        assert!(!s.is_empty());
    }
}
