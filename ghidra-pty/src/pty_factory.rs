//! `PtyFactory` -- trait for opening pseudo-terminals.
//!
//! Ported from `ghidra.pty.PtyFactory`.

use std::io;

use crate::pty::Pty;

/// Default terminal width in columns.
pub const DEFAULT_COLS: u16 = 80;

/// Default terminal height in rows.
pub const DEFAULT_ROWS: u16 = 25;

/// A mechanism for opening pseudo-terminals.
///
/// Platform-specific implementations provide the actual pty creation
/// (e.g., `openpty()` on Unix, ConPTY on Windows).
pub trait PtyFactory {
    /// Open a new pseudo-terminal with the given dimensions.
    ///
    /// If `cols` or `rows` is 0, the system decides the dimension.
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>>;

    /// Open a new pseudo-terminal with default dimensions
    /// ({@value DEFAULT_COLS} x {@value DEFAULT_ROWS}).
    fn openpty_default(&self) -> io::Result<Box<dyn Pty>> {
        self.openpty(DEFAULT_COLS, DEFAULT_ROWS)
    }

    /// Get a human-readable description of the factory.
    fn description(&self) -> &str;
}

/// Create a platform-appropriate pty factory for the local machine.
///
/// Returns the appropriate factory for Linux, macOS, or Windows.
pub fn local_factory() -> io::Result<Box<dyn PtyFactory>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(crate::linux::LinuxPtyFactory))
    }

    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(crate::macos::MacosPtyFactory))
    }

    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(crate::windows::ConPtyFactory))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Pty not supported on this platform",
        ))
    }
}

/// A mock pty factory for testing.
pub struct MockPtyFactory;

impl PtyFactory for MockPtyFactory {
    fn openpty(&self, _cols: u16, _rows: u16) -> io::Result<Box<dyn Pty>> {
        Ok(Box::new(crate::pty::MemoryPty::new()))
    }

    fn description(&self) -> &str {
        "MockPtyFactory (testing)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_dimensions() {
        assert_eq!(DEFAULT_COLS, 80);
        assert_eq!(DEFAULT_ROWS, 25);
    }

    #[test]
    fn test_mock_factory() {
        let factory = MockPtyFactory;
        let pty = factory.openpty_default().unwrap();
        assert!(pty.is_open());
        assert_eq!(factory.description(), "MockPtyFactory (testing)");
    }

    #[test]
    fn test_mock_factory_custom_size() {
        let factory = MockPtyFactory;
        let pty = factory.openpty(120, 40).unwrap();
        assert!(pty.is_open());
    }
}
