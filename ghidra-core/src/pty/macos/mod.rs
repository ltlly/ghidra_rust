//! macOS-specific pseudo-terminal support.
//!
//! Port of Ghidra's `ghidra.pty.macos` Java package.

use std::io;

use crate::pty::unix::{UnixPty, Ioctls};
use crate::pty::{Pty, PtyFactory};

/// macOS ioctl constants for `TIOCSCTTY` and `TIOCSWINSZ`.
pub struct MacosIoctls;

impl Ioctls for MacosIoctls {
    fn tiocsctty(&self) -> libc::c_ulong {
        0x20007461
    }

    fn tiocswinsz(&self) -> libc::c_ulong {
        0x80087467
    }

    fn platform_name(&self) -> &str {
        "macOS"
    }
}

/// macOS PTY factory.
///
/// Opens pseudo-terminals using `openpty` and configures them with
/// macOS-specific ioctl constants.
pub struct MacosPtyFactory;

impl PtyFactory for MacosPtyFactory {
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
        let ioctls: &'static dyn Ioctls = &MacosIoctls;
        let mut pty = UnixPty::openpty(ioctls)?;
        if cols != 0 && rows != 0 {
            pty.child().set_window_size(cols, rows);
        }
        Ok(Box::new(pty))
    }

    fn description(&self) -> &str {
        "local (macOS)"
    }
}

/// Get a reference to the macOS ioctls table.
pub fn macos_ioctls() -> &'static dyn Ioctls {
    &MacosIoctls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_ioctls() {
        let ioctls = MacosIoctls;
        assert_eq!(ioctls.tiocsctty(), 0x20007461);
        assert_eq!(ioctls.tiocswinsz(), 0x80087467);
        assert_eq!(ioctls.platform_name(), "macOS");
    }

    #[test]
    fn test_macos_factory_description() {
        let factory = MacosPtyFactory;
        assert_eq!(factory.description(), "local (macOS)");
    }
}
