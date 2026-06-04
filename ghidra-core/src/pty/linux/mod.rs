//! Linux-specific pseudo-terminal support.
//!
//! Port of Ghidra's `ghidra.pty.linux` Java package.

use std::io;

use crate::pty::unix::{UnixPty, Ioctls};
use crate::pty::{Pty, PtyFactory};

/// Linux ioctl constants for `TIOCSCTTY` and `TIOCSWINSZ`.
pub struct LinuxIoctls;

impl Ioctls for LinuxIoctls {
    fn tiocsctty(&self) -> libc::c_ulong {
        0x540e
    }

    fn tiocswinsz(&self) -> libc::c_ulong {
        0x5414
    }

    fn platform_name(&self) -> &str {
        "Linux"
    }
}

/// Linux PTY factory.
///
/// Opens pseudo-terminals using `openpty` and configures them with
/// Linux-specific ioctl constants.
pub struct LinuxPtyFactory;

impl PtyFactory for LinuxPtyFactory {
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
        let ioctls: &'static dyn Ioctls = &LinuxIoctls;
        let mut pty = UnixPty::openpty(ioctls)?;
        if cols != 0 && rows != 0 {
            pty.child().set_window_size(cols, rows);
        }
        Ok(Box::new(pty))
    }

    fn description(&self) -> &str {
        "local (Linux)"
    }
}

/// Get a reference to the Linux ioctls table.
pub fn linux_ioctls() -> &'static dyn Ioctls {
    &LinuxIoctls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_ioctls() {
        let ioctls = LinuxIoctls;
        assert_eq!(ioctls.tiocsctty(), 0x540e);
        assert_eq!(ioctls.tiocswinsz(), 0x5414);
        assert_eq!(ioctls.platform_name(), "Linux");
    }

    #[test]
    fn test_linux_factory_description() {
        let factory = LinuxPtyFactory;
        assert_eq!(factory.description(), "local (Linux)");
    }

    #[test]
    fn test_linux_factory_openpty() {
        let factory = LinuxPtyFactory;
        // This may fail in environments without terminal support
        match factory.openpty(80, 25) {
            Ok(mut pty) => {
                let _ = pty.close();
            }
            Err(_) => {
                // OK in CI environments
            }
        }
    }

    #[test]
    fn test_linux_factory_openpty_default() {
        let factory = LinuxPtyFactory;
        match factory.openpty_default() {
            Ok(mut pty) => {
                let _ = pty.close();
            }
            Err(_) => {
                // OK in CI environments
            }
        }
    }
}
