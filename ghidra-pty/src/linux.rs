//! Linux pseudo-terminal implementation.
//!
//! Ported from `ghidra.pty.linux.*`.

use std::io;

use crate::pty::Pty;
use crate::pty_factory::PtyFactory;
use crate::pty_session::PtySession;
use crate::unix::UnixPty;

/// Linux-specific ioctl constants for pseudo-terminal operations.
pub struct LinuxIoctls;

impl LinuxIoctls {
    /// `TIOCSCTTY` - set the controlling terminal.
    pub const TIOCSCTTY: libc::c_ulong = 0x540E;
    /// `TIOCSWINSZ` - set the window size.
    pub const TIOCSWINSZ: libc::c_ulong = 0x5414;
}

/// A Linux pseudo-terminal factory.
///
/// Uses POSIX `openpty()` via the [`UnixPty`] implementation.
pub struct LinuxPtyFactory;

impl PtyFactory for LinuxPtyFactory {
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
        let mut pty = UnixPty::open()?;

        // Set the window size if non-zero dimensions are requested
        if cols > 0 && rows > 0 {
            let ws = libc::winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let ret = unsafe {
                libc::ioctl(
                    pty.master_fd.as_raw_fd(),
                    LinuxIoctls::TIOCSWINSZ,
                    &ws as *const libc::winsize,
                )
            };
            if ret != 0 {
                log::warn!("Failed to set window size: {}", io::Error::last_os_error());
            }
        }

        Ok(Box::new(pty))
    }

    fn description(&self) -> &str {
        "Linux PtyFactory (openpty)"
    }
}

/// A Linux-specific pty session leader.
pub struct LinuxPtySessionLeader {
    /// The child process.
    child: std::process::Child,
}

impl LinuxPtySessionLeader {
    /// Create a new session leader from a child process.
    pub fn new(child: std::process::Child) -> Self {
        Self { child }
    }
}

impl PtySession for LinuxPtySessionLeader {
    fn wait_exit(&mut self) -> io::Result<i32> {
        let status = self.child.wait()?;
        Ok(status.code().unwrap_or(-1))
    }

    fn wait_exit_timeout(&mut self, timeout: std::time::Duration) -> io::Result<i32> {
        let start = std::time::Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Ok(status.code().unwrap_or(-1)),
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Process did not exit within timeout",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn destroy_forcibly(&mut self) -> io::Result<()> {
        self.child.kill()?;
        let _ = self.child.wait();
        Ok(())
    }

    fn description(&self) -> String {
        format!("LinuxPtySessionLeader(pid={})", self.child.id())
    }
}

use std::os::unix::io::AsRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_factory_description() {
        let factory = LinuxPtyFactory;
        assert_eq!(factory.description(), "Linux PtyFactory (openpty)");
    }

    #[test]
    fn test_linux_session_leader() {
        let child = std::process::Command::new("true").spawn().unwrap();
        let mut session = LinuxPtySessionLeader::new(child);
        assert!(session.description().contains("LinuxPtySessionLeader"));
        let code = session.wait_exit().unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_linux_ioctls() {
        assert_eq!(LinuxIoctls::TIOCSCTTY, 0x540E);
        assert_eq!(LinuxIoctls::TIOCSWINSZ, 0x5414);
    }
}
