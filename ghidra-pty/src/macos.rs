//! macOS pseudo-terminal implementation.
//!
//! Ported from `ghidra.pty.macos.*`.

use std::io;

use crate::pty::Pty;
use crate::pty_factory::PtyFactory;
use crate::pty_session::PtySession;
use crate::unix::UnixPty;

/// macOS-specific ioctl constants.
pub struct MacosIoctls;

impl MacosIoctls {
    /// `TIOCSCTTY` - set the controlling terminal.
    pub const TIOCSCTTY: libc::c_ulong = 0x20007461;
    /// `TIOCSWINSZ` - set the window size.
    pub const TIOCSWINSZ: libc::c_ulong = 0x80087467;
}

/// A macOS pseudo-terminal factory.
///
/// Uses POSIX `openpty()` via the [`UnixPty`] implementation.
pub struct MacosPtyFactory;

impl PtyFactory for MacosPtyFactory {
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
        let mut pty = UnixPty::open()?;

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
                    MacosIoctls::TIOCSWINSZ,
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
        "macOS PtyFactory (openpty)"
    }
}

/// A macOS-specific pty session leader.
pub struct MacosPtySessionLeader {
    child: std::process::Child,
}

impl MacosPtySessionLeader {
    /// Create a new session leader from a child process.
    pub fn new(child: std::process::Child) -> Self {
        Self { child }
    }
}

impl PtySession for MacosPtySessionLeader {
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
        format!("MacosPtySessionLeader(pid={})", self.child.id())
    }
}

use std::os::unix::io::AsRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_factory_description() {
        let factory = MacosPtyFactory;
        assert_eq!(factory.description(), "macOS PtyFactory (openpty)");
    }

    #[test]
    fn test_macos_ioctls() {
        assert_eq!(MacosIoctls::TIOCSCTTY, 0x20007461);
        assert_eq!(MacosIoctls::TIOCSWINSZ, 0x80087467);
    }
}
