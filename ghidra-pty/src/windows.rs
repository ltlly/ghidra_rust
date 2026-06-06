//! Windows ConPTY pseudo-terminal implementation.
//!
//! Ported from `ghidra.pty.windows.*`. Uses the Windows ConPTY API
//! (`CreatePseudoConsole`, `ClosePseudoConsole`).
//!
//! Note: This module is only compiled on Windows targets.

use std::io;

use crate::pty::Pty;
use crate::pty_factory::PtyFactory;
use crate::pty_session::PtySession;

/// A ConPTY-based pseudo-terminal for Windows.
pub struct ConPty {
    /// The pseudo-console handle.
    handle: isize,
    parent_read: Option<Box<dyn std::io::Read + Send>>,
    parent_write: Option<Box<dyn std::io::Write + Send>>,
    open: bool,
}

impl ConPty {
    /// Create a new ConPTY (stub for non-Windows platforms).
    ///
    /// On non-Windows, this always returns an error.
    #[cfg(not(windows))]
    pub fn new(_cols: u16, _rows: u16) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ConPTY is only available on Windows",
        ))
    }

    /// Create a new ConPTY.
    #[cfg(windows)]
    pub fn new(cols: u16, rows: u16) -> io::Result<Self> {
        // ConPTY implementation would go here on Windows
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ConPTY not yet implemented",
        ))
    }
}

impl Pty for ConPty {
    fn get_parent(&self) -> &crate::pty_parent::PtyParent {
        unimplemented!("ConPTY not available on this platform")
    }

    fn get_child(&self) -> &crate::pty_child::PtyChild {
        unimplemented!("ConPTY not available on this platform")
    }

    fn get_parent_mut(&mut self) -> &mut crate::pty_parent::PtyParent {
        unimplemented!("ConPTY not available on this platform")
    }

    fn get_child_mut(&mut self) -> &mut crate::pty_child::PtyChild {
        unimplemented!("ConPTY not available on this platform")
    }

    fn close(&mut self) -> io::Result<()> {
        self.open = false;
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.open
    }
}

/// Windows ConPTY factory.
pub struct ConPtyFactory;

impl PtyFactory for ConPtyFactory {
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
        Ok(Box::new(ConPty::new(cols, rows)?))
    }

    fn description(&self) -> &str {
        "Windows ConPTY Factory"
    }
}

/// Windows ConPTY session.
pub struct ConPtySession {
    child: std::process::Child,
}

impl ConPtySession {
    /// Create a new ConPTY session.
    pub fn new(child: std::process::Child) -> Self {
        Self { child }
    }
}

impl PtySession for ConPtySession {
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
        format!("ConPtySession(pid={})", self.child.id())
    }
}

/// Stub for pipe operations (Windows named pipes).
pub struct Pipe;

impl Pipe {
    /// Create a new named pipe pair (stub).
    pub fn new() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Pipe not available on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_con_pty_factory_description() {
        let factory = ConPtyFactory;
        assert_eq!(factory.description(), "Windows ConPTY Factory");
    }

    #[test]
    fn test_con_pty_unsupported() {
        let result = ConPty::new(80, 25);
        assert!(result.is_err());
    }
}
