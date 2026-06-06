//! `PtySession` -- handle to a session leader process.
//!
//! Ported from `ghidra.pty.PtySession`.

use std::io;
use std::process::Child;
use std::time::Duration;

/// A session led by the child pty.
///
/// This is typically a handle to the (local or remote) process designated
/// as the "session leader".
pub trait PtySession: Send {
    /// Wait for the session leader to exit, returning its exit status code.
    fn wait_exit(&mut self) -> io::Result<i32>;

    /// Wait for the session leader to exit with a timeout.
    fn wait_exit_timeout(&mut self, timeout: Duration) -> io::Result<i32>;

    /// Forcefully terminate the session (leader and descendants).
    fn destroy_forcibly(&mut self) -> io::Result<()>;

    /// Returns a human-readable description of the session.
    fn description(&self) -> String;
}

/// A local process-based pty session.
///
/// Wraps a `std::process::Child` as a `PtySession`.
pub struct LocalProcessPtySession {
    /// The child process.
    pub child: Child,
    /// A description of the session.
    pub desc: String,
}

impl LocalProcessPtySession {
    /// Create a new local process session.
    pub fn new(child: Child) -> Self {
        let desc = format!("LocalProcess(pid={})", child.id());
        Self { child, desc }
    }

    /// Returns the process ID.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl PtySession for LocalProcessPtySession {
    fn wait_exit(&mut self) -> io::Result<i32> {
        let status = self.child.wait()?;
        Ok(status.code().unwrap_or(-1))
    }

    fn wait_exit_timeout(&mut self, timeout: Duration) -> io::Result<i32> {
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
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn destroy_forcibly(&mut self) -> io::Result<()> {
        self.child.kill()?;
        let _ = self.child.wait(); // reap the process
        Ok(())
    }

    fn description(&self) -> String {
        self.desc.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_process_session_description() {
        // Create a real child process for testing
        let child = std::process::Command::new("true").spawn().unwrap();
        let mut session = LocalProcessPtySession::new(child);
        assert!(session.description().contains("LocalProcess"));
        let code = session.wait_exit().unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_local_process_session_destroy() {
        let child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let mut session = LocalProcessPtySession::new(child);
        session.destroy_forcibly().unwrap();
    }
}
