//! Local process pseudo-terminal session management.
//!
//! Port of Ghidra's `ghidra.pty.local` Java package.

use std::io;
use std::process::Child;
use std::time::Duration;

use crate::pty::PtySession;

/// A PTY session backed by a local child process.
///
/// Wraps a [`std::process::Child`] and implements the [`PtySession`] trait
/// for waiting on exit and forcible termination.
pub struct LocalProcessPtySession {
    child: Child,
    pty_name: String,
}

impl LocalProcessPtySession {
    /// Create a new local process PTY session.
    pub fn new(child: Child, pty_name: String) -> Self {
        log::info!("local Pty session. PID = {}", child.id());
        Self { child, pty_name }
    }
}

impl PtySession for LocalProcessPtySession {
    fn wait_exit(&mut self) -> io::Result<i32> {
        let status = self.child.wait()?;
        Ok(status.code().unwrap_or(-1))
    }

    fn wait_exit_timeout(&mut self, timeout: Duration) -> io::Result<i32> {
        // Use a polling loop since Rust's Child doesn't have a direct
        // timeout-based wait. We check every 10ms.
        let start = std::time::Instant::now();
        loop {
            match self.child.try_wait()? {
                Some(status) => return Ok(status.code().unwrap_or(-1)),
                None => {
                    if start.elapsed() >= timeout {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Timed out waiting for process exit",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn destroy_forcibly(&mut self) -> io::Result<()> {
        self.child.kill()?;
        let _ = self.child.wait(); // Reap the zombie
        Ok(())
    }

    fn description(&self) -> String {
        format!("process {} on {}", self.child.id(), self.pty_name)
    }

    fn pid(&self) -> Option<u32> {
        Some(self.child.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_process_session_description() {
        let child = std::process::Command::new("true").spawn().unwrap();
        let session = LocalProcessPtySession::new(child, "/dev/pts/0".to_string());
        assert!(session.description().contains("/dev/pts/0"));
    }

    #[test]
    fn test_local_process_session_pid() {
        let child = std::process::Command::new("true").spawn().unwrap();
        let mut session = LocalProcessPtySession::new(child, "/dev/pts/0".to_string());
        assert!(session.pid().is_some());
        assert!(session.pid().unwrap() > 0);
        // Wait for process to complete
        let _ = session.wait_exit();
    }

    #[test]
    fn test_local_process_session_wait_exit() {
        let child = std::process::Command::new("true").spawn().unwrap();
        let mut session = LocalProcessPtySession::new(child, "test".to_string());
        let exit_code = session.wait_exit().unwrap();
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_local_process_session_wait_exit_nonzero() {
        let child = std::process::Command::new("false").spawn().unwrap();
        let mut session = LocalProcessPtySession::new(child, "test".to_string());
        let exit_code = session.wait_exit().unwrap();
        assert_ne!(exit_code, 0);
    }

    #[test]
    fn test_local_process_session_destroy_forcibly() {
        let child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let mut session = LocalProcessPtySession::new(child, "test".to_string());
        session.destroy_forcibly().unwrap();
    }

    #[test]
    fn test_local_process_session_timeout() {
        let child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let mut session = LocalProcessPtySession::new(child, "test".to_string());
        let result = session.wait_exit_timeout(Duration::from_millis(50));
        assert!(result.is_err());
        // Clean up
        let _ = session.destroy_forcibly();
    }
}
