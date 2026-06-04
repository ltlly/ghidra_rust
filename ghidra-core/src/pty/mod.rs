//! Pseudo-terminal (PTY) framework.
//!
//! Port of Ghidra's `ghidra.pty` Java package. Provides a cross-platform
//! abstraction for opening pseudo-terminals, spawning sessions, and
//! communicating with child processes through the terminal's line discipline.
//!
//! # Architecture
//!
//! The core traits mirror the Java interfaces:
//!
//! - [`Pty`] -- a handle to both ends of a pseudo-terminal
//! - [`PtyEndpoint`] -- one end (parent or child) with input/output streams
//! - [`PtyParent`] / [`PtyChild`] -- typed markers for each end
//! - [`PtyFactory`] -- creates new pseudo-terminals
//! - [`PtySession`] -- handle to the spawned session leader
//!
//! Platform implementations live in sub-modules:
//! - [`unix`] -- POSIX (Linux/macOS/BSD) via `openpty` and `fork`/`exec`
//! - [`linux`] -- Linux-specific ioctl constants
//! - [`macos`] -- macOS-specific ioctl constants
//! - [`windows`] -- Windows ConPTY
//! - [`local`] -- local process session management
//!
//! # Example
//!
//! ```no_run
//! use ghidra_core::pty::{local_pty_factory, PtySession};
//!
//! let factory = local_pty_factory();
//! let pty = factory.openpty_default().unwrap();
//! let mut session = pty.child().session(
//!     &["/bin/bash"], &[], None, &[]
//! ).unwrap();
//! let exit_code = session.wait_exit().unwrap();
//! ```

pub mod linux;
pub mod local;
pub mod macos;
pub mod shell_utils;
pub mod unix;
pub mod windows;

use std::io::{self, Read, Write};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Core traits
// ---------------------------------------------------------------------------

/// One end of a pseudo-terminal.
///
/// Writes to the output stream arrive on the input stream of the opposite
/// end, subject to the terminal's line discipline.
pub trait PtyEndpoint {
    /// Get a boxed writer for this end of the pty.
    fn output_stream(&mut self) -> Box<dyn Write>;

    /// Get a boxed reader for this end of the pty.
    fn input_stream(&mut self) -> Box<dyn Read>;
}

/// The parent (UNIX "master") end of a pseudo-terminal.
pub trait PtyParent: PtyEndpoint {}

/// The child (UNIX "slave") end of a pseudo-terminal.
pub trait PtyChild: PtyEndpoint {
    /// Spawn a subprocess in a new session whose controlling tty is this pty.
    ///
    /// # Arguments
    /// * `args` -- image path and arguments
    /// * `env` -- environment variables as `(key, value)` pairs
    /// * `working_directory` -- optional working directory
    /// * `mode` -- terminal mode flags
    fn session(
        &self,
        args: &[&str],
        env: &[(&str, &str)],
        working_directory: Option<&std::path::Path>,
        mode: &[TermMode],
    ) -> io::Result<Box<dyn PtySession>>;

    /// Start a session without a real leader, returning the pty device name.
    fn null_session(&self, mode: &[TermMode]) -> io::Result<String>;

    /// Resize the terminal window.
    fn set_window_size(&self, cols: u16, rows: u16);
}

/// A pseudo-terminal handle with access to both ends.
pub trait Pty {
    /// Get the parent end.
    fn parent(&mut self) -> &mut dyn PtyParent;

    /// Get the child end.
    fn child(&mut self) -> &mut dyn PtyChild;

    /// Close both ends of the pty.
    fn close(&mut self) -> io::Result<()>;
}

/// A mechanism for opening pseudo-terminals.
pub trait PtyFactory {
    /// Open a new pseudo-terminal with the given dimensions.
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>>;

    /// Open a new pseudo-terminal with default dimensions (80x25).
    fn openpty_default(&self) -> io::Result<Box<dyn Pty>> {
        self.openpty(DEFAULT_COLS, DEFAULT_ROWS)
    }

    /// Human-readable description of this factory.
    fn description(&self) -> &str;
}

/// Choose a PTY factory for the current operating system.
///
/// Returns a platform-appropriate factory: Linux PTY, macOS PTY, or
/// Windows ConPTY.
pub fn local_pty_factory() -> Box<dyn PtyFactory> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPtyFactory)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosPtyFactory)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::ConPtyFactory)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        compile_error!("Unsupported platform for local_pty_factory()")
    }
}

/// Default terminal width in columns.
pub const DEFAULT_COLS: u16 = 80;
/// Default terminal height in rows.
pub const DEFAULT_ROWS: u16 = 25;

/// A session led by the child pty (typically a spawned process).
pub trait PtySession {
    /// Wait for the session leader to exit, returning its exit status code.
    fn wait_exit(&mut self) -> io::Result<i32>;

    /// Wait for the session leader to exit with a timeout.
    fn wait_exit_timeout(&mut self, timeout: Duration) -> io::Result<i32>;

    /// Forcibly terminate the session (leader and descendants).
    fn destroy_forcibly(&mut self) -> io::Result<()>;

    /// Human-readable description of this session.
    fn description(&self) -> String;

    /// The process ID of the session leader, if available.
    fn pid(&self) -> Option<u32>;
}

/// Terminal mode flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermMode {
    /// Input is echoed to output by the terminal itself.
    EchoOn,
    /// No local echo.
    EchoOff,
}

// ---------------------------------------------------------------------------
// Convenience extension
// ---------------------------------------------------------------------------

/// Extension methods for [`PtyFactory`].
pub trait PtyFactoryExt: PtyFactory {
    /// Open a pty and spawn a session in one call.
    fn open_session(
        &self,
        args: &[&str],
        env: &[(&str, &str)],
        working_directory: Option<&std::path::Path>,
        cols: u16,
        rows: u16,
    ) -> io::Result<(Box<dyn Pty>, Box<dyn PtySession>)> {
        let mut pty = self.openpty(cols, rows)?;
        let session = pty.child().session(args, env, working_directory, &[])?;
        Ok((pty, session))
    }
}

impl<T: PtyFactory + ?Sized> PtyFactoryExt for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_dimensions() {
        assert_eq!(DEFAULT_COLS, 80);
        assert_eq!(DEFAULT_ROWS, 25);
    }

    #[test]
    fn test_term_mode_variants() {
        let on = TermMode::EchoOn;
        let off = TermMode::EchoOff;
        assert_ne!(on, off);
        assert_eq!(on, TermMode::EchoOn);
    }

    #[test]
    fn test_factory_local_returns_factory() {
        let factory = local_pty_factory();
        assert!(!factory.description().is_empty());
    }
}
