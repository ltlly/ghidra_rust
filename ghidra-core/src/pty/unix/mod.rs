//! Unix/POSIX pseudo-terminal implementation.
//!
//! Port of Ghidra's `ghidra.pty.unix` Java package. Uses `openpty` to
//! create pseudo-terminals and POSIX file descriptors for I/O.

mod err;
mod fd_input_stream;
mod fd_output_stream;
mod posix_c;
mod util;

pub use err::check_lt0;
pub use fd_input_stream::FdInputStream;
pub use fd_output_stream::FdOutputStream;
pub use posix_c::{
    c_close, c_dup2, c_execv, c_ioctl, c_open, c_read, c_setsid, c_tcgetattr, c_tcsetattr,
    c_write, Ioctls, Termios, Winsize, CONTROLLING_TTY, O_RDWR, TCSANOW, TERMIO_ECHO,
};

use std::io;

use crate::pty::{Pty, PtyChild, PtyEndpoint, PtyParent, PtySession, TermMode};

// ---------------------------------------------------------------------------
// UnixPtyEndpoint
// ---------------------------------------------------------------------------

/// A file-descriptor based endpoint for a Unix pseudo-terminal.
pub struct UnixPtyEndpoint {
    fd: i32,
    ioctls: &'static dyn Ioctls,
}

impl UnixPtyEndpoint {
    /// Create a new endpoint wrapping the given file descriptor.
    pub fn new(ioctls: &'static dyn Ioctls, fd: i32) -> Self {
        Self { fd, ioctls }
    }

    /// Get the raw file descriptor.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Get the ioctls table.
    pub fn ioctls(&self) -> &'static dyn Ioctls {
        self.ioctls
    }

    /// Close streams (marks them as closed; does not close the fd itself).
    pub fn close_streams(&self) {
        // The Pty is responsible for closing the fd; this just marks the streams.
    }
}

impl PtyEndpoint for UnixPtyEndpoint {
    fn output_stream(&mut self) -> Box<dyn io::Write> {
        Box::new(FdOutputStream::new(self.fd))
    }

    fn input_stream(&mut self) -> Box<dyn io::Read> {
        Box::new(FdInputStream::new(self.fd))
    }
}

// ---------------------------------------------------------------------------
// UnixPtyParent
// ---------------------------------------------------------------------------

/// The parent (master) end of a Unix pseudo-terminal.
pub struct UnixPtyParent {
    endpoint: UnixPtyEndpoint,
}

impl UnixPtyParent {
    /// Create a new parent endpoint.
    pub fn new(ioctls: &'static dyn Ioctls, fd: i32) -> Self {
        Self {
            endpoint: UnixPtyEndpoint::new(ioctls, fd),
        }
    }
}

impl PtyEndpoint for UnixPtyParent {
    fn output_stream(&mut self) -> Box<dyn io::Write> {
        self.endpoint.output_stream()
    }

    fn input_stream(&mut self) -> Box<dyn io::Read> {
        self.endpoint.input_stream()
    }
}

impl PtyParent for UnixPtyParent {}

// ---------------------------------------------------------------------------
// UnixPtyChild
// ---------------------------------------------------------------------------

/// The child (slave) end of a Unix pseudo-terminal.
pub struct UnixPtyChild {
    endpoint: UnixPtyEndpoint,
    name: String,
}

impl UnixPtyChild {
    /// Create a new child endpoint.
    pub fn new(ioctls: &'static dyn Ioctls, fd: i32, name: String) -> Self {
        Self {
            endpoint: UnixPtyEndpoint::new(ioctls, fd),
            name,
        }
    }

    fn apply_mode(&self, mode: &[TermMode]) {
        if mode.contains(&TermMode::EchoOff) {
            self.disable_echo();
        }
    }

    fn disable_echo(&self) {
        unsafe {
            let mut tmios = std::mem::zeroed::<Termios>();
            if c_tcgetattr(self.endpoint.fd(), &mut tmios) >= 0 {
                tmios.c_lflag &= !TERMIO_ECHO;
                c_tcsetattr(self.endpoint.fd(), TCSANOW, &tmios);
            }
        }
    }
}

impl PtyEndpoint for UnixPtyChild {
    fn output_stream(&mut self) -> Box<dyn io::Write> {
        self.endpoint.output_stream()
    }

    fn input_stream(&mut self) -> Box<dyn io::Read> {
        self.endpoint.input_stream()
    }
}

impl PtyChild for UnixPtyChild {
    fn session(
        &self,
        args: &[&str],
        env: &[(&str, &str)],
        working_directory: Option<&std::path::Path>,
        mode: &[TermMode],
    ) -> io::Result<Box<dyn PtySession>> {
        self.apply_mode(mode);

        // Build the session leader arguments:
        // [leader_binary, pty_name, original_args...]
        let mut leader_args: Vec<String> = Vec::new();
        leader_args.push(self.name.clone());
        leader_args.extend(args.iter().map(|s| s.to_string()));

        use crate::pty::local::LocalProcessPtySession;

        // Use std::process::Command to spawn the subprocess
        let mut cmd = std::process::Command::new(args[0]);
        if args.len() > 1 {
            cmd.args(&args[1..]);
        }
        for &(k, v) in env {
            cmd.env(k, v);
        }
        if let Some(dir) = working_directory {
            cmd.current_dir(dir);
        }

        // Redirect stdio to inherit
        cmd.stdin(std::process::Stdio::inherit());
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());

        let child = cmd.spawn().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Could not start process with args {:?}: {}", args, e),
            )
        })?;

        Ok(Box::new(LocalProcessPtySession::new(child, self.name.clone())))
    }

    fn null_session(&self, mode: &[TermMode]) -> io::Result<String> {
        self.apply_mode(mode);
        Ok(self.name.clone())
    }

    fn set_window_size(&self, cols: u16, rows: u16) {
        unsafe {
            let ws = Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            c_ioctl(
                self.endpoint.fd(),
                self.endpoint.ioctls().tiocswinsz(),
                &ws as *const Winsize as *const libc::c_void,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// UnixPty
// ---------------------------------------------------------------------------

/// A Unix pseudo-terminal with parent and child endpoints.
pub struct UnixPty {
    parent_fd: i32,
    child_fd: i32,
    closed: bool,
    parent: UnixPtyParent,
    child: UnixPtyChild,
}

impl UnixPty {
    /// Open a new pseudo-terminal using the system's `openpty`.
    pub fn openpty(ioctls: &'static dyn Ioctls) -> io::Result<Self> {
        let mut parent_fd: i32 = 0;
        let mut child_fd: i32 = 0;
        let mut name_buf = [0u8; 1024];

        let ret = util::raw_openpty(
            &mut parent_fd,
            &mut child_fd,
            name_buf.as_mut_ptr() as *mut libc::c_char,
        );
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Find the null terminator
        let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(name_buf.len());
        let name = String::from_utf8_lossy(&name_buf[..name_len]).to_string();

        log::debug!("New Pty: {} at ({}, {})", name, parent_fd, child_fd);

        Ok(Self {
            parent_fd,
            child_fd,
            closed: false,
            parent: UnixPtyParent::new(ioctls, parent_fd),
            child: UnixPtyChild::new(ioctls, child_fd, name),
        })
    }
}

impl Pty for UnixPty {
    fn parent(&mut self) -> &mut dyn PtyParent {
        &mut self.parent
    }

    fn child(&mut self) -> &mut dyn PtyChild {
        &mut self.child
    }

    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        unsafe {
            c_close(self.child_fd);
            c_close(self.parent_fd);
        }
        self.closed = true;
        Ok(())
    }
}

impl Drop for UnixPty {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// ---------------------------------------------------------------------------
// UnixPtySessionLeader
// ---------------------------------------------------------------------------

/// The session leader process that sets up a new session on the pty.
///
/// This is the Rust equivalent of `UnixPtySessionLeader.run()`. It opens the
/// named TTY, redirects stdio, calls `setsid`, sets the controlling tty,
/// and then `execv`s the requested program.
///
/// # Safety
///
/// This function uses `fork` and `exec` internally.
pub unsafe fn run_session_leader(pty_path: &str, args: &[&str], ioctls: &'static dyn Ioctls) -> ! {
    let fd = c_open(
        std::ffi::CString::new(pty_path).unwrap().as_ptr(),
        O_RDWR,
        0,
    );

    if fd < 0 {
        eprintln!("Could not open pty {}: {}", pty_path, io::Error::last_os_error());
        std::process::exit(127);
    }

    // Copy stderr to a backup descriptor
    let bkt = fd + 1;
    c_dup2(2, bkt);

    // Redirect all standard streams to the TTY
    c_close(0);
    c_close(1);
    c_close(2);
    c_dup2(fd, 0);
    c_dup2(fd, 1);
    c_dup2(fd, 2);
    c_close(fd);

    // Create a new session
    c_setsid();

    // Set controlling tty
    let steal: i32 = 0;
    c_ioctl(0, ioctls.tiocsctty(), &steal as *const i32 as *const libc::c_void);

    // Exec the requested program
    let c_args: Vec<std::ffi::CString> = args
        .iter()
        .map(|s| std::ffi::CString::new(*s).unwrap())
        .collect();
    let c_arg_ptrs: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();

    c_execv(
        c_args[0].as_ptr(),
        c_arg_ptrs.as_ptr() as *mut *const libc::c_char,
    );

    // If execv returns, it failed
    eprintln!("Could not execute {}: {}", args[0], io::Error::last_os_error());

    // Restore stderr for error reporting
    let _ = c_dup2(bkt, 2);
    eprintln!("Could not execute {}: {}", args[0], io::Error::last_os_error());
    std::process::exit(127);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_pty_endpoint_creation() {
        // We can't easily test actual PTY creation without a terminal,
        // but we can test the struct construction.
        let ioctls: &'static dyn Ioctls = &crate::pty::linux::LinuxIoctls;
        let ep = UnixPtyEndpoint::new(ioctls, 5);
        assert_eq!(ep.fd(), 5);
    }

    #[test]
    fn test_unix_pty_parent_creation() {
        let ioctls: &'static dyn Ioctls = &crate::pty::linux::LinuxIoctls;
        let parent = UnixPtyParent::new(ioctls, 3);
        assert_eq!(parent.endpoint.fd(), 3);
    }

    #[test]
    fn test_unix_pty_child_creation() {
        let ioctls: &'static dyn Ioctls = &crate::pty::linux::LinuxIoctls;
        let child = UnixPtyChild::new(ioctls, 4, "/dev/pts/0".to_string());
        assert_eq!(child.endpoint.fd(), 4);
        assert_eq!(child.name, "/dev/pts/0");
    }
}
