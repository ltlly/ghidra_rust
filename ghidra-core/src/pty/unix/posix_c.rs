//! Raw POSIX C bindings for terminal operations.
//!
//! Port of Ghidra's `ghidra.pty.unix.PosixC`. These are low-level FFI
//! bindings to libc functions used by the pty framework.

// Re-export libc types for convenience
pub use libc::termios as Termios;
pub use libc::winsize as Winsize;

/// Standard POSIX constants for terminal I/O.
pub const O_RDWR: libc::c_int = libc::O_RDWR;
/// TCSANOW: apply changes immediately.
pub const TCSANOW: libc::c_int = 0;
/// ECHO flag in termios c_lflag.
pub const TERMIO_ECHO: libc::c_uint = 0o000010; // octal 0000010

/// A constant placeholder for TIOCSCTTY's `steal` argument.
pub const CONTROLLING_TTY: i32 = 0;

/// Trait providing platform-specific ioctl numbers.
///
/// Each platform provides its own constants for `TIOCSCTTY` (set controlling
/// terminal) and `TIOCSWINSZ` (set window size).
pub trait Ioctls: Send + Sync {
    /// ioctl number for setting the controlling terminal.
    fn tiocsctty(&self) -> libc::c_ulong;

    /// ioctl number for setting the window size.
    fn tiocswinsz(&self) -> libc::c_ulong;

    /// Human-readable platform name.
    fn platform_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Raw FFI bindings
// ---------------------------------------------------------------------------

/// Close a file descriptor.
///
/// # Safety
/// The fd must be a valid, open file descriptor.
pub unsafe fn c_close(fd: i32) -> i32 {
    libc::close(fd)
}

/// Read from a file descriptor into a buffer.
///
/// # Safety
/// `buf` must point to a valid writable memory region of at least `count` bytes.
pub unsafe fn c_read(fd: i32, buf: *mut libc::c_void, count: usize) -> isize {
    libc::read(fd, buf, count)
}

/// Write a buffer to a file descriptor.
///
/// # Safety
/// `buf` must point to a valid readable memory region of at least `count` bytes.
pub unsafe fn c_write(fd: i32, buf: *const libc::c_void, count: usize) -> isize {
    libc::write(fd, buf, count)
}

/// Create a new session for the calling process.
///
/// # Safety
/// Must only be called in the appropriate child process context.
pub unsafe fn c_setsid() -> libc::pid_t {
    libc::setsid()
}

/// Open a file.
///
/// # Safety
/// `path` must be a valid null-terminated C string.
pub unsafe fn c_open(path: *const libc::c_char, oflag: libc::c_int, mode: libc::c_int) -> i32 {
    libc::open(path, oflag, mode) as i32
}

/// Duplicate a file descriptor.
///
/// # Safety
/// Both fds must be valid or appropriately assigned.
pub unsafe fn c_dup2(oldfd: i32, newfd: i32) -> i32 {
    libc::dup2(oldfd, newfd)
}

/// Execute a program.
///
/// # Safety
/// `path` and `argv` must be valid null-terminated C strings/arrays.
/// This function does not return on success.
pub unsafe fn c_execv(path: *const libc::c_char, argv: *mut *const libc::c_char) -> i32 {
    libc::execv(path, argv) as i32
}

/// Perform an ioctl operation on a file descriptor.
///
/// # Safety
/// `arg` must be appropriate for the given ioctl command.
pub unsafe fn c_ioctl(fd: i32, request: libc::c_ulong, arg: *const libc::c_void) -> i32 {
    libc::ioctl(fd, request, arg) as i32
}

/// Get terminal attributes.
///
/// # Safety
/// `termios_p` must point to a valid `termios` struct.
pub unsafe fn c_tcgetattr(fd: i32, termios_p: *mut Termios) -> i32 {
    libc::tcgetattr(fd, termios_p)
}

/// Set terminal attributes.
///
/// # Safety
/// `termios_p` must point to a valid `termios` struct.
pub unsafe fn c_tcsetattr(fd: i32, action: i32, termios_p: *const Termios) -> i32 {
    libc::tcsetattr(fd, action, termios_p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(TCSANOW, 0);
        assert_eq!(TERMIO_ECHO, 0o10);
        assert_eq!(CONTROLLING_TTY, 0);
    }

    #[test]
    fn test_termios_size() {
        // Verify the Termios struct has a reasonable size
        assert!(std::mem::size_of::<Termios>() > 0);
    }

    #[test]
    fn test_winsize_size() {
        assert!(std::mem::size_of::<Winsize>() > 0);
    }
}
