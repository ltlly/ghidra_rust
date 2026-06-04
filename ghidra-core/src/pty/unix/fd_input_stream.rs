//! Input stream wrapping a native POSIX file descriptor.
//!
//! Port of Ghidra's `ghidra.pty.unix.FdInputStream`.

use std::io::{self, Read};

use super::posix_c::c_read;

/// An input stream that reads from a POSIX file descriptor.
///
/// # Safety
///
/// This makes use of native `read()` calls. An invalid file descriptor
/// is generally detected, but a valid but incorrect descriptor may cause
/// undefined behavior.
pub struct FdInputStream {
    fd: i32,
    closed: bool,
}

impl FdInputStream {
    /// Wrap the given file descriptor in an `FdInputStream`.
    pub fn new(fd: i32) -> Self {
        Self { fd, closed: false }
    }
}

impl Read for FdInputStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Stream closed"));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let ret = unsafe { c_read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(5) | Some(9) => Err(err), // EIO, EBADF
                _ => Err(err),
            }
        } else {
            Ok(ret as usize)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_input_stream_creation() {
        let stream = FdInputStream::new(5);
        assert!(!stream.closed);
        assert_eq!(stream.fd, 5);
    }

    #[test]
    fn test_fd_input_stream_closed_read() {
        let mut stream = FdInputStream::new(5);
        stream.closed = true;
        let mut buf = [0u8; 10];
        let result = stream.read(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_fd_input_stream_empty_buf() {
        let mut stream = FdInputStream::new(5);
        let mut buf = [];
        let result = stream.read(&mut buf);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
