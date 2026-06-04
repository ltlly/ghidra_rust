//! Output stream wrapping a native POSIX file descriptor.
//!
//! Port of Ghidra's `ghidra.pty.unix.FdOutputStream`.

use std::io::{self, Write};

use super::posix_c::c_write;

/// An output stream that writes to a POSIX file descriptor.
///
/// # Safety
///
/// This makes use of native `write()` calls. An invalid file descriptor
/// is generally detected, but a valid but incorrect descriptor may cause
/// undefined behavior.
pub struct FdOutputStream {
    fd: i32,
    closed: bool,
}

impl FdOutputStream {
    /// Wrap the given file descriptor in an `FdOutputStream`.
    pub fn new(fd: i32) -> Self {
        Self { fd, closed: false }
    }
}

impl Write for FdOutputStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Stream closed"));
        }

        let mut total: usize = 0;
        while total < buf.len() {
            let ret = unsafe {
                c_write(
                    self.fd,
                    buf[total..].as_ptr() as *const libc::c_void,
                    buf.len() - total,
                )
            };

            if ret < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(5) | Some(9) => return Err(err), // EIO, EBADF
                    _ => return Err(err),
                }
            }
            total += ret as usize;
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_output_stream_creation() {
        let stream = FdOutputStream::new(3);
        assert!(!stream.closed);
        assert_eq!(stream.fd, 3);
    }

    #[test]
    fn test_fd_output_stream_closed_write() {
        let mut stream = FdOutputStream::new(3);
        stream.closed = true;
        let result = stream.write(b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn test_fd_output_stream_flush() {
        let mut stream = FdOutputStream::new(3);
        assert!(stream.flush().is_ok());
    }
}
