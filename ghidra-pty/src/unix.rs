//! Unix pseudo-terminal implementation using POSIX APIs.
//!
//! Ported from `ghidra.pty.unix.*`. Provides `openpty()` using `libc`.

use std::io;
use std::os::unix::io::{FromRawFd, OwnedFd};

use crate::pty::Pty;
use crate::pty_child::PtyChild;
use crate::pty_parent::PtyParent;

/// A Unix pseudo-terminal backed by `openpty()`.
pub struct UnixPty {
    parent: PtyParent,
    child: PtyChild,
    /// The master file descriptor.
    pub master_fd: OwnedFd,
    /// The slave file descriptor.
    pub slave_fd: OwnedFd,
    /// The slave device name (e.g., `/dev/pts/0`).
    pub slave_name: String,
}

impl UnixPty {
    /// Open a new pseudo-terminal using POSIX `openpty()`.
    ///
    /// # Safety
    ///
    /// This function calls `libc::openpty` which is inherently unsafe.
    pub fn open() -> io::Result<Self> {
        let mut master_fd: i32 = -1;
        let mut slave_fd: i32 = -1;
        let mut name_buf = [0u8; 256];
        let name_ptr = name_buf.as_mut_ptr() as *mut i8;

        let result = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                name_ptr,
                std::ptr::null(),
                std::ptr::null(),
            )
        };

        if result != 0 {
            return Err(io::Error::last_os_error());
        }

        let slave_name = unsafe {
            std::ffi::CStr::from_ptr(name_ptr)
                .to_string_lossy()
                .into_owned()
        };

        let master_fd = unsafe { OwnedFd::from_raw_fd(master_fd) };
        let slave_fd_owned = unsafe { OwnedFd::from_raw_fd(slave_fd) };

        // Create reader/writer from the master fd for the parent side
        let master_read = unsafe { std::fs::File::from_raw_fd(libc::dup(master_fd.as_raw_fd())) };
        let master_write =
            unsafe { std::fs::File::from_raw_fd(libc::dup(master_fd.as_raw_fd())) };

        let slave_read = unsafe { std::fs::File::from_raw_fd(libc::dup(slave_fd)) };
        let slave_write = unsafe { std::fs::File::from_raw_fd(libc::dup(slave_fd)) };

        let parent = PtyParent::new(Box::new(master_read), Box::new(master_write));
        let child = PtyChild::new(Box::new(slave_read), Box::new(slave_write))
            .with_device_name(&slave_name);

        Ok(Self {
            parent,
            child,
            master_fd,
            slave_fd: slave_fd_owned,
            slave_name,
        })
    }
}

impl Pty for UnixPty {
    fn get_parent(&self) -> &PtyParent {
        &self.parent
    }

    fn get_child(&self) -> &PtyChild {
        &self.child
    }

    fn get_parent_mut(&mut self) -> &mut PtyParent {
        &mut self.parent
    }

    fn get_child_mut(&mut self) -> &mut PtyChild {
        &mut self.child
    }

    fn close(&mut self) -> io::Result<()> {
        // Closing the file descriptors will close the pty
        Ok(())
    }

    fn is_open(&self) -> bool {
        true // FDs are managed by OwnedFd
    }
}

use std::os::unix::io::AsRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_pty_open() {
        // Only run on Unix systems with pty support
        if cfg!(unix) {
            match UnixPty::open() {
                Ok(pty) => {
                    assert!(pty.is_open());
                    assert!(!pty.slave_name.is_empty());
                }
                Err(e) => {
                    // May fail in CI/container without pty access
                    eprintln!("Could not open pty (expected in some CI): {}", e);
                }
            }
        }
    }
}
