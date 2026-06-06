//! `PtyParent` -- the parent end of a pseudo-terminal.
//!
//! Ported from `ghidra.pty.PtyParent`.

use std::io::{Read, Write};

use crate::pty_endpoint::PtyEndpoint;

/// The parent end of a pseudo-terminal.
///
/// The parent end provides I/O streams for controlling a child process.
/// It is typically the end used by the controlling application (e.g., an SSH
/// server or a debugger).
pub struct PtyParent {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

impl PtyParent {
    /// Create a new parent endpoint.
    pub fn new(reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>) -> Self {
        Self { reader, writer }
    }
}

impl std::fmt::Debug for PtyParent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyParent").finish()
    }
}

impl PtyEndpoint for PtyParent {
    fn input(&mut self) -> &mut dyn Read {
        &mut *self.reader
    }

    fn output(&mut self) -> &mut dyn Write {
        &mut *self.writer
    }
}

/// Wrapper providing convenient read/write access to the parent pty.
pub struct PtyParentHandle {
    /// The underlying parent endpoint.
    pub inner: PtyParent,
    /// The file descriptor for the parent side (Unix).
    pub fd: Option<i32>,
}

impl PtyParentHandle {
    /// Create a new parent handle.
    pub fn new(parent: PtyParent) -> Self {
        Self {
            inner: parent,
            fd: None,
        }
    }

    /// Set the file descriptor.
    pub fn with_fd(mut self, fd: i32) -> Self {
        self.fd = Some(fd);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_pty_parent_new() {
        let reader: Box<dyn Read + Send> = Box::new(Cursor::new(vec![1, 2, 3]));
        let writer: Box<dyn Write + Send> = Box::new(Vec::new());
        let parent = PtyParent::new(reader, writer);
        let _ = parent;
    }

    #[test]
    fn test_pty_parent_handle() {
        let reader: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::new()));
        let writer: Box<dyn Write + Send> = Box::new(Vec::new());
        let parent = PtyParent::new(reader, writer);
        let handle = PtyParentHandle::new(parent).with_fd(3);
        assert_eq!(handle.fd, Some(3));
    }
}
