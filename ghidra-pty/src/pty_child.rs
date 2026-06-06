//! `PtyChild` -- the child end of a pseudo-terminal.
//!
//! Ported from `ghidra.pty.PtyChild`.

use std::io::{Read, Write};

use crate::pty_endpoint::PtyEndpoint;

/// The child end of a pseudo-terminal.
///
/// The child end is typically given to a subprocess as its controlling
/// terminal. It provides I/O streams and methods for obtaining the pty
/// device name (for spawning sessions).
pub struct PtyChild {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    /// The slave device path (e.g., `/dev/pts/0` on Linux).
    device_name: Option<String>,
}

impl PtyChild {
    /// Create a new child endpoint.
    pub fn new(reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>) -> Self {
        Self {
            reader,
            writer,
            device_name: None,
        }
    }

    /// Set the device name for this child endpoint.
    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = Some(name.into());
        self
    }

    /// Get the device name for this child endpoint.
    pub fn device_name(&self) -> Option<&str> {
        self.device_name.as_deref()
    }
}

impl std::fmt::Debug for PtyChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyChild")
            .field("device_name", &self.device_name)
            .finish()
    }
}

impl PtyEndpoint for PtyChild {
    fn input(&mut self) -> &mut dyn Read {
        &mut *self.reader
    }

    fn output(&mut self) -> &mut dyn Write {
        &mut *self.writer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_pty_child_new() {
        let reader: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::new()));
        let writer: Box<dyn Write + Send> = Box::new(Vec::new());
        let child = PtyChild::new(reader, writer);
        assert!(child.device_name().is_none());
    }

    #[test]
    fn test_pty_child_with_device() {
        let reader: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::new()));
        let writer: Box<dyn Write + Send> = Box::new(Vec::new());
        let child = PtyChild::new(reader, writer).with_device_name("/dev/pts/0");
        assert_eq!(child.device_name(), Some("/dev/pts/0"));
    }
}
