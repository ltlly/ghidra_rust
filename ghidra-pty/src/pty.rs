//! `Pty` -- pseudo-terminal interface.
//!
//! Ported from `ghidra.pty.Pty`. A pseudo-terminal is a two-way pipe where
//! one end acts as the parent and the other acts as the child.

use std::io;

use crate::pty_child::PtyChild;
use crate::pty_parent::PtyParent;

/// A pseudo-terminal.
///
/// A pseudo-terminal is essentially a two-way pipe where one end acts as the
/// parent, and the other acts as the child. The process opening the
/// pseudo-terminal is given a handle to both ends. The child end is generally
/// given to a subprocess, possibly designating the pty as the controlling tty
/// of a new session.
pub trait Pty: Send {
    /// Get a handle to the parent side of the pty.
    fn get_parent(&self) -> &PtyParent;

    /// Get a handle to the child side of the pty.
    fn get_child(&self) -> &PtyChild;

    /// Get a mutable handle to the parent side of the pty.
    fn get_parent_mut(&mut self) -> &mut PtyParent;

    /// Get a mutable handle to the child side of the pty.
    fn get_child_mut(&mut self) -> &mut PtyChild;

    /// Close both ends of the pty.
    fn close(&mut self) -> io::Result<()>;

    /// Returns `true` if this pty is still open.
    fn is_open(&self) -> bool;
}

/// A basic in-memory Pty implementation for testing and non-platform-specific
/// use.
#[derive(Debug)]
pub struct MemoryPty {
    parent: PtyParent,
    child: PtyChild,
    open: bool,
}

impl MemoryPty {
    /// Create a new memory-backed pty (for testing).
    pub fn new() -> Self {
        let (parent_tx, parent_rx) = std::sync::mpsc::channel();
        let (child_tx, child_rx) = std::sync::mpsc::channel();

        Self {
            parent: PtyParent::new(
                Box::new(MpscReader(parent_rx)),
                Box::new(MpscWriter(child_tx)),
            ),
            child: PtyChild::new(
                Box::new(MpscReader(child_rx)),
                Box::new(MpscWriter(parent_tx)),
            ),
            open: true,
        }
    }
}

impl Default for MemoryPty {
    fn default() -> Self {
        Self::new()
    }
}

impl Pty for MemoryPty {
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
        self.open = false;
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.open
    }
}

// Internal stream adapters for MemoryPty

struct MpscReader(std::sync::mpsc::Receiver<u8>);

impl std::io::Read for MpscReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.0.recv() {
            Ok(byte) => {
                buf[0] = byte;
                // Try to read more without blocking
                let mut count = 1;
                while count < buf.len() {
                    match self.0.try_recv() {
                        Ok(b) => {
                            buf[count] = b;
                            count += 1;
                        }
                        Err(_) => break,
                    }
                }
                Ok(count)
            }
            Err(_) => Ok(0), // EOF
        }
    }
}

struct MpscWriter(std::sync::mpsc::Sender<u8>);

impl std::io::Write for MpscWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut count = 0;
        for &byte in buf {
            if self.0.send(byte).is_err() {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn test_memory_pty_creation() {
        let pty = MemoryPty::new();
        assert!(pty.is_open());
    }

    #[test]
    fn test_memory_pty_close() {
        let mut pty = MemoryPty::new();
        pty.close().unwrap();
        assert!(!pty.is_open());
    }

    #[test]
    fn test_memory_pty_parent_child() {
        let pty = MemoryPty::new();
        let _parent = pty.get_parent();
        let _child = pty.get_child();
    }

    #[test]
    fn test_memory_pty_default() {
        let pty = MemoryPty::default();
        assert!(pty.is_open());
    }
}
