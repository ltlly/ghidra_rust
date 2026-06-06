//! `PtyEndpoint` -- base trait for pty endpoints.
//!
//! Ported from `ghidra.pty.PtyEndpoint`.

use std::io::{Read, Write};

/// An endpoint of a pseudo-terminal.
///
/// Both the parent and child ends provide input/output streams.
pub trait PtyEndpoint {
    /// Get a reader for the input side of this endpoint.
    fn input(&mut self) -> &mut dyn Read;

    /// Get a writer for the output side of this endpoint.
    fn output(&mut self) -> &mut dyn Write;

    /// Get the file descriptor (Unix) or handle (Windows) for this endpoint.
    ///
    /// Returns `None` if not applicable (e.g., memory-backed pty).
    fn file_descriptor(&self) -> Option<i32> {
        None
    }
}
