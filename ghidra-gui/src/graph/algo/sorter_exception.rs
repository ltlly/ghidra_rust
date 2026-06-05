//! Exception thrown by graph sorting algorithms.
//!
//! Ports `ghidra.graph.algo.SorterException`.

use std::fmt;

/// Error from a graph sorting algorithm.
#[derive(Debug, Clone)]
pub struct SorterException {
    /// The error message.
    pub message: String,
    /// The vertex that caused the error (if applicable).
    pub vertex: Option<String>,
}

impl SorterException {
    /// Create a new SorterException.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            vertex: None,
        }
    }

    /// Create with a specific vertex.
    pub fn with_vertex(message: impl Into<String>, vertex: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            vertex: Some(vertex.into()),
        }
    }
}

impl fmt::Display for SorterException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref v) = self.vertex {
            write!(f, "Sorter error at vertex '{}': {}", v, self.message)
        } else {
            write!(f, "Sorter error: {}", self.message)
        }
    }
}

impl std::error::Error for SorterException {}
