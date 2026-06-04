//! Default directed edge implementation.
//!
//! Port of `ghidra.graph.DefaultGEdge<V>`.

use std::fmt::Debug;
use std::hash::{Hash, Hasher};

use super::traits::GEdge;

/// A simple directed edge with a start and end vertex.
///
/// Mirrors `ghidra.graph.DefaultGEdge<V>`.
#[derive(Debug, Clone)]
pub struct DefaultGEdge<V: Clone + Debug + Eq + Hash> {
    start: V,
    end: V,
}

impl<V: Clone + Debug + Eq + Hash> DefaultGEdge<V> {
    /// Create a new edge from `start` to `end`.
    pub fn new(start: V, end: V) -> Self {
        Self { start, end }
    }
}

impl<V: Clone + Debug + Eq + Hash> GEdge<V> for DefaultGEdge<V> {
    fn start(&self) -> &V {
        &self.start
    }

    fn end(&self) -> &V {
        &self.end
    }
}

impl<V: Clone + Debug + Eq + Hash> PartialEq for DefaultGEdge<V> {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start && self.end == other.end
    }
}

impl<V: Clone + Debug + Eq + Hash> Eq for DefaultGEdge<V> {}

impl<V: Clone + Debug + Eq + Hash> Hash for DefaultGEdge<V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.start.hash(state);
        self.end.hash(state);
    }
}
