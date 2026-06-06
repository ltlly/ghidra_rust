//! Port of Ghidra's `ghidra.graph.GEdge` interface.
//!
//! Defines the minimal contract for edges in a directed graph. Each edge
//! connects a start vertex to an end vertex.

/// A directed edge connecting two vertices of type `V`.
///
/// This trait mirrors Ghidra's Java `GEdge<V>` interface. Implementors
/// carry vertex references and may add additional metadata (weight,
/// label, visual properties, etc.).
pub trait GEdge<V>: Send + Sync + std::fmt::Debug {
    /// Return the source vertex of this edge.
    fn start(&self) -> &V;

    /// Return the target vertex of this edge.
    fn end(&self) -> &V;

    /// Return the two endpoints as a tuple `(start, end)`.
    fn endpoints(&self) -> (&V, &V) {
        (self.start(), self.end())
    }

    /// Return `true` when `vertex` is one of the two endpoints.
    fn touches(&self, vertex: &V) -> bool
    where
        V: PartialEq,
    {
        self.start() == vertex || self.end() == vertex
    }

    /// Return the "other" endpoint -- i.e. whichever of start/end is *not*
    /// `vertex`. Returns `None` if `vertex` is not an endpoint (or if
    /// start == end == vertex).
    fn opposite(&self, vertex: &V) -> Option<&V>
    where
        V: PartialEq,
    {
        if self.start() == vertex {
            Some(self.end())
        } else if self.end() == vertex {
            Some(self.start())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct SimpleEdge {
        from: String,
        to: String,
    }

    impl GEdge<String> for SimpleEdge {
        fn start(&self) -> &String { &self.from }
        fn end(&self) -> &String { &self.to }
    }

    #[test]
    fn test_endpoints() {
        let e = SimpleEdge { from: "A".into(), to: "B".into() };
        assert_eq!(e.endpoints(), (&"A".to_string(), &"B".to_string()));
    }

    #[test]
    fn test_touches() {
        let e = SimpleEdge { from: "A".into(), to: "B".into() };
        assert!(e.touches(&"A".to_string()));
        assert!(e.touches(&"B".to_string()));
        assert!(!e.touches(&"C".to_string()));
    }

    #[test]
    fn test_opposite() {
        let e = SimpleEdge { from: "A".into(), to: "B".into() };
        assert_eq!(e.opposite(&"A".into()), Some(&"B".to_string()));
        assert_eq!(e.opposite(&"B".into()), Some(&"A".to_string()));
        assert_eq!(e.opposite(&"C".into()), None);
    }
}
