//! Function Call Graph edge.
//!
//! Ported from Ghidra's `functioncalls.graph.FcgEdge` Java class.
//!
//! An edge connects two vertices in the function call graph.  Edges can be
//! classified as "direct" (connecting adjacent levels) or "indirect"
//! (connecting non-adjacent levels).

use super::fcg_level::FcgLevel;
use super::fcg_vertex::FcgVertex;

/// An edge in the function call graph.
///
/// Ported from `functioncalls.graph.FcgEdge`.
#[derive(Debug, Clone)]
pub struct FcgEdge {
    /// Unique edge ID.
    id: u64,
    /// The start (source/caller) vertex.
    start: FcgVertex,
    /// The end (target/callee) vertex.
    end: FcgVertex,
    /// Visual emphasis level (0.0 = none, 1.0 = full).
    emphasis: f64,
    /// Alpha/opacity for animation (0.0 = transparent, 1.0 = opaque).
    alpha: f64,
}

impl FcgEdge {
    /// Create a new edge between two vertices.
    pub fn new(id: u64, start: FcgVertex, end: FcgVertex) -> Self {
        Self {
            id,
            start,
            end,
            emphasis: 0.0,
            alpha: 1.0,
        }
    }

    /// Get the edge ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the start (source/caller) vertex.
    pub fn start(&self) -> &FcgVertex {
        &self.start
    }

    /// Get the end (target/callee) vertex.
    pub fn end(&self) -> &FcgVertex {
        &self.end
    }

    /// Get the emphasis level.
    pub fn emphasis(&self) -> f64 {
        self.emphasis
    }

    /// Set the emphasis level.
    pub fn set_emphasis(&mut self, emphasis: f64) {
        self.emphasis = emphasis;
    }

    /// Get the alpha/opacity.
    pub fn alpha(&self) -> f64 {
        self.alpha
    }

    /// Set the alpha/opacity.
    pub fn set_alpha(&mut self, alpha: f64) {
        self.alpha = alpha;
    }

    /// Returns `true` if this edge is a direct edge from a lower level.
    ///
    /// Direct edges connect adjacent levels (parent <-> child).
    /// Any other edges are considered indirect and are less important
    /// in the graph.
    pub fn is_direct_edge(&self) -> bool {
        let start_level = self.start.level();
        let end_level = self.end.level();

        if start_level.is_source() || end_level.is_source() {
            // All info leaving the source is important / "direct"
            return true;
        }

        let parent = start_level.parent();
        if parent == *end_level {
            return true;
        }

        let child = start_level.child();
        child == *end_level
    }

    /// Clone this edge with new start and end vertices.
    pub fn clone_edge(&self, start: FcgVertex, end: FcgVertex) -> FcgEdge {
        FcgEdge {
            id: self.id,
            start,
            end,
            emphasis: self.emphasis,
            alpha: self.alpha,
        }
    }
}

impl PartialEq for FcgEdge {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for FcgEdge {}

impl std::hash::Hash for FcgEdge {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl std::fmt::Display for FcgEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.start.name(), self.end.name())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calltree::fcg_direction::FcgDirection;
    use crate::calltree::fcg_level::FcgLevel;
    use crate::calltree::fcg_vertex::FcgVertex;

    fn make_vertex(name: &str, addr: u64, level: FcgLevel) -> FcgVertex {
        FcgVertex::new(name, addr, level)
    }

    #[test]
    fn test_edge_creation() {
        let v1 = make_vertex("main", 0x1000, FcgLevel::source_level());
        let v2 = make_vertex("foo", 0x2000, FcgLevel::new(1, FcgDirection::Out));
        let edge = FcgEdge::new(1, v1.clone(), v2.clone());

        assert_eq!(edge.id(), 1);
        assert_eq!(edge.start().name(), "main");
        assert_eq!(edge.end().name(), "foo");
        assert_eq!(edge.emphasis(), 0.0);
        assert_eq!(edge.alpha(), 1.0);
    }

    #[test]
    fn test_direct_edge_from_source() {
        let source = make_vertex("main", 0x1000, FcgLevel::source_level());
        let out1 = make_vertex("foo", 0x2000, FcgLevel::new(1, FcgDirection::Out));
        let edge = FcgEdge::new(1, source, out1);
        assert!(edge.is_direct_edge());
    }

    #[test]
    fn test_direct_edge_parent_child() {
        let in1 = make_vertex("caller", 0x2000, FcgLevel::new(1, FcgDirection::In));
        let in2 = make_vertex("caller2", 0x3000, FcgLevel::new(2, FcgDirection::In));
        let edge = FcgEdge::new(1, in1, in2);
        assert!(edge.is_direct_edge());
    }

    #[test]
    fn test_indirect_edge() {
        let in1 = make_vertex("caller1", 0x2000, FcgLevel::new(1, FcgDirection::In));
        let out1 = make_vertex("callee1", 0x3000, FcgLevel::new(1, FcgDirection::Out));
        let edge = FcgEdge::new(1, in1, out1);
        // In->Out across different directions is not direct
        assert!(!edge.is_direct_edge());
    }

    #[test]
    fn test_emphasis_and_alpha() {
        let v1 = make_vertex("a", 0x1000, FcgLevel::source_level());
        let v2 = make_vertex("b", 0x2000, FcgLevel::new(1, FcgDirection::Out));
        let mut edge = FcgEdge::new(1, v1, v2);

        edge.set_emphasis(0.5);
        assert_eq!(edge.emphasis(), 0.5);

        edge.set_alpha(0.8);
        assert_eq!(edge.alpha(), 0.8);
    }

    #[test]
    fn test_clone_edge() {
        let v1 = make_vertex("a", 0x1000, FcgLevel::source_level());
        let v2 = make_vertex("b", 0x2000, FcgLevel::new(1, FcgDirection::Out));
        let edge = FcgEdge::new(1, v1, v2);

        let v3 = make_vertex("c", 0x3000, FcgLevel::source_level());
        let v4 = make_vertex("d", 0x4000, FcgLevel::new(1, FcgDirection::Out));
        let cloned = edge.clone_edge(v3, v4);

        assert_eq!(cloned.id(), edge.id());
        assert_eq!(cloned.start().name(), "c");
        assert_eq!(cloned.end().name(), "d");
    }

    #[test]
    fn test_equality_by_id() {
        let v1 = make_vertex("a", 0x1000, FcgLevel::source_level());
        let v2 = make_vertex("b", 0x2000, FcgLevel::new(1, FcgDirection::Out));
        let e1 = FcgEdge::new(1, v1.clone(), v2.clone());
        let e2 = FcgEdge::new(1, v1, v2);
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_display() {
        let v1 = make_vertex("main", 0x1000, FcgLevel::source_level());
        let v2 = make_vertex("foo", 0x2000, FcgLevel::new(1, FcgDirection::Out));
        let edge = FcgEdge::new(1, v1, v2);
        assert_eq!(edge.to_string(), "main -> foo");
    }
}
