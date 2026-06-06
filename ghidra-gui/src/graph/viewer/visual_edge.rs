//! Port of Ghidra's `ghidra.graph.viewer.VisualEdge` interface.

use super::Point2D;

/// Trait for a visual edge in a graph viewer.
pub trait VisualEdge: Send + Sync + std::fmt::Debug {
    /// Unique identifier for this edge.
    fn id(&self) -> &str;
    /// Source vertex id.
    fn source_id(&self) -> &str;
    /// Target vertex id.
    fn target_id(&self) -> &str;
    /// Whether this edge is highlighted.
    fn is_highlighted(&self) -> bool;
    /// Set the highlight state.
    fn set_highlighted(&mut self, highlighted: bool);
    /// Whether this edge is hovered.
    fn is_hovered(&self) -> bool;
    /// Set the hover state.
    fn set_hovered(&mut self, hovered: bool);
    /// Edge articulation points for routing.
    fn articulations(&self) -> &[Point2D];
    /// Set articulation points.
    fn set_articulations(&mut self, points: Vec<Point2D>);
    /// Edge label text (if any).
    fn label(&self) -> Option<&str> { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestEdge {
        _id: String, _src: String, _tgt: String,
        hl: bool, hv: bool, arts: Vec<Point2D>,
    }
    impl TestEdge {
        fn new(id: &str, src: &str, tgt: &str) -> Self {
            Self { _id: id.into(), _src: src.into(), _tgt: tgt.into(), hl: false, hv: false, arts: vec![] }
        }
    }
    impl VisualEdge for TestEdge {
        fn id(&self) -> &str { &self._id }
        fn source_id(&self) -> &str { &self._src }
        fn target_id(&self) -> &str { &self._tgt }
        fn is_highlighted(&self) -> bool { self.hl }
        fn set_highlighted(&mut self, h: bool) { self.hl = h; }
        fn is_hovered(&self) -> bool { self.hv }
        fn set_hovered(&mut self, h: bool) { self.hv = h; }
        fn articulations(&self) -> &[Point2D] { &self.arts }
        fn set_articulations(&mut self, pts: Vec<Point2D>) { self.arts = pts; }
    }

    #[test]
    fn test_edge_basic() {
        let mut e = TestEdge::new("e1", "v1", "v2");
        assert_eq!(e.id(), "e1");
        assert_eq!(e.source_id(), "v1");
        assert_eq!(e.target_id(), "v2");
        assert!(!e.is_highlighted());
        e.set_highlighted(true);
        assert!(e.is_highlighted());
    }

    #[test]
    fn test_edge_articulations() {
        let mut e = TestEdge::new("e1", "v1", "v2");
        e.set_articulations(vec![Point2D::new(10.0, 20.0)]);
        assert_eq!(e.articulations().len(), 1);
    }
}
