//! Visual graph traits for graph visualization.
//!
//! Port of `ghidra.graph.viewer.VisualVertex` and
//! `ghidra.graph.viewer.VisualEdge`.

use std::fmt::Debug;
use std::hash::Hash;

use super::traits::GEdge;

/// A point in 2-D space used for vertex layout positions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point2D {
    /// X coordinate.
    pub x: f64,
    /// Y coordinate.
    pub y: f64,
}

impl Eq for Point2D {}

impl std::hash::Hash for Point2D {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.x.to_bits().hash(state);
        self.y.to_bits().hash(state);
    }
}

impl Point2D {
    /// Create a new point.
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// Trait for vertices that can be displayed in a visual graph.
pub trait VisualVertex: Clone + Debug + Eq + Hash {
    /// Get the display location of this vertex.
    fn get_location(&self) -> Point2D;

    /// Set the display location of this vertex.
    fn set_location(&mut self, location: Point2D);

    /// Whether this vertex is currently selected.
    fn is_selected(&self) -> bool {
        false
    }

    /// Set the selected state of this vertex.
    fn set_selected(&mut self, _selected: bool) {}

    /// Whether this vertex is currently focused.
    fn is_focused(&self) -> bool {
        false
    }

    /// Set the focused state of this vertex.
    fn set_focused(&mut self, _focused: bool) {}
}

/// Trait for edges that can be displayed in a visual graph.
pub trait VisualEdge<V: VisualVertex>: GEdge<V> + Clone + Debug {
    /// Whether this edge is currently selected.
    fn is_selected(&self) -> bool {
        false
    }

    /// Set the selected state of this edge.
    fn set_selected(&mut self, _selected: bool) {}
}

// Blanket impl: any GEdge<V> where V: VisualVertex automatically
// implements VisualEdge<V> with default (not-selected) behavior.
impl<V: VisualVertex, E: GEdge<V> + Clone + Debug> VisualEdge<V> for E {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestVertex {
        id: u32,
        location: Point2D,
        selected: bool,
    }

    impl VisualVertex for TestVertex {
        fn get_location(&self) -> Point2D {
            self.location
        }
        fn set_location(&mut self, location: Point2D) {
            self.location = location;
        }
        fn is_selected(&self) -> bool {
            self.selected
        }
        fn set_selected(&mut self, selected: bool) {
            self.selected = selected;
        }
    }

    #[test]
    fn test_point2d() {
        let p = Point2D::new(3.0, 4.0);
        assert_eq!(p.x, 3.0);
        assert_eq!(p.y, 4.0);
    }

    #[test]
    fn test_point2d_eq() {
        let p1 = Point2D::new(1.0, 2.0);
        let p2 = Point2D::new(1.0, 2.0);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_point2d_ne() {
        let p1 = Point2D::new(1.0, 2.0);
        let p2 = Point2D::new(1.0, 3.0);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_visual_vertex_trait() {
        let mut v = TestVertex {
            id: 1,
            location: Point2D::new(0.0, 0.0),
            selected: false,
        };
        assert!(!v.is_selected());
        v.set_selected(true);
        assert!(v.is_selected());
        v.set_location(Point2D::new(10.0, 20.0));
        assert_eq!(v.get_location(), Point2D::new(10.0, 20.0));
    }

    #[test]
    fn test_default_visual_edge() {
        // DefaultGEdge implements VisualEdge via blanket impl when V: VisualVertex
        let v1 = TestVertex { id: 1, location: Point2D::new(0.0, 0.0), selected: false };
        let v2 = TestVertex { id: 2, location: Point2D::new(10.0, 0.0), selected: false };
        let e = DefaultGEdge::new(v1, v2);
        assert!(!e.is_selected());
    }

    #[test]
    fn test_vertex_focused_default() {
        let v = TestVertex {
            id: 1,
            location: Point2D::new(0.0, 0.0),
            selected: false,
        };
        // Default is_focused returns false
        assert!(!v.is_focused());
    }
}
