//! Port of Ghidra's `ghidra.graph.viewer.VisualVertex` interface.
//!
//! Defines the trait for visual vertices in the graph viewer.

use super::Point2D;

/// Trait for a visual vertex in a graph viewer.
///
/// Ports Ghidra's `VisualVertex` interface. Each visual vertex has an
/// identifier, a position, a size, and selection/focus state.
pub trait VisualVertex: Send + Sync + std::fmt::Debug {
    /// Unique identifier for this vertex.
    fn id(&self) -> &str;

    /// Display label for this vertex.
    fn label(&self) -> &str;

    /// Position (top-left corner) of this vertex in layout space.
    fn position(&self) -> Point2D;

    /// Set the position of this vertex.
    fn set_position(&mut self, pos: Point2D);

    /// Size of this vertex (width, height).
    fn size(&self) -> (f64, f64);

    /// Center point of this vertex.
    fn center(&self) -> Point2D {
        let (w, h) = self.size();
        let p = self.position();
        Point2D::new(p.x + w / 2.0, p.y + h / 2.0)
    }

    /// Whether this vertex is currently selected.
    fn is_selected(&self) -> bool;

    /// Set the selection state.
    fn set_selected(&mut self, selected: bool);

    /// Whether this vertex is currently focused.
    fn is_focused(&self) -> bool;

    /// Set the focus state.
    fn set_focused(&mut self, focused: bool);

    /// Whether this vertex is visible.
    fn is_visible(&self) -> bool {
        true
    }

    /// Set the visibility of this vertex.
    fn set_visible(&mut self, _visible: bool) {}

    /// Whether this vertex is a "root" or entry vertex.
    fn is_entry(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestVertex {
        _id: String,
        _label: String,
        pos: Point2D,
        sz: (f64, f64),
        sel: bool,
        foc: bool,
    }

    impl TestVertex {
        fn new(id: &str, label: &str) -> Self {
            Self {
                _id: id.into(),
                _label: label.into(),
                pos: Point2D::ZERO,
                sz: (100.0, 40.0),
                sel: false,
                foc: false,
            }
        }
    }

    impl VisualVertex for TestVertex {
        fn id(&self) -> &str { &self._id }
        fn label(&self) -> &str { &self._label }
        fn position(&self) -> Point2D { self.pos }
        fn set_position(&mut self, pos: Point2D) { self.pos = pos; }
        fn size(&self) -> (f64, f64) { self.sz }
        fn is_selected(&self) -> bool { self.sel }
        fn set_selected(&mut self, selected: bool) { self.sel = selected; }
        fn is_focused(&self) -> bool { self.foc }
        fn set_focused(&mut self, focused: bool) { self.foc = focused; }
    }

    #[test]
    fn test_vertex_center() {
        let v = TestVertex::new("a", "A");
        assert_eq!(v.center(), Point2D::new(50.0, 20.0));
    }

    #[test]
    fn test_vertex_selection() {
        let mut v = TestVertex::new("a", "A");
        assert!(!v.is_selected());
        v.set_selected(true);
        assert!(v.is_selected());
    }

    #[test]
    fn test_vertex_position() {
        let mut v = TestVertex::new("a", "A");
        v.set_position(Point2D::new(10.0, 20.0));
        assert_eq!(v.position(), Point2D::new(10.0, 20.0));
    }
}
