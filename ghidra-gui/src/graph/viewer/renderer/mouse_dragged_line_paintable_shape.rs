//! Port of `MouseDraggedLinePaintableShape`.
use std::collections::HashMap;
/// Struct porting `MouseDraggedLinePaintableShape`.
#[derive(Debug, Clone)]
pub struct MouseDraggedLinePaintableShape {
    _phantom: std::marker::PhantomData<()>,
}
impl MouseDraggedLinePaintableShape {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MouseDraggedLinePaintableShape {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mouse_dragged_line_paintable_shape_new() { let _ = MouseDraggedLinePaintableShape::new(); }
}
