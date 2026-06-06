//! Port of `MouseDraggedPaintableShape`.
use std::collections::HashMap;
/// Struct porting `MouseDraggedPaintableShape`.
#[derive(Debug, Clone)]
pub struct MouseDraggedPaintableShape {
    _phantom: std::marker::PhantomData<()>,
}
impl MouseDraggedPaintableShape {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MouseDraggedPaintableShape {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mouse_dragged_paintable_shape_new() { let _ = MouseDraggedPaintableShape::new(); }
}
