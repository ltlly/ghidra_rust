//! Port of `MouseClickedPaintableShape`.
use std::collections::HashMap;
/// Struct porting `MouseClickedPaintableShape`.
#[derive(Debug, Clone)]
pub struct MouseClickedPaintableShape {
    _phantom: std::marker::PhantomData<()>,
}
impl MouseClickedPaintableShape {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MouseClickedPaintableShape {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mouse_clicked_paintable_shape_new() { let _ = MouseClickedPaintableShape::new(); }
}
