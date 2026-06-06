//! Port of `VertexShape`.
use std::collections::HashMap;
/// Struct porting `VertexShape`.
#[derive(Debug, Clone)]
pub struct VertexShape {
    /// rectangle.
    pub rectangle: String,
    /// ellipse.
    pub ellipse: String,
    /// triangle_up.
    pub triangle_up: String,
    /// triangle_down.
    pub triangle_down: String,
    /// star.
    pub star: String,
    /// diamond.
    pub diamond: String,
}

impl VertexShape {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for VertexShape {
    fn default() -> Self {
        Self {
            rectangle: String::new(),
            ellipse: String::new(),
            triangle_up: String::new(),
            triangle_down: String::new(),
            star: String::new(),
            diamond: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vertex_shape_new() { let _ = VertexShape::new(); }
}
