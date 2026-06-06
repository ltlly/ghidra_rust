//! Port of `VerticalLayoutPixelIndexMap`.
use std::collections::HashMap;
/// Struct porting `VerticalLayoutPixelIndexMap`.
#[derive(Debug, Clone)]
pub struct VerticalLayoutPixelIndexMap {
    _phantom: std::marker::PhantomData<()>,
}
impl VerticalLayoutPixelIndexMap {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VerticalLayoutPixelIndexMap {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vertical_layout_pixel_index_map_new() { let _ = VerticalLayoutPixelIndexMap::new(); }
}
