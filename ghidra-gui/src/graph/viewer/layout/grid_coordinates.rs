//! Port of `GridCoordinates`.
use std::collections::HashMap;
/// Struct porting `GridCoordinates`.
#[derive(Debug, Clone)]
pub struct GridCoordinates {
    _phantom: std::marker::PhantomData<()>,
}
impl GridCoordinates {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GridCoordinates {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_grid_coordinates_new() { let _ = GridCoordinates::new(); }
}
