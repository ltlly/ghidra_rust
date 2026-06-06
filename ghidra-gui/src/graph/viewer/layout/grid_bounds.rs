//! Port of `GridBounds`.
use std::collections::HashMap;
/// Struct porting `GridBounds`.
#[derive(Debug, Clone)]
pub struct GridBounds {
    _phantom: std::marker::PhantomData<()>,
}
impl GridBounds {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GridBounds {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_grid_bounds_new() { let _ = GridBounds::new(); }
}
