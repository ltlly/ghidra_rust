//! Port of `GridPoint`.
use std::collections::HashMap;
/// Struct porting `GridPoint`.
#[derive(Debug, Clone)]
pub struct GridPoint {
    /// row.
    pub row: i32,
    /// col.
    pub col: i32,
}

impl GridPoint {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for GridPoint {
    fn default() -> Self {
        Self {
            row: 0,
            col: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_grid_point_new() { let _ = GridPoint::new(); }
}
