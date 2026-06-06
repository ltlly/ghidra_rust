//! Port of `GridRange`.
use std::collections::HashMap;
/// Struct porting `GridRange`.
#[derive(Debug, Clone)]
pub struct GridRange {
    /// min.
    pub min: i32,
    /// max.
    pub max: i32,
}

impl GridRange {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for GridRange {
    fn default() -> Self {
        Self {
            min: 0,
            max: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_grid_range_new() { let _ = GridRange::new(); }
}
