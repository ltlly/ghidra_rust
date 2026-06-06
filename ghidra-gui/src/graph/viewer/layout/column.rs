//! Port of `Column`.
use std::collections::HashMap;
/// Struct porting `Column`.
#[derive(Debug, Clone)]
pub struct Column {
    /// x.
    pub x: i32,
    /// width.
    pub width: i32,
    /// index.
    pub index: i32,
}

impl Column {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for Column {
    fn default() -> Self {
        Self {
            x: 0,
            width: 0,
            index: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_column_new() { let _ = Column::new(); }
}
