//! Port of `Row`.
use std::collections::HashMap;
/// Struct porting `Row`.
#[derive(Debug, Clone)]
pub struct Row {
    /// y.
    pub y: i32,
    /// height.
    pub height: i32,
    /// index.
    pub index: i32,
}

impl Row {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for Row {
    fn default() -> Self {
        Self {
            y: 0,
            height: 0,
            index: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_row_new() { let _ = Row::new(); }
}
