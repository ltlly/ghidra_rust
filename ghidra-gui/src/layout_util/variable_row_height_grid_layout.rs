//! Port of `VariableRowHeightGridLayout`.
use std::collections::HashMap;
/// Struct porting `VariableRowHeightGridLayout`.
#[derive(Debug, Clone)]
pub struct VariableRowHeightGridLayout {
    _phantom: std::marker::PhantomData<()>,
}
impl VariableRowHeightGridLayout {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VariableRowHeightGridLayout {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_variable_row_height_grid_layout_new() { let _ = VariableRowHeightGridLayout::new(); }
}
