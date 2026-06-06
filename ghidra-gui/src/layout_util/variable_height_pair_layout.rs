//! Port of `VariableHeightPairLayout`.
use std::collections::HashMap;
/// Struct porting `VariableHeightPairLayout`.
#[derive(Debug, Clone)]
pub struct VariableHeightPairLayout {
    _phantom: std::marker::PhantomData<()>,
}
impl VariableHeightPairLayout {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VariableHeightPairLayout {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_variable_height_pair_layout_new() { let _ = VariableHeightPairLayout::new(); }
}
