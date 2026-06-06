//! Port of `ColumnLayout`.
use std::collections::HashMap;
/// Struct porting `ColumnLayout`.
#[derive(Debug, Clone)]
pub struct ColumnLayout {
    _phantom: std::marker::PhantomData<()>,
}
impl ColumnLayout {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ColumnLayout {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_column_layout_new() { let _ = ColumnLayout::new(); }
}
