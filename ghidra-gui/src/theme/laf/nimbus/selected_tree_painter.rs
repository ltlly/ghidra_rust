//! Port of `SelectedTreePainter`.
use std::collections::HashMap;
/// Struct porting `SelectedTreePainter`.
#[derive(Debug, Clone)]
pub struct SelectedTreePainter {
    _phantom: std::marker::PhantomData<()>,
}
impl SelectedTreePainter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SelectedTreePainter {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_selected_tree_painter_new() { let _ = SelectedTreePainter::new(); }
}
