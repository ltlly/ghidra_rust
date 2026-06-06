//! Port of `HorizontalLayout`.
use std::collections::HashMap;
/// Struct porting `HorizontalLayout`.
#[derive(Debug, Clone)]
pub struct HorizontalLayout {
    _phantom: std::marker::PhantomData<()>,
}
impl HorizontalLayout {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for HorizontalLayout {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_horizontal_layout_new() { let _ = HorizontalLayout::new(); }
}
