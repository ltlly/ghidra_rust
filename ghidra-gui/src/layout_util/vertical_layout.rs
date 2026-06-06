//! Port of `VerticalLayout`.
use std::collections::HashMap;
/// Struct porting `VerticalLayout`.
#[derive(Debug, Clone)]
pub struct VerticalLayout {
    _phantom: std::marker::PhantomData<()>,
}
impl VerticalLayout {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VerticalLayout {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vertical_layout_new() { let _ = VerticalLayout::new(); }
}
