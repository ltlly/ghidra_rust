//! Port of `StretchLayout`.
use std::collections::HashMap;
/// Struct porting `StretchLayout`.
#[derive(Debug, Clone)]
pub struct StretchLayout {
    _phantom: std::marker::PhantomData<()>,
}
impl StretchLayout {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for StretchLayout {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_stretch_layout_new() { let _ = StretchLayout::new(); }
}
