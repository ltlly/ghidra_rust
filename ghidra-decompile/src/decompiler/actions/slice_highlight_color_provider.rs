//! Port of `SliceHighlightColorProvider`.
use std::collections::HashMap;
/// Struct porting `SliceHighlightColorProvider`.
#[derive(Debug, Clone)]
pub struct SliceHighlightColorProvider {
    _phantom: std::marker::PhantomData<()>,
}
impl SliceHighlightColorProvider {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SliceHighlightColorProvider {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_slice_highlight_color_provider_new() { let _ = SliceHighlightColorProvider::new(); }
}
