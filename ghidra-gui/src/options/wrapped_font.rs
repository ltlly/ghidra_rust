//! Port of `WrappedFont`.
use std::collections::HashMap;
/// Struct porting `WrappedFont`.
#[derive(Debug, Clone)]
pub struct WrappedFont {
    _phantom: std::marker::PhantomData<()>,
}
impl WrappedFont {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WrappedFont {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wrapped_font_new() { let _ = WrappedFont::new(); }
}
