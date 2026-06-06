//! Port of `WrappedColor`.
use std::collections::HashMap;
/// Struct porting `WrappedColor`.
#[derive(Debug, Clone)]
pub struct WrappedColor {
    _phantom: std::marker::PhantomData<()>,
}
impl WrappedColor {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WrappedColor {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wrapped_color_new() { let _ = WrappedColor::new(); }
}
