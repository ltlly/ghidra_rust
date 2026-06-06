//! Port of `MetalTheme`.
use std::collections::HashMap;
/// Struct porting `MetalTheme`.
#[derive(Debug, Clone)]
pub struct MetalTheme {
    _phantom: std::marker::PhantomData<()>,
}
impl MetalTheme {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MetalTheme {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_metal_theme_new() { let _ = MetalTheme::new(); }
}
