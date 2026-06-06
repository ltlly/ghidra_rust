//! Port of `FlatLightTheme`.
use std::collections::HashMap;
/// Struct porting `FlatLightTheme`.
#[derive(Debug, Clone)]
pub struct FlatLightTheme {
    _phantom: std::marker::PhantomData<()>,
}
impl FlatLightTheme {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FlatLightTheme {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_flat_light_theme_new() { let _ = FlatLightTheme::new(); }
}
