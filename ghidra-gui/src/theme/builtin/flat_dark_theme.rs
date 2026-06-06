//! Port of `FlatDarkTheme`.
use std::collections::HashMap;
/// Struct porting `FlatDarkTheme`.
#[derive(Debug, Clone)]
pub struct FlatDarkTheme {
    _phantom: std::marker::PhantomData<()>,
}
impl FlatDarkTheme {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FlatDarkTheme {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_flat_dark_theme_new() { let _ = FlatDarkTheme::new(); }
}
