//! Port of `ThemeColorOption`.
use std::collections::HashMap;
/// Struct porting `ThemeColorOption`.
#[derive(Debug, Clone)]
pub struct ThemeColorOption {
    _phantom: std::marker::PhantomData<()>,
}
impl ThemeColorOption {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ThemeColorOption {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_theme_color_option_new() { let _ = ThemeColorOption::new(); }
}
