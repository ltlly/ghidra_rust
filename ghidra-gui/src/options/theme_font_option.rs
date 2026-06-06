//! Port of `ThemeFontOption`.
use std::collections::HashMap;
/// Struct porting `ThemeFontOption`.
#[derive(Debug, Clone)]
pub struct ThemeFontOption {
    _phantom: std::marker::PhantomData<()>,
}
impl ThemeFontOption {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ThemeFontOption {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_theme_font_option_new() { let _ = ThemeFontOption::new(); }
}
