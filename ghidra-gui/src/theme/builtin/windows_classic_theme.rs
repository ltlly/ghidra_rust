//! Port of `WindowsClassicTheme`.
use std::collections::HashMap;
/// Struct porting `WindowsClassicTheme`.
#[derive(Debug, Clone)]
pub struct WindowsClassicTheme {
    _phantom: std::marker::PhantomData<()>,
}
impl WindowsClassicTheme {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WindowsClassicTheme {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_windows_classic_theme_new() { let _ = WindowsClassicTheme::new(); }
}
