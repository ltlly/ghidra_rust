//! Port of `FontChangedThemeEvent`.
use std::collections::HashMap;
/// Struct porting `FontChangedThemeEvent`.
#[derive(Debug, Clone)]
pub struct FontChangedThemeEvent {
    _phantom: std::marker::PhantomData<()>,
}
impl FontChangedThemeEvent {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FontChangedThemeEvent {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_font_changed_theme_event_new() { let _ = FontChangedThemeEvent::new(); }
}
