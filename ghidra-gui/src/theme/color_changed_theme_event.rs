//! Port of `ColorChangedThemeEvent`.
use std::collections::HashMap;
/// Struct porting `ColorChangedThemeEvent`.
#[derive(Debug, Clone)]
pub struct ColorChangedThemeEvent {
    _phantom: std::marker::PhantomData<()>,
}
impl ColorChangedThemeEvent {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ColorChangedThemeEvent {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_color_changed_theme_event_new() { let _ = ColorChangedThemeEvent::new(); }
}
