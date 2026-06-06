//! Port of `IconChangedThemeEvent`.
use std::collections::HashMap;
/// Struct porting `IconChangedThemeEvent`.
#[derive(Debug, Clone)]
pub struct IconChangedThemeEvent {
    _phantom: std::marker::PhantomData<()>,
}
impl IconChangedThemeEvent {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for IconChangedThemeEvent {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_icon_changed_theme_event_new() { let _ = IconChangedThemeEvent::new(); }
}
