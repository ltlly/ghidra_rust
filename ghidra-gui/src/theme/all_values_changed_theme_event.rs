//! Port of `AllValuesChangedThemeEvent`.
use std::collections::HashMap;
/// Struct porting `AllValuesChangedThemeEvent`.
#[derive(Debug, Clone)]
pub struct AllValuesChangedThemeEvent {
    _phantom: std::marker::PhantomData<()>,
}
impl AllValuesChangedThemeEvent {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for AllValuesChangedThemeEvent {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_all_values_changed_theme_event_new() { let _ = AllValuesChangedThemeEvent::new(); }
}
