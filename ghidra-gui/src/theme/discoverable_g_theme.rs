//! Port of `DiscoverableGTheme`.
use std::collections::HashMap;
/// Struct porting `DiscoverableGTheme`.
#[derive(Debug, Clone)]
pub struct DiscoverableGTheme {
    _phantom: std::marker::PhantomData<()>,
}
impl DiscoverableGTheme {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DiscoverableGTheme {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_discoverable_g_theme_new() { let _ = DiscoverableGTheme::new(); }
}
