//! Port of `NimbusTheme`.
use std::collections::HashMap;
/// Struct porting `NimbusTheme`.
#[derive(Debug, Clone)]
pub struct NimbusTheme {
    _phantom: std::marker::PhantomData<()>,
}
impl NimbusTheme {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for NimbusTheme {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_nimbus_theme_new() { let _ = NimbusTheme::new(); }
}
