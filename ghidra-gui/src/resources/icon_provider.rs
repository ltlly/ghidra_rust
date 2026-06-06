//! Port of `IconProvider`.
use std::collections::HashMap;
/// Struct porting `IconProvider`.
#[derive(Debug, Clone)]
pub struct IconProvider {
    _phantom: std::marker::PhantomData<()>,
}
impl IconProvider {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for IconProvider {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_icon_provider_new() { let _ = IconProvider::new(); }
}
