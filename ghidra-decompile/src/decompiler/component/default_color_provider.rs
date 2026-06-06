//! Port of `DefaultColorProvider`.
use std::collections::HashMap;
/// Struct porting `DefaultColorProvider`.
#[derive(Debug, Clone)]
pub struct DefaultColorProvider {
    _phantom: std::marker::PhantomData<()>,
}
impl DefaultColorProvider {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DefaultColorProvider {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_color_provider_new() { let _ = DefaultColorProvider::new(); }
}
