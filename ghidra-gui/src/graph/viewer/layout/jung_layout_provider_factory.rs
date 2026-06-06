//! Port of `JungLayoutProviderFactory`.
use std::collections::HashMap;
/// Struct porting `JungLayoutProviderFactory`.
#[derive(Debug, Clone)]
pub struct JungLayoutProviderFactory {
    _phantom: std::marker::PhantomData<()>,
}
impl JungLayoutProviderFactory {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for JungLayoutProviderFactory {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_jung_layout_provider_factory_new() { let _ = JungLayoutProviderFactory::new(); }
}
