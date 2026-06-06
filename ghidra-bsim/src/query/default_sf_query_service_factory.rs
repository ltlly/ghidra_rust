//! Port of `DefaultSFQueryServiceFactory`.
use std::collections::HashMap;
/// Struct porting `DefaultSFQueryServiceFactory`.
#[derive(Debug, Clone)]
pub struct DefaultSFQueryServiceFactory {
    _phantom: std::marker::PhantomData<()>,
}
impl DefaultSFQueryServiceFactory {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DefaultSFQueryServiceFactory {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_sf_query_service_factory_new() { let _ = DefaultSFQueryServiceFactory::new(); }
}
