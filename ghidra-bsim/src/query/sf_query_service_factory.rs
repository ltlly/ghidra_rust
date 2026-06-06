//! Port of `SFQueryServiceFactory`.
use std::collections::HashMap;
/// Struct porting `SFQueryServiceFactory`.
#[derive(Debug, Clone)]
pub struct SFQueryServiceFactory {
    _phantom: std::marker::PhantomData<()>,
}
impl SFQueryServiceFactory {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SFQueryServiceFactory {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sf_query_service_factory_new() { let _ = SFQueryServiceFactory::new(); }
}
