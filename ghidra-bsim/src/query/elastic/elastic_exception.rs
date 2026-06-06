//! Port of `ElasticException`.
use std::collections::HashMap;
/// Struct porting `ElasticException`.
#[derive(Debug, Clone)]
pub struct ElasticException {
    _phantom: std::marker::PhantomData<()>,
}
impl ElasticException {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ElasticException {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_elastic_exception_new() { let _ = ElasticException::new(); }
}
