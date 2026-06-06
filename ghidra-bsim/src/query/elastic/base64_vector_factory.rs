//! Port of `Base64VectorFactory`.
use std::collections::HashMap;
/// Struct porting `Base64VectorFactory`.
#[derive(Debug, Clone)]
pub struct Base64VectorFactory {
    _phantom: std::marker::PhantomData<()>,
}
impl Base64VectorFactory {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for Base64VectorFactory {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_base64_vector_factory_new() { let _ = Base64VectorFactory::new(); }
}
