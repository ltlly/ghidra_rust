//! Port of `WrappedKeyStroke`.
use std::collections::HashMap;
/// Struct porting `WrappedKeyStroke`.
#[derive(Debug, Clone)]
pub struct WrappedKeyStroke {
    _phantom: std::marker::PhantomData<()>,
}
impl WrappedKeyStroke {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WrappedKeyStroke {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wrapped_key_stroke_new() { let _ = WrappedKeyStroke::new(); }
}
