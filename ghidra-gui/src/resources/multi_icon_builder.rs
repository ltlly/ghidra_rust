//! Port of `MultiIconBuilder`.
use std::collections::HashMap;
/// Struct porting `MultiIconBuilder`.
#[derive(Debug, Clone)]
pub struct MultiIconBuilder {
    _phantom: std::marker::PhantomData<()>,
}
impl MultiIconBuilder {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MultiIconBuilder {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_multi_icon_builder_new() { let _ = MultiIconBuilder::new(); }
}
