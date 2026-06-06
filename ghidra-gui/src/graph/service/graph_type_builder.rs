//! Port of `GraphTypeBuilder`.
use std::collections::HashMap;
/// Struct porting `GraphTypeBuilder`.
#[derive(Debug, Clone)]
pub struct GraphTypeBuilder {
    _phantom: std::marker::PhantomData<()>,
}
impl GraphTypeBuilder {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GraphTypeBuilder {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_graph_type_builder_new() { let _ = GraphTypeBuilder::new(); }
}
