//! Port of `GraphDisplayOptionsBuilder`.
use std::collections::HashMap;
/// Struct porting `GraphDisplayOptionsBuilder`.
#[derive(Debug, Clone)]
pub struct GraphDisplayOptionsBuilder {
    _phantom: std::marker::PhantomData<()>,
}
impl GraphDisplayOptionsBuilder {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GraphDisplayOptionsBuilder {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_graph_display_options_builder_new() { let _ = GraphDisplayOptionsBuilder::new(); }
}
