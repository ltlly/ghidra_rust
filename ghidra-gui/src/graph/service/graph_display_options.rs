//! Port of `GraphDisplayOptions`.
use std::collections::HashMap;
/// Struct porting `GraphDisplayOptions`.
#[derive(Debug, Clone)]
pub struct GraphDisplayOptions {
    _phantom: std::marker::PhantomData<()>,
}
impl GraphDisplayOptions {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GraphDisplayOptions {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_graph_display_options_new() { let _ = GraphDisplayOptions::new(); }
}
