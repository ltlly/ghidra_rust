//! Port of `GraphType`.
use std::collections::HashMap;
/// Struct porting `GraphType`.
#[derive(Debug, Clone)]
pub struct GraphType {
    _phantom: std::marker::PhantomData<()>,
}
impl GraphType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GraphType {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_graph_type_new() { let _ = GraphType::new(); }
}
