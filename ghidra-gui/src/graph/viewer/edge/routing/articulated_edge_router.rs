//! Port of `ArticulatedEdgeRouter`.
use std::collections::HashMap;
/// Struct porting `ArticulatedEdgeRouter`.
#[derive(Debug, Clone)]
pub struct ArticulatedEdgeRouter {
    _phantom: std::marker::PhantomData<()>,
}
impl ArticulatedEdgeRouter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ArticulatedEdgeRouter {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_articulated_edge_router_new() { let _ = ArticulatedEdgeRouter::new(); }
}
