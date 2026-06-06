//! Port of `DefaultGEdge`.
use std::collections::HashMap;
/// Struct porting `DefaultGEdge`.
#[derive(Debug, Clone)]
pub struct DefaultGEdge {
    _phantom: std::marker::PhantomData<()>,
}
impl DefaultGEdge {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DefaultGEdge {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_g_edge_new() { let _ = DefaultGEdge::new(); }
}
