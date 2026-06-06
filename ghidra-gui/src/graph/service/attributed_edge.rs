//! Port of `AttributedEdge`.
use std::collections::HashMap;
/// Struct porting `AttributedEdge`.
#[derive(Debug, Clone)]
pub struct AttributedEdge {
    /// edge_type_key.
    pub edge_type_key: String,
}

impl AttributedEdge {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for AttributedEdge {
    fn default() -> Self {
        Self {
            edge_type_key: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_attributed_edge_new() { let _ = AttributedEdge::new(); }
}
