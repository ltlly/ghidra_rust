//! Port of `AttributedVertex`.
use std::collections::HashMap;
/// Struct porting `AttributedVertex`.
#[derive(Debug, Clone)]
pub struct AttributedVertex {
    /// name_key.
    pub name_key: String,
    /// vertex_type_key.
    pub vertex_type_key: String,
}

impl AttributedVertex {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for AttributedVertex {
    fn default() -> Self {
        Self {
            name_key: String::new(),
            vertex_type_key: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_attributed_vertex_new() { let _ = AttributedVertex::new(); }
}
