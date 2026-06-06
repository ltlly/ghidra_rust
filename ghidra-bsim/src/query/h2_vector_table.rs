//! Port of `H2VectorTable`.
use std::collections::HashMap;
/// Struct porting `H2VectorTable`.
#[derive(Debug, Clone)]
pub struct H2VectorTable {
    /// table_name.
    pub table_name: String,
}

impl H2VectorTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for H2VectorTable {
    fn default() -> Self {
        Self {
            table_name: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_h2_vector_table_new() { let _ = H2VectorTable::new(); }
}
