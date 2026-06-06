//! Port of `QueryVectorId`.
use std::collections::HashMap;
/// Struct porting `QueryVectorId`.
#[derive(Debug, Clone)]
pub struct QueryVectorId {
    /// vector_ids.
    pub vector_ids: String,
    /// vector_id_response.
    pub vector_id_response: String,
}

impl QueryVectorId {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for QueryVectorId {
    fn default() -> Self {
        Self {
            vector_ids: String::new(),
            vector_id_response: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_query_vector_id_new() { let _ = QueryVectorId::new(); }
}
