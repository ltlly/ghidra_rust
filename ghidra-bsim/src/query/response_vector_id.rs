//! Port of `ResponseVectorId`.
use std::collections::HashMap;
/// Struct porting `ResponseVectorId`.
#[derive(Debug, Clone)]
pub struct ResponseVectorId {
    /// vector_results.
    pub vector_results: String,
}

impl ResponseVectorId {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseVectorId {
    fn default() -> Self {
        Self {
            vector_results: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_vector_id_new() { let _ = ResponseVectorId::new(); }
}
