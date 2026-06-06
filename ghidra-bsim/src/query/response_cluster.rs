//! Port of `ResponseCluster`.
use std::collections::HashMap;
/// Struct porting `ResponseCluster`.
#[derive(Debug, Clone)]
pub struct ResponseCluster {
    /// notes.
    pub notes: String,
    /// query.
    pub query: String,
}

impl ResponseCluster {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseCluster {
    fn default() -> Self {
        Self {
            notes: String::new(),
            query: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_cluster_new() { let _ = ResponseCluster::new(); }
}
