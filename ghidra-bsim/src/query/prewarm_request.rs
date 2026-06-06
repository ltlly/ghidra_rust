//! Port of `PrewarmRequest`.
use std::collections::HashMap;
/// Struct porting `PrewarmRequest`.
#[derive(Debug, Clone)]
pub struct PrewarmRequest {
    /// main_index_config.
    pub main_index_config: i32,
    /// secondary_index_config.
    pub secondary_index_config: i32,
    /// vector_table_config.
    pub vector_table_config: i32,
    /// prewarmresponse.
    pub prewarmresponse: String,
}

impl PrewarmRequest {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for PrewarmRequest {
    fn default() -> Self {
        Self {
            main_index_config: 0,
            secondary_index_config: 0,
            vector_table_config: 0,
            prewarmresponse: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_prewarm_request_new() { let _ = PrewarmRequest::new(); }
}
