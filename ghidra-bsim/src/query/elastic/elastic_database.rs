//! Port of `ElasticDatabase`.
use std::collections::HashMap;
/// Struct porting `ElasticDatabase`.
#[derive(Debug, Clone)]
pub struct ElasticDatabase {
    /// layout_version.
    pub layout_version: i32,
    /// max_vector_overall.
    pub max_vector_overall: i32,
    /// max_function_window.
    pub max_function_window: i32,
    /// max_functionupdate_window.
    pub max_functionupdate_window: i32,
    /// max_vectorcount_window.
    pub max_vectorcount_window: i32,
    /// max_vectordelete_window.
    pub max_vectordelete_window: i32,
}

impl ElasticDatabase {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ElasticDatabase {
    fn default() -> Self {
        Self {
            layout_version: 0,
            max_vector_overall: 0,
            max_function_window: 0,
            max_functionupdate_window: 0,
            max_vectorcount_window: 0,
            max_vectordelete_window: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_elastic_database_new() { let _ = ElasticDatabase::new(); }
}
