//! Port of `QueryVectorMatch`.
use std::collections::HashMap;
/// Struct porting `QueryVectorMatch`.
#[derive(Debug, Clone)]
pub struct QueryVectorMatch {
    /// default_max_functions.
    pub default_max_functions: i32,
    /// matchresponse.
    pub matchresponse: String,
    /// max.
    pub max: i32,
    /// fillin_categories.
    pub fillin_categories: bool,
    /// bsim_filter.
    pub bsim_filter: String,
    /// vector_ids.
    pub vector_ids: String,
}

impl QueryVectorMatch {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for QueryVectorMatch {
    fn default() -> Self {
        Self {
            default_max_functions: 0,
            matchresponse: String::new(),
            max: 0,
            fillin_categories: false,
            bsim_filter: String::new(),
            vector_ids: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_query_vector_match_new() { let _ = QueryVectorMatch::new(); }
}
