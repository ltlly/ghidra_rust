//! Port of `QueryNearestVector`.
use std::collections::HashMap;
/// Struct porting `QueryNearestVector`.
#[derive(Debug, Clone)]
pub struct QueryNearestVector {
    /// manage.
    pub manage: String,
    /// nearresponse.
    pub nearresponse: String,
    /// thresh.
    pub thresh: f64,
    /// signifthresh.
    pub signifthresh: f64,
    /// vectormax.
    pub vectormax: i32,
}

impl QueryNearestVector {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for QueryNearestVector {
    fn default() -> Self {
        Self {
            manage: String::new(),
            nearresponse: String::new(),
            thresh: 0,
            signifthresh: 0,
            vectormax: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_query_nearest_vector_new() { let _ = QueryNearestVector::new(); }
}
