//! Port of `ElasticConnection`.
use std::collections::HashMap;
/// Struct porting `ElasticConnection`.
#[derive(Debug, Clone)]
pub struct ElasticConnection {
    /// post.
    pub post: String,
    /// put.
    pub put: String,
    /// get.
    pub get: String,
    /// delete.
    pub delete: String,
    /// host_url.
    pub host_url: String,
    /// http_ur_lbase.
    pub http_ur_lbase: String,
}

impl ElasticConnection {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ElasticConnection {
    fn default() -> Self {
        Self {
            post: String::new(),
            put: String::new(),
            get: String::new(),
            delete: String::new(),
            host_url: String::new(),
            http_ur_lbase: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_elastic_connection_new() { let _ = ElasticConnection::new(); }
}
