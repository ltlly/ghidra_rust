//! Port of `SFQueryInfo`.
use std::collections::HashMap;
/// Struct porting `SFQueryInfo`.
#[derive(Debug, Clone)]
pub struct SFQueryInfo {
    /// default_queries_per_stage.
    pub default_queries_per_stage: i32,
}

impl SFQueryInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for SFQueryInfo {
    fn default() -> Self {
        Self {
            default_queries_per_stage: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sf_query_info_new() { let _ = SFQueryInfo::new(); }
}
