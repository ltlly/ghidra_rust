//! Port of `SFOverviewInfo`.
use std::collections::HashMap;
/// Struct porting `SFOverviewInfo`.
#[derive(Debug, Clone)]
pub struct SFOverviewInfo {
    /// default_queries_per_stage.
    pub default_queries_per_stage: i32,
}

impl SFOverviewInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for SFOverviewInfo {
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
    fn test_sf_overview_info_new() { let _ = SFOverviewInfo::new(); }
}
