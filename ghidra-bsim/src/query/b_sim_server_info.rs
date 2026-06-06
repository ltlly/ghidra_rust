//! Port of `BSimServerInfo`.
use std::collections::HashMap;
/// Struct porting `BSimServerInfo`.
#[derive(Debug, Clone)]
pub struct BSimServerInfo {
    /// default_postgres_port.
    pub default_postgres_port: i32,
    /// default_elastic_port.
    pub default_elastic_port: i32,
    /// h2_file_extension.
    pub h2_file_extension: String,
}

impl BSimServerInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for BSimServerInfo {
    fn default() -> Self {
        Self {
            default_postgres_port: 0,
            default_elastic_port: 0,
            h2_file_extension: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_server_info_new() { let _ = BSimServerInfo::new(); }
}
