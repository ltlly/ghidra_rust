//! Port of `BSimQuery`.
use std::collections::HashMap;
/// Struct porting `BSimQuery`.
#[derive(Debug, Clone)]
pub struct BSimQuery {
    /// name.
    pub name: String,
    /// response.
    pub response: String,
}

impl BSimQuery {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for BSimQuery {
    fn default() -> Self {
        Self {
            name: String::new(),
            response: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_query_new() { let _ = BSimQuery::new(); }
}
