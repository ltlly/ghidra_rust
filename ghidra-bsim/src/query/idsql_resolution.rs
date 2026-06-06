//! Port of `IDSQLResolution`.
use std::collections::HashMap;
/// Struct porting `IDSQLResolution`.
#[derive(Debug, Clone)]
pub struct IDSQLResolution {
    /// id1.
    pub id1: i64,
    /// id2.
    pub id2: i64,
}

impl IDSQLResolution {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for IDSQLResolution {
    fn default() -> Self {
        Self {
            id1: 0,
            id2: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_idsql_resolution_new() { let _ = IDSQLResolution::new(); }
}
