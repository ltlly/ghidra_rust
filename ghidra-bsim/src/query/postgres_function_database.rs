//! Port of `PostgresFunctionDatabase`.
use std::collections::HashMap;
/// Struct porting `PostgresFunctionDatabase`.
#[derive(Debug, Clone)]
pub struct PostgresFunctionDatabase {
    /// layout_version.
    pub layout_version: i32,
}

impl PostgresFunctionDatabase {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for PostgresFunctionDatabase {
    fn default() -> Self {
        Self {
            layout_version: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_postgres_function_database_new() { let _ = PostgresFunctionDatabase::new(); }
}
