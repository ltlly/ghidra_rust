//! Port of `DatabaseInformation`.
use std::collections::HashMap;
/// Struct porting `DatabaseInformation`.
#[derive(Debug, Clone)]
pub struct DatabaseInformation {
    /// databasename.
    pub databasename: String,
    /// owner.
    pub owner: String,
    /// description.
    pub description: String,
    /// major.
    pub major: String,
    /// minor.
    pub minor: String,
    /// settings.
    pub settings: i32,
}

impl DatabaseInformation {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for DatabaseInformation {
    fn default() -> Self {
        Self {
            databasename: String::new(),
            owner: String::new(),
            description: String::new(),
            major: String::new(),
            minor: String::new(),
            settings: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_database_information_new() { let _ = DatabaseInformation::new(); }
}
