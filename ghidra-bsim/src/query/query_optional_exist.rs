//! Port of `QueryOptionalExist`.
use std::collections::HashMap;
/// Struct porting `QueryOptionalExist`.
#[derive(Debug, Clone)]
pub struct QueryOptionalExist {
    /// optionalresponse.
    pub optionalresponse: String,
    /// table_name.
    pub table_name: String,
    /// key_type.
    pub key_type: i32,
    /// value_type.
    pub value_type: i32,
    /// attempt_creation.
    pub attempt_creation: bool,
    /// clear_table.
    pub clear_table: bool,
}

impl QueryOptionalExist {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for QueryOptionalExist {
    fn default() -> Self {
        Self {
            optionalresponse: String::new(),
            table_name: String::new(),
            key_type_: 0,
            value_type_: 0,
            attempt_creation: false,
            clear_table: false,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_query_optional_exist_new() { let _ = QueryOptionalExist::new(); }
}
