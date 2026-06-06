//! Port of `QueryOptionalValues`.
use std::collections::HashMap;
/// Struct porting `QueryOptionalValues`.
#[derive(Debug, Clone)]
pub struct QueryOptionalValues {
    /// optionalresponse.
    pub optionalresponse: String,
    /// keys.
    pub keys: String,
    /// table_name.
    pub table_name: String,
    /// key_type.
    pub key_type: i32,
    /// value_type.
    pub value_type: i32,
}

impl QueryOptionalValues {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for QueryOptionalValues {
    fn default() -> Self {
        Self {
            optionalresponse: String::new(),
            keys: String::new(),
            table_name: String::new(),
            key_type_: 0,
            value_type_: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_query_optional_values_new() { let _ = QueryOptionalValues::new(); }
}
