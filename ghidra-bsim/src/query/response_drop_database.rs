//! Port of `ResponseDropDatabase`.
use std::collections::HashMap;
/// Struct porting `ResponseDropDatabase`.
#[derive(Debug, Clone)]
pub struct ResponseDropDatabase {
    /// operation_supported.
    pub operation_supported: bool,
    /// drop_successful.
    pub drop_successful: bool,
    /// error_message.
    pub error_message: String,
}

impl ResponseDropDatabase {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseDropDatabase {
    fn default() -> Self {
        Self {
            operation_supported: false,
            drop_successful: false,
            error_message: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_drop_database_new() { let _ = ResponseDropDatabase::new(); }
}
