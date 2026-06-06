//! Port of `ResponseOptionalExist`.
use std::collections::HashMap;
/// Struct porting `ResponseOptionalExist`.
#[derive(Debug, Clone)]
pub struct ResponseOptionalExist {
    /// table_exists.
    pub table_exists: bool,
    /// was_created.
    pub was_created: bool,
}

impl ResponseOptionalExist {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseOptionalExist {
    fn default() -> Self {
        Self {
            table_exists: false,
            was_created: false,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_optional_exist_new() { let _ = ResponseOptionalExist::new(); }
}
