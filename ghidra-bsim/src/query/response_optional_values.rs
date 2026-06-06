//! Port of `ResponseOptionalValues`.
use std::collections::HashMap;
/// Struct porting `ResponseOptionalValues`.
#[derive(Debug, Clone)]
pub struct ResponseOptionalValues {
    /// result_array.
    pub result_array: String,
    /// table_exists.
    pub table_exists: bool,
}

impl ResponseOptionalValues {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseOptionalValues {
    fn default() -> Self {
        Self {
            result_array: String::new(),
            table_exists: false,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_optional_values_new() { let _ = ResponseOptionalValues::new(); }
}
