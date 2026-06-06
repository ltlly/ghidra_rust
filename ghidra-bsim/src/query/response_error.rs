//! Port of `ResponseError`.
use std::collections::HashMap;
/// Struct porting `ResponseError`.
#[derive(Debug, Clone)]
pub struct ResponseError {
    /// error_message.
    pub error_message: String,
}

impl ResponseError {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseError {
    fn default() -> Self {
        Self {
            error_message: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_error_new() { let _ = ResponseError::new(); }
}
