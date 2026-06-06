//! Port of `ResponsePassword`.
use std::collections::HashMap;
/// Struct porting `ResponsePassword`.
#[derive(Debug, Clone)]
pub struct ResponsePassword {
    /// change_successful.
    pub change_successful: bool,
    /// error_message.
    pub error_message: String,
}

impl ResponsePassword {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponsePassword {
    fn default() -> Self {
        Self {
            change_successful: false,
            error_message: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_password_new() { let _ = ResponsePassword::new(); }
}
