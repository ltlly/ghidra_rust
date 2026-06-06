//! Port of `ResponseInfo`.
use std::collections::HashMap;
/// Struct porting `ResponseInfo`.
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    /// info.
    pub info: String,
}

impl ResponseInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseInfo {
    fn default() -> Self {
        Self {
            info: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_info_new() { let _ = ResponseInfo::new(); }
}
