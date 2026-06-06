//! Port of `ResponseAdjustIndex`.
use std::collections::HashMap;
/// Struct porting `ResponseAdjustIndex`.
#[derive(Debug, Clone)]
pub struct ResponseAdjustIndex {
    /// success.
    pub success: bool,
    /// operation_supported.
    pub operation_supported: bool,
}

impl ResponseAdjustIndex {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseAdjustIndex {
    fn default() -> Self {
        Self {
            success: false,
            operation_supported: false,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_adjust_index_new() { let _ = ResponseAdjustIndex::new(); }
}
