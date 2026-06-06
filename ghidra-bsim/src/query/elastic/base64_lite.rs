//! Port of `Base64Lite`.
use std::collections::HashMap;
/// Struct porting `Base64Lite`.
#[derive(Debug, Clone)]
pub struct Base64Lite {
    /// encode.
    pub encode: String,
    /// decode.
    pub decode: String,
}

impl Base64Lite {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for Base64Lite {
    fn default() -> Self {
        Self {
            encode: String::new(),
            decode: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_base64_lite_new() { let _ = Base64Lite::new(); }
}
