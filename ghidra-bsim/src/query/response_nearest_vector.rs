//! Port of `ResponseNearestVector`.
use std::collections::HashMap;
/// Struct porting `ResponseNearestVector`.
#[derive(Debug, Clone)]
pub struct ResponseNearestVector {
    /// totalvec.
    pub totalvec: i32,
    /// totalmatch.
    pub totalmatch: i32,
    /// uniquematch.
    pub uniquematch: i32,
    /// result.
    pub result: String,
    /// qnear.
    pub qnear: String,
}

impl ResponseNearestVector {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseNearestVector {
    fn default() -> Self {
        Self {
            totalvec: 0,
            totalmatch: 0,
            uniquematch: 0,
            result: String::new(),
            qnear: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_nearest_vector_new() { let _ = ResponseNearestVector::new(); }
}
