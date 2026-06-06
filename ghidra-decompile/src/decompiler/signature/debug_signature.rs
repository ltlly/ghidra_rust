//! Port of `DebugSignature`.
use std::collections::HashMap;
/// Struct porting `DebugSignature`.
#[derive(Debug, Clone)]
pub struct DebugSignature {
    /// hash
    pub hash: i32,
}
impl DebugSignature {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DebugSignature {
    fn default() -> Self {
        Self {
            hash: 0
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_debug_signature_new() { let _ = DebugSignature::new(); }
}
