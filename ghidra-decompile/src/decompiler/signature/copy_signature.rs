//! Port of `CopySignature`.
use std::collections::HashMap;
/// Struct porting `CopySignature`.
#[derive(Debug, Clone)]
pub struct CopySignature {
    /// index
    pub index: i32,
}
impl CopySignature {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CopySignature {
    fn default() -> Self {
        Self {
            index: 0
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_copy_signature_new() { let _ = CopySignature::new(); }
}
