//! Port of `SignatureRecord`.
use std::collections::HashMap;
/// Struct porting `SignatureRecord`.
#[derive(Debug, Clone)]
pub struct SignatureRecord {
    _phantom: std::marker::PhantomData<()>,
}
impl SignatureRecord {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SignatureRecord {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_signature_record_new() { let _ = SignatureRecord::new(); }
}
