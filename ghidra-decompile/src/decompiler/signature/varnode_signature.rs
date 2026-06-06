//! Port of `VarnodeSignature`.
use std::collections::HashMap;
/// Struct porting `VarnodeSignature`.
#[derive(Debug, Clone)]
pub struct VarnodeSignature {
    /// vn
    pub vn: String,
    /// seqNum
    pub seq_num: String,
    /// opcode
    pub opcode: String,
}
impl VarnodeSignature {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VarnodeSignature {
    fn default() -> Self {
        Self {
            vn: String::new(),
            seq_num: String::new(),
            opcode: String::new()
        }


}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_varnode_signature_new() { let _ = VarnodeSignature::new(); }
}
