//! Port of `BlockSignature`.
use std::collections::HashMap;
/// Struct porting `BlockSignature`.
#[derive(Debug, Clone)]
pub struct BlockSignature {
    /// blockSeq
    pub block_seq: String,
    /// index
    pub index: i32,
    /// opSeq
    pub op_seq: String,
    /// opcode
    pub opcode: String,
    /// previousOpSeq
    pub previous_op_seq: String,
    /// previousOpcode
    pub previous_opcode: String,
}
impl BlockSignature {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BlockSignature {
    fn default() -> Self {
        Self {
            block_seq: String::new(),
            index: 0,
            op_seq: String::new(),
            opcode: String::new(),
            previous_op_seq: String::new(),
            previous_opcode: String::new()
        }
    }


}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_block_signature_new() { let _ = BlockSignature::new(); }
}
