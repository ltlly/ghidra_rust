//! Signature analysis for decompiled functions.
//!
//! Port of Ghidra's `ghidra.app.decompiler.signature` package.

/// A block signature capturing the p-code operations in a basic block.
#[derive(Debug, Clone)]
pub struct BlockSignature {
    /// Address of the block.
    pub address: u64,
    /// Size of the block in bytes.
    pub size: u32,
    /// Number of p-code operations in the block.
    pub op_count: usize,
    /// Hash of the block's p-code operations.
    pub hash: u64,
}

impl BlockSignature {
    /// Create a new BlockSignature.
    pub fn new(address: u64, size: u32, op_count: usize, hash: u64) -> Self {
        Self {
            address,
            size,
            op_count,
            hash,
        }
    }

    /// Whether this signature matches another block signature.
    pub fn matches(&self, other: &BlockSignature) -> bool {
        self.hash == other.hash && self.op_count == other.op_count
    }
}

/// A copy signature describing a data copy operation.
#[derive(Debug, Clone)]
pub struct CopySignature {
    /// Source address.
    pub source_address: u64,
    /// Destination address.
    pub dest_address: u64,
    /// Size of the copy in bytes.
    pub size: u32,
}

impl CopySignature {
    /// Create a new CopySignature.
    pub fn new(source_address: u64, dest_address: u64, size: u32) -> Self {
        Self {
            source_address,
            dest_address,
            size,
        }
    }
}

/// A varnode signature capturing a varnode's properties.
#[derive(Debug, Clone)]
pub struct VarnodeSignature {
    /// Space name.
    pub space: String,
    /// Offset in the space.
    pub offset: u64,
    /// Size in bytes.
    pub size: u32,
}

impl VarnodeSignature {
    /// Create a new VarnodeSignature.
    pub fn new(space: &str, offset: u64, size: u32) -> Self {
        Self {
            space: space.to_string(),
            offset,
            size,
        }
    }
}

/// Debug signature for a function (returned by DecompInterface::debug_signatures).
#[derive(Debug, Clone)]
pub struct DebugSignature {
    /// The function entry point.
    pub function_entry: u64,
    /// Block signatures.
    pub blocks: Vec<BlockSignature>,
    /// Copy signatures.
    pub copies: Vec<CopySignature>,
    /// Varnode signatures.
    pub varnodes: Vec<VarnodeSignature>,
    /// Raw XML response data.
    pub raw_data: Option<Vec<u8>>,
}

impl DebugSignature {
    /// Create a new DebugSignature.
    pub fn new(function_entry: u64) -> Self {
        Self {
            function_entry,
            blocks: Vec::new(),
            copies: Vec::new(),
            varnodes: Vec::new(),
            raw_data: None,
        }
    }

    /// Add a block signature.
    pub fn add_block(&mut self, block: BlockSignature) {
        self.blocks.push(block);
    }

    /// Add a copy signature.
    pub fn add_copy(&mut self, copy: CopySignature) {
        self.copies.push(copy);
    }

    /// Add a varnode signature.
    pub fn add_varnode(&mut self, vn: VarnodeSignature) {
        self.varnodes.push(vn);
    }
}

/// Result of a signature analysis.
#[derive(Debug, Clone)]
pub struct SignatureResult {
    /// The debug signature.
    pub signature: DebugSignature,
    /// Any error message.
    pub error_message: Option<String>,
}

impl SignatureResult {
    /// Create a successful result.
    pub fn success(signature: DebugSignature) -> Self {
        Self {
            signature,
            error_message: None,
        }
    }

    /// Create an error result.
    pub fn error(message: String) -> Self {
        Self {
            signature: DebugSignature::new(0),
            error_message: Some(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_signature() {
        let bs = BlockSignature::new(0x1000, 16, 5, 0xABCD);
        assert_eq!(bs.address, 0x1000);
        assert_eq!(bs.size, 16);
    }

    #[test]
    fn test_block_signature_matches() {
        let bs1 = BlockSignature::new(0x1000, 16, 5, 0xABCD);
        let bs2 = BlockSignature::new(0x2000, 16, 5, 0xABCD);
        let bs3 = BlockSignature::new(0x1000, 16, 5, 0x1234);
        assert!(bs1.matches(&bs2));
        assert!(!bs1.matches(&bs3));
    }

    #[test]
    fn test_copy_signature() {
        let cs = CopySignature::new(0x1000, 0x2000, 8);
        assert_eq!(cs.source_address, 0x1000);
        assert_eq!(cs.dest_address, 0x2000);
        assert_eq!(cs.size, 8);
    }

    #[test]
    fn test_varnode_signature() {
        let vs = VarnodeSignature::new("register", 0x10, 4);
        assert_eq!(vs.space, "register");
        assert_eq!(vs.offset, 0x10);
        assert_eq!(vs.size, 4);
    }

    #[test]
    fn test_debug_signature() {
        let mut ds = DebugSignature::new(0x1000);
        ds.add_block(BlockSignature::new(0x1000, 16, 5, 0xABCD));
        ds.add_copy(CopySignature::new(0x1000, 0x2000, 8));
        ds.add_varnode(VarnodeSignature::new("register", 0x10, 4));
        assert_eq!(ds.blocks.len(), 1);
        assert_eq!(ds.copies.len(), 1);
        assert_eq!(ds.varnodes.len(), 1);
    }

    #[test]
    fn test_signature_result() {
        let ds = DebugSignature::new(0x1000);
        let result = SignatureResult::success(ds);
        assert!(result.error_message.is_none());

        let err = SignatureResult::error("timeout".to_string());
        assert!(err.error_message.is_some());
    }
}
