//! P-code frontend for LISA analysis.
//!
//! Ported from `PcodeFrontend.java` in the Lisa extension.
//!
//! The frontend translates machine instructions into p-code
//! operations for analysis, providing the interface between
//! raw binary and the LISA analysis framework.

use super::locations::PcodeLocation;

/// A p-code operation produced by the frontend.
#[derive(Debug, Clone)]
pub struct PcodeOp {
    /// The opcode name (e.g., "INT_ADD", "COPY", "BRANCH").
    pub opcode: String,
    /// The address where this op was produced.
    pub address: u64,
    /// The p-code op index within the instruction.
    pub op_index: u32,
    /// Input varnode offsets (by index into a varnode table).
    pub inputs: Vec<u64>,
    /// Output varnode offset, if any.
    pub output: Option<u64>,
    /// Size in bytes.
    pub size: u32,
}

impl PcodeOp {
    /// Create a new p-code operation.
    pub fn new(
        opcode: impl Into<String>,
        address: u64,
        op_index: u32,
        inputs: Vec<u64>,
        output: Option<u64>,
        size: u32,
    ) -> Self {
        Self {
            opcode: opcode.into(),
            address,
            op_index,
            inputs,
            output,
            size,
        }
    }

    /// Get the location of this op.
    pub fn location(&self) -> PcodeLocation {
        PcodeLocation::new(self.address, self.op_index)
    }

    /// Whether this op has an output.
    pub fn has_output(&self) -> bool {
        self.output.is_some()
    }
}

/// The p-code frontend interface.
///
/// Translates machine instructions to p-code operations for the
/// analysis framework.
#[derive(Debug)]
pub struct PcodeFrontend {
    /// Translation cache: address -> list of p-code ops.
    cache: std::collections::HashMap<u64, Vec<PcodeOp>>,
}

impl PcodeFrontend {
    /// Create a new p-code frontend.
    pub fn new() -> Self {
        Self {
            cache: std::collections::HashMap::new(),
        }
    }

    /// Register p-code operations for an instruction address.
    pub fn register(&mut self, address: u64, ops: Vec<PcodeOp>) {
        self.cache.insert(address, ops);
    }

    /// Get p-code operations for an instruction address.
    pub fn get_ops(&self, address: u64) -> Option<&[PcodeOp]> {
        self.cache.get(&address).map(|v| v.as_slice())
    }

    /// Number of registered instructions.
    pub fn num_instructions(&self) -> usize {
        self.cache.len()
    }

    /// Clear the translation cache.
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

impl Default for PcodeFrontend {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_op() {
        let op = PcodeOp::new("INT_ADD", 0x1000, 0, vec![0, 8], Some(16), 8);
        assert_eq!(op.opcode, "INT_ADD");
        assert!(op.has_output());
        assert_eq!(op.location().address, 0x1000);
    }

    #[test]
    fn test_pcode_op_no_output() {
        let op = PcodeOp::new("STORE", 0x1000, 0, vec![0, 8, 16], None, 4);
        assert!(!op.has_output());
    }

    #[test]
    fn test_frontend_register_and_get() {
        let mut fe = PcodeFrontend::new();
        let ops = vec![
            PcodeOp::new("COPY", 0x1000, 0, vec![0], Some(8), 8),
            PcodeOp::new("INT_ADD", 0x1000, 1, vec![8, 16], Some(24), 8),
        ];
        fe.register(0x1000, ops);
        assert_eq!(fe.num_instructions(), 1);
        let got = fe.get_ops(0x1000).unwrap();
        assert_eq!(got.len(), 2);
        assert!(fe.get_ops(0x2000).is_none());
    }

    #[test]
    fn test_frontend_clear() {
        let mut fe = PcodeFrontend::new();
        fe.register(0x1000, vec![]);
        fe.clear();
        assert_eq!(fe.num_instructions(), 0);
    }
}
