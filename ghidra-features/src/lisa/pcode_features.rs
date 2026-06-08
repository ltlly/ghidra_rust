//! P-code features for LISA analysis.
//!
//! Ported from `PcodeFeatures.java` in the Lisa extension.
//!
//! Tracks which p-code features (opcodes, patterns) are present in
//! a function or program, allowing analysis passes to check
//! prerequisites before running.

use std::collections::HashSet;

/// Tracks the presence of p-code features in analyzed code.
///
/// Used by analysis passes to check whether their prerequisites
/// are met before running (e.g., "does this function use CALL ops?").
#[derive(Debug, Clone, Default)]
pub struct PcodeFeatures {
    /// The set of opcodes present.
    opcodes: HashSet<String>,
    /// Whether function calls are present.
    has_calls: bool,
    /// Whether indirect branches are present.
    has_indirect_branches: bool,
    /// Whether floating-point operations are present.
    has_float_ops: bool,
}

impl PcodeFeatures {
    /// Create an empty feature set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a p-code opcode.
    pub fn record_opcode(&mut self, opcode: &str) {
        self.opcodes.insert(opcode.to_string());
        match opcode {
            "CALL" => self.has_calls = true,
            "CALLIND" => { self.has_calls = true; self.has_indirect_branches = true; }
            "BRANCHIND" => self.has_indirect_branches = true,
            "FLOAT_ADD" | "FLOAT_SUB" | "FLOAT_MULT" | "FLOAT_DIV" | "FLOAT_NEG"
            | "FLOAT_INT2FLOAT" | "FLOAT_FLOAT2FLOAT" | "FLOAT_TRUNC" => {
                self.has_float_ops = true
            }
            _ => {}
        }
    }

    /// Check if a specific opcode is present.
    pub fn has_opcode(&self, opcode: &str) -> bool {
        self.opcodes.contains(opcode)
    }

    /// Whether function calls are present.
    pub fn has_calls(&self) -> bool {
        self.has_calls
    }

    /// Whether indirect branches are present.
    pub fn has_indirect_branches(&self) -> bool {
        self.has_indirect_branches
    }

    /// Whether floating-point ops are present.
    pub fn has_float_ops(&self) -> bool {
        self.has_float_ops
    }

    /// Number of distinct opcodes.
    pub fn num_opcodes(&self) -> usize {
        self.opcodes.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_opcode() {
        let mut features = PcodeFeatures::new();
        features.record_opcode("INT_ADD");
        features.record_opcode("CALL");
        features.record_opcode("FLOAT_ADD");

        assert!(features.has_opcode("INT_ADD"));
        assert!(features.has_opcode("CALL"));
        assert!(!features.has_opcode("BRANCH"));
        assert!(features.has_calls());
        assert!(features.has_float_ops());
        assert_eq!(features.num_opcodes(), 3);
    }

    #[test]
    fn test_indirect_branch() {
        let mut features = PcodeFeatures::new();
        features.record_opcode("BRANCHIND");
        assert!(features.has_indirect_branches());
    }

    #[test]
    fn test_empty_features() {
        let features = PcodeFeatures::new();
        assert!(!features.has_calls());
        assert!(!features.has_float_ops());
        assert_eq!(features.num_opcodes(), 0);
    }
}
