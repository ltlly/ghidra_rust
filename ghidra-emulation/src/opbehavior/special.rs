//! Special operation behavior.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.SpecialOpBehavior`.

/// Special operations that don't fit the binary/unary pattern.
///
/// These include LOAD, STORE, BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND,
/// CALLOTHER, RETURN, MULTIEQUAL, INDIRECT, CAST, PTRADD, PTRSUB,
/// SEGMENTOP, CPOOLREF, NEW, INSERT, ZPULL, SPULL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecialOpBehavior {
    /// The P-code opcode.
    pub opcode: u32,
}

impl SpecialOpBehavior {
    /// Create a new special op behavior for the given opcode.
    pub fn new(opcode: u32) -> Self {
        Self { opcode }
    }

    /// Get the opcode.
    pub fn get_opcode(&self) -> u32 {
        self.opcode
    }
}
