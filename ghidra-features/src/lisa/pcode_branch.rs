//! P-code branch representation.
//!
//! Ported from `PcodeBranch.java` in the Lisa extension.
//!
//! Represents a branch in the p-code control flow graph.

/// A branch in the p-code control flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeBranch {
    /// The address of the branch instruction.
    pub address: u64,
    /// The branch target address.
    pub target: u64,
    /// The type of branch.
    pub kind: BranchKind,
}

/// The kind of branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BranchKind {
    /// Unconditional branch.
    Unconditional,
    /// Conditional branch (falls through if condition is false).
    Conditional,
    /// Call (returns to the next instruction).
    Call,
    /// Indirect call (target is a register/memory value).
    IndirectCall,
    /// Indirect branch (computed jump).
    IndirectBranch,
    /// Return from function.
    Return,
}

impl PcodeBranch {
    /// Create a new branch.
    pub fn new(address: u64, target: u64, kind: BranchKind) -> Self {
        Self {
            address,
            target,
            kind,
        }
    }

    /// Whether this is a conditional branch.
    pub fn is_conditional(&self) -> bool {
        self.kind == BranchKind::Conditional
    }

    /// Whether this is an unconditional branch.
    pub fn is_unconditional(&self) -> bool {
        self.kind == BranchKind::Unconditional
    }

    /// Whether this is a call.
    pub fn is_call(&self) -> bool {
        matches!(self.kind, BranchKind::Call | BranchKind::IndirectCall)
    }

    /// Whether this is a return.
    pub fn is_return(&self) -> bool {
        self.kind == BranchKind::Return
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unconditional_branch() {
        let b = PcodeBranch::new(0x1000, 0x2000, BranchKind::Unconditional);
        assert!(b.is_unconditional());
        assert!(!b.is_conditional());
    }

    #[test]
    fn test_conditional_branch() {
        let b = PcodeBranch::new(0x1000, 0x3000, BranchKind::Conditional);
        assert!(b.is_conditional());
    }

    #[test]
    fn test_call_branch() {
        let b = PcodeBranch::new(0x1000, 0x4000, BranchKind::Call);
        assert!(b.is_call());
        assert!(!b.is_return());
    }

    #[test]
    fn test_return() {
        let b = PcodeBranch::new(0x1000, 0, BranchKind::Return);
        assert!(b.is_return());
    }
}
