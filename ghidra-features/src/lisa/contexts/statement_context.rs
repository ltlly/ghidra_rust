//! Statement context types for p-code analysis.
//!
//! Ported from `StatementContext.java`, `ConditionContext.java`, and
//! `VarDefContext.java` in the Lisa extension.

/// Context for a p-code statement.
#[derive(Debug, Clone)]
pub struct StatementContext {
    /// The opcode name.
    pub opcode: String,
    /// The address of this statement.
    pub address: u64,
    /// Whether this is a branch.
    pub is_branch: bool,
    /// The branch target, if this is a branch.
    pub branch_target: Option<u64>,
}

impl StatementContext {
    /// Create a new statement context.
    pub fn new(opcode: impl Into<String>, address: u64) -> Self {
        Self {
            opcode: opcode.into(),
            address,
            is_branch: false,
            branch_target: None,
        }
    }

    /// Mark this statement as a branch.
    pub fn with_branch(mut self, target: u64) -> Self {
        self.is_branch = true;
        self.branch_target = Some(target);
        self
    }
}

/// Context for a conditional branch condition.
#[derive(Debug, Clone)]
pub struct ConditionContext {
    /// The condition opcode (e.g., "CBRANCH").
    pub opcode: String,
    /// The condition value varnode offset.
    pub condition_offset: u64,
    /// The true branch target.
    pub true_target: u64,
    /// The false fallthrough address.
    pub false_target: u64,
}

impl ConditionContext {
    /// Create a new condition context.
    pub fn new(
        opcode: impl Into<String>,
        condition_offset: u64,
        true_target: u64,
        false_target: u64,
    ) -> Self {
        Self {
            opcode: opcode.into(),
            condition_offset,
            true_target,
            false_target,
        }
    }
}

/// Context for a variable definition (store / register write).
#[derive(Debug, Clone)]
pub struct VarDefContext {
    /// The address of the definition.
    pub address: u64,
    /// The offset of the target varnode.
    pub target_offset: u64,
    /// The size of the target varnode in bytes.
    pub target_size: u32,
    /// The name of the address space.
    pub space: String,
}

impl VarDefContext {
    /// Create a new variable definition context.
    pub fn new(
        address: u64,
        target_offset: u64,
        target_size: u32,
        space: impl Into<String>,
    ) -> Self {
        Self {
            address,
            target_offset,
            target_size,
            space: space.into(),
        }
    }

    /// Whether this is a register write.
    pub fn is_register_write(&self) -> bool {
        self.space == "register"
    }

    /// Whether this is a memory store.
    pub fn is_memory_store(&self) -> bool {
        self.space == "ram"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statement_context() {
        let stmt = StatementContext::new("COPY", 0x1000);
        assert_eq!(stmt.address, 0x1000);
        assert!(!stmt.is_branch);
    }

    #[test]
    fn test_statement_with_branch() {
        let stmt = StatementContext::new("CBRANCH", 0x1000).with_branch(0x2000);
        assert!(stmt.is_branch);
        assert_eq!(stmt.branch_target, Some(0x2000));
    }

    #[test]
    fn test_condition_context() {
        let cond = ConditionContext::new("CBRANCH", 0, 0x2000, 0x1004);
        assert_eq!(cond.true_target, 0x2000);
        assert_eq!(cond.false_target, 0x1004);
    }

    #[test]
    fn test_vardef_context() {
        let vd = VarDefContext::new(0x1000, 0, 8, "register");
        assert!(vd.is_register_write());
        assert!(!vd.is_memory_store());

        let mem = VarDefContext::new(0x1000, 0x4000, 4, "ram");
        assert!(mem.is_memory_store());
    }
}
