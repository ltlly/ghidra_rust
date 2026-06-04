//! Context objects for p-code analysis.
//!
//! Ported from the `ghidra.lisa.pcode.contexts` package in the Lisa extension.
//!
//! Context objects carry analysis state through the p-code IR visitor.
//! Each context type represents a different syntactic construct
//! (expressions, statements, instructions, etc.) and provides
//! typed access to the construct's operands.

mod varnode_context;
mod expression_context;
mod statement_context;
mod instruction_context;

pub use varnode_context::{VarnodeContext, SymbolVarnodeContext, MemLocContext};
pub use expression_context::{
    BinaryExprContext, UnaryExprContext, TernaryExprContext,
    CallContext, VarargsExprContext,
};
pub use statement_context::{StatementContext, ConditionContext, VarDefContext};
pub use instruction_context::{InstructionContext, HighInstructionContext};

/// An abstract unit of p-code analysis.
///
/// Every context implements this trait, which provides a way
/// to check whether the context represents valid, complete
/// analysis state.
pub trait UnitContext {
    /// Whether this context represents a valid (non-null) unit.
    fn is_valid(&self) -> bool;
}

/// High-level unit context (function / global scope).
#[derive(Debug, Clone)]
pub struct HighUnitContext {
    /// Name of the enclosing function or unit.
    pub name: String,
    /// Whether this is a valid (non-empty) unit.
    pub valid: bool,
}

impl UnitContext for HighUnitContext {
    fn is_valid(&self) -> bool {
        self.valid
    }
}

/// High-level statement context (for decompiler output analysis).
#[derive(Debug, Clone)]
pub struct HighStatementContext {
    /// The statement text.
    pub text: String,
    /// The address of the statement.
    pub address: u64,
}

impl UnitContext for HighStatementContext {
    fn is_valid(&self) -> bool {
        !self.text.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_unit_context() {
        let ctx = HighUnitContext {
            name: "main".to_string(),
            valid: true,
        };
        assert!(ctx.is_valid());

        let invalid = HighUnitContext {
            name: String::new(),
            valid: false,
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_high_statement_context() {
        let ctx = HighStatementContext {
            text: "x = y + z".to_string(),
            address: 0x1000,
        };
        assert!(ctx.is_valid());

        let empty = HighStatementContext {
            text: String::new(),
            address: 0,
        };
        assert!(!empty.is_valid());
    }
}
