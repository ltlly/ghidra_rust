//! ClangStatement: a C statement grouping under a PcodeOp.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangStatement`.
//! Re-exports `ClangStatementData` from `clang_node`.

pub use super::clang_node::ClangStatementData;

/// Create an empty statement group.
pub fn empty_statement() -> ClangStatementData {
    ClangStatementData::default()
}

/// Create a statement group with a p-code op reference.
pub fn statement_with_op(op_ref: u32) -> ClangStatementData {
    ClangStatementData {
        group: Default::default(),
        op_ref: Some(op_ref),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_statement() {
        let s = empty_statement();
        assert!(s.group.children.is_empty());
        assert!(s.op_ref.is_none());
    }

    #[test]
    fn test_statement_with_op() {
        let s = statement_with_op(42);
        assert_eq!(s.op_ref, Some(42));
    }
}
