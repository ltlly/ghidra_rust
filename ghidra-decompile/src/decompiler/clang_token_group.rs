//! ClangTokenGroup: a group of tokens representing a C code construct.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangTokenGroup`.
//! Re-exports `ClangTokenGroupData` from `clang_node` and provides
//! convenience constructors for building AST groups.

pub use super::clang_node::ClangTokenGroupData;

/// Create an empty token group.
pub fn empty_group() -> ClangTokenGroupData {
    ClangTokenGroupData::default()
}

/// Create a token group with a given parent id.
pub fn group_with_parent(parent: super::clang_node::ClangNodeId) -> ClangTokenGroupData {
    ClangTokenGroupData {
        parent,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_group() {
        let g = empty_group();
        assert!(g.children.is_empty());
        assert!(g.min_address.is_none());
        assert!(g.max_address.is_none());
    }

    #[test]
    fn test_group_with_parent() {
        let g = group_with_parent(42);
        assert_eq!(g.parent, 42);
    }
}
