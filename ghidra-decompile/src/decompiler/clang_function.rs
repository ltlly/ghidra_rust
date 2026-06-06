//! ClangFunction: a grouping of tokens for an entire function.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangFunction`.
//! Re-exports `ClangFunctionData` from `clang_node`.

pub use super::clang_node::ClangFunctionData;

/// Create an empty function group.
pub fn empty_function() -> ClangFunctionData {
    ClangFunctionData::default()
}

/// Create a function group with a high-function reference.
pub fn function_with_ref(high_function_ref: u32) -> ClangFunctionData {
    ClangFunctionData {
        group: Default::default(),
        high_function_ref: Some(high_function_ref),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_function() {
        let f = empty_function();
        assert!(f.group.children.is_empty());
        assert!(f.high_function_ref.is_none());
    }

    #[test]
    fn test_function_with_ref() {
        let f = function_with_ref(99);
        assert_eq!(f.high_function_ref, Some(99));
    }
}
