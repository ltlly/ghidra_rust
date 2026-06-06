//! ClangFuncProto: a function prototype token group.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangFuncProto`.
//! Re-exports `ClangFuncProtoData` from `clang_node`.

pub use super::clang_node::ClangFuncProtoData;

/// Create an empty function prototype group.
pub fn empty_func_proto() -> ClangFuncProtoData {
    ClangFuncProtoData::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_func_proto() {
        let p = empty_func_proto();
        assert!(p.group.children.is_empty());
    }
}
