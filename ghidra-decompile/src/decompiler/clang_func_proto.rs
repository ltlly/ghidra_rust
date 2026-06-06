//! Port of `ClangFuncProto`.
use std::collections::HashMap;
/// Struct porting `ClangFuncProto`.
#[derive(Debug, Clone)]
pub struct ClangFuncProto {
    _phantom: std::marker::PhantomData<()>,
}
impl ClangFuncProto {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ClangFuncProto {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clang_func_proto_new() { let _ = ClangFuncProto::new(); }
}
