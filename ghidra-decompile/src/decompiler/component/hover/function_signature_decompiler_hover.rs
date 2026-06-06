//! Port of `FunctionSignatureDecompilerHover`.
use std::collections::HashMap;
/// Struct porting `FunctionSignatureDecompilerHover`.
#[derive(Debug, Clone)]
pub struct FunctionSignatureDecompilerHover {
    _phantom: std::marker::PhantomData<()>,
}
impl FunctionSignatureDecompilerHover {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FunctionSignatureDecompilerHover {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_function_signature_decompiler_hover_new() { let _ = FunctionSignatureDecompilerHover::new(); }
}
