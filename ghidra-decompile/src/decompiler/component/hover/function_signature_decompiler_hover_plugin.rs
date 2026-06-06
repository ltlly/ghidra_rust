//! Port of `FunctionSignatureDecompilerHoverPlugin`.
use std::collections::HashMap;
/// Struct porting `FunctionSignatureDecompilerHoverPlugin`.
#[derive(Debug, Clone)]
pub struct FunctionSignatureDecompilerHoverPlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl FunctionSignatureDecompilerHoverPlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FunctionSignatureDecompilerHoverPlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_function_signature_decompiler_hover_plugin_new() { let _ = FunctionSignatureDecompilerHoverPlugin::new(); }
}
