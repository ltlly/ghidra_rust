//! Port of `DecompilerCallbackHandlerAdapter`.
use std::collections::HashMap;
/// Struct porting `DecompilerCallbackHandlerAdapter`.
#[derive(Debug, Clone)]
pub struct DecompilerCallbackHandlerAdapter {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerCallbackHandlerAdapter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerCallbackHandlerAdapter {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_callback_handler_adapter_new() { let _ = DecompilerCallbackHandlerAdapter::new(); }
}
