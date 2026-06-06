//! Port of `DecompilerActionContext`.
use std::collections::HashMap;
/// Struct porting `DecompilerActionContext`.
#[derive(Debug, Clone)]
pub struct DecompilerActionContext {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerActionContext {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerActionContext {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_action_context_new() { let _ = DecompilerActionContext::new(); }
}
