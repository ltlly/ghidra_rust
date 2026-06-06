//! Port of `DecompilerCommentsActionFactory`.
use std::collections::HashMap;
/// Struct porting `DecompilerCommentsActionFactory`.
#[derive(Debug, Clone)]
pub struct DecompilerCommentsActionFactory {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerCommentsActionFactory {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerCommentsActionFactory {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_comments_action_factory_new() { let _ = DecompilerCommentsActionFactory::new(); }
}
