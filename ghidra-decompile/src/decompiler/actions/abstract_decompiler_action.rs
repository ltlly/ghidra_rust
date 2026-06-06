//! Port of `AbstractDecompilerAction`.
use std::collections::HashMap;
/// Struct porting `AbstractDecompilerAction`.
#[derive(Debug, Clone)]
pub struct AbstractDecompilerAction {
    _phantom: std::marker::PhantomData<()>,
}
impl AbstractDecompilerAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for AbstractDecompilerAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_decompiler_action_new() { let _ = AbstractDecompilerAction::new(); }
}
