//! Port of `CloneDecompilerAction`.
use std::collections::HashMap;
/// Struct porting `CloneDecompilerAction`.
#[derive(Debug, Clone)]
pub struct CloneDecompilerAction {
    _phantom: std::marker::PhantomData<()>,
}
impl CloneDecompilerAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CloneDecompilerAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clone_decompiler_action_new() { let _ = CloneDecompilerAction::new(); }
}
