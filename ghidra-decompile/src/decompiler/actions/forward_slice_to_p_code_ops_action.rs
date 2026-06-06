//! Port of `ForwardSliceToPCodeOpsAction`.
use std::collections::HashMap;
/// Struct porting `ForwardSliceToPCodeOpsAction`.
#[derive(Debug, Clone)]
pub struct ForwardSliceToPCodeOpsAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ForwardSliceToPCodeOpsAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ForwardSliceToPCodeOpsAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_forward_slice_to_p_code_ops_action_new() { let _ = ForwardSliceToPCodeOpsAction::new(); }
}
