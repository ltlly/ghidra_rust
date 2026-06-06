//! Port of `BackwardsSliceToPCodeOpsAction`.
use std::collections::HashMap;
/// Struct porting `BackwardsSliceToPCodeOpsAction`.
#[derive(Debug, Clone)]
pub struct BackwardsSliceToPCodeOpsAction {
    _phantom: std::marker::PhantomData<()>,
}
impl BackwardsSliceToPCodeOpsAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BackwardsSliceToPCodeOpsAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_backwards_slice_to_p_code_ops_action_new() { let _ = BackwardsSliceToPCodeOpsAction::new(); }
}
