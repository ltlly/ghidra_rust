//! Port of `CommitParamsAction`.
use std::collections::HashMap;
/// Struct porting `CommitParamsAction`.
#[derive(Debug, Clone)]
pub struct CommitParamsAction {
    _phantom: std::marker::PhantomData<()>,
}
impl CommitParamsAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CommitParamsAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_commit_params_action_new() { let _ = CommitParamsAction::new(); }
}
