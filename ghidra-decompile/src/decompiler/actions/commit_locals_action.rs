//! Port of `CommitLocalsAction`.
use std::collections::HashMap;
/// Struct porting `CommitLocalsAction`.
#[derive(Debug, Clone)]
pub struct CommitLocalsAction {
    _phantom: std::marker::PhantomData<()>,
}
impl CommitLocalsAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CommitLocalsAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_commit_locals_action_new() { let _ = CommitLocalsAction::new(); }
}
