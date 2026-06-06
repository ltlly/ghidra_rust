//! Port of `RenameLocalAction`.
use std::collections::HashMap;
/// Struct porting `RenameLocalAction`.
#[derive(Debug, Clone)]
pub struct RenameLocalAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RenameLocalAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameLocalAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_local_action_new() { let _ = RenameLocalAction::new(); }
}
