//! Port of `RenameGlobalAction`.
use std::collections::HashMap;
/// Struct porting `RenameGlobalAction`.
#[derive(Debug, Clone)]
pub struct RenameGlobalAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RenameGlobalAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameGlobalAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_global_action_new() { let _ = RenameGlobalAction::new(); }
}
