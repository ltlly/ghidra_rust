//! Port of `RenameFunctionAction`.
use std::collections::HashMap;
/// Struct porting `RenameFunctionAction`.
#[derive(Debug, Clone)]
pub struct RenameFunctionAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RenameFunctionAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameFunctionAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_function_action_new() { let _ = RenameFunctionAction::new(); }
}
