//! Port of `SelectAllAction`.
use std::collections::HashMap;
/// Struct porting `SelectAllAction`.
#[derive(Debug, Clone)]
pub struct SelectAllAction {
    _phantom: std::marker::PhantomData<()>,
}
impl SelectAllAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SelectAllAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_select_all_action_new() { let _ = SelectAllAction::new(); }
}
