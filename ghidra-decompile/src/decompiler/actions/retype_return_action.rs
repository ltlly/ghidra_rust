//! Port of `RetypeReturnAction`.
use std::collections::HashMap;
/// Struct porting `RetypeReturnAction`.
#[derive(Debug, Clone)]
pub struct RetypeReturnAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RetypeReturnAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RetypeReturnAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_retype_return_action_new() { let _ = RetypeReturnAction::new(); }
}
