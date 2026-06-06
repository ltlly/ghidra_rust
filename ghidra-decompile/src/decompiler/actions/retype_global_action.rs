//! Port of `RetypeGlobalAction`.
use std::collections::HashMap;
/// Struct porting `RetypeGlobalAction`.
#[derive(Debug, Clone)]
pub struct RetypeGlobalAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RetypeGlobalAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RetypeGlobalAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_retype_global_action_new() { let _ = RetypeGlobalAction::new(); }
}
