//! Port of `RetypeFieldAction`.
use std::collections::HashMap;
/// Struct porting `RetypeFieldAction`.
#[derive(Debug, Clone)]
pub struct RetypeFieldAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RetypeFieldAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RetypeFieldAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_retype_field_action_new() { let _ = RetypeFieldAction::new(); }
}
