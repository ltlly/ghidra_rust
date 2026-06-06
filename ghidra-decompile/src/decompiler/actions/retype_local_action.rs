//! Port of `RetypeLocalAction`.
use std::collections::HashMap;
/// Struct porting `RetypeLocalAction`.
#[derive(Debug, Clone)]
pub struct RetypeLocalAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RetypeLocalAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RetypeLocalAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_retype_local_action_new() { let _ = RetypeLocalAction::new(); }
}
