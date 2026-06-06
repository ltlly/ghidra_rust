//! Port of `PCodeDfgAction`.
use std::collections::HashMap;
/// Struct porting `PCodeDfgAction`.
#[derive(Debug, Clone)]
pub struct PCodeDfgAction {
    _phantom: std::marker::PhantomData<()>,
}
impl PCodeDfgAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeDfgAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_dfg_action_new() { let _ = PCodeDfgAction::new(); }
}
