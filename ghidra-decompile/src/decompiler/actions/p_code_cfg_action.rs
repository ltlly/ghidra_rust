//! Port of `PCodeCfgAction`.
use std::collections::HashMap;
/// Struct porting `PCodeCfgAction`.
#[derive(Debug, Clone)]
pub struct PCodeCfgAction {
    _phantom: std::marker::PhantomData<()>,
}
impl PCodeCfgAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeCfgAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_cfg_action_new() { let _ = PCodeCfgAction::new(); }
}
