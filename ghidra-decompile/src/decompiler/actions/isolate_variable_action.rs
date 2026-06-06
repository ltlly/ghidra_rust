//! Port of `IsolateVariableAction`.
use std::collections::HashMap;
/// Struct porting `IsolateVariableAction`.
#[derive(Debug, Clone)]
pub struct IsolateVariableAction {
    _phantom: std::marker::PhantomData<()>,
}
impl IsolateVariableAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for IsolateVariableAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_isolate_variable_action_new() { let _ = IsolateVariableAction::new(); }
}
