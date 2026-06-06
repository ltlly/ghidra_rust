//! Port of `WrappedActionTrigger`.
use std::collections::HashMap;
/// Struct porting `WrappedActionTrigger`.
#[derive(Debug, Clone)]
pub struct WrappedActionTrigger {
    _phantom: std::marker::PhantomData<()>,
}
impl WrappedActionTrigger {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WrappedActionTrigger {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wrapped_action_trigger_new() { let _ = WrappedActionTrigger::new(); }
}
