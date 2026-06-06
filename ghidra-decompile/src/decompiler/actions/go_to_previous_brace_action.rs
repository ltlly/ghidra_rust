//! Port of `GoToPreviousBraceAction`.
use std::collections::HashMap;
/// Struct porting `GoToPreviousBraceAction`.
#[derive(Debug, Clone)]
pub struct GoToPreviousBraceAction {
    _phantom: std::marker::PhantomData<()>,
}
impl GoToPreviousBraceAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GoToPreviousBraceAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_go_to_previous_brace_action_new() { let _ = GoToPreviousBraceAction::new(); }
}
