//! Port of `GoToNextBraceAction`.
use std::collections::HashMap;
/// Struct porting `GoToNextBraceAction`.
#[derive(Debug, Clone)]
pub struct GoToNextBraceAction {
    _phantom: std::marker::PhantomData<()>,
}
impl GoToNextBraceAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GoToNextBraceAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_go_to_next_brace_action_new() { let _ = GoToNextBraceAction::new(); }
}
