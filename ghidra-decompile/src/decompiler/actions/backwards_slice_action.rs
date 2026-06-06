//! Port of `BackwardsSliceAction`.
use std::collections::HashMap;
/// Struct porting `BackwardsSliceAction`.
#[derive(Debug, Clone)]
pub struct BackwardsSliceAction {
    /// NAME
    pub name: String,
}
impl BackwardsSliceAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BackwardsSliceAction {
    fn default() -> Self {
        Self {
            name: String::new()
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_backwards_slice_action_new() { let _ = BackwardsSliceAction::new(); }
}
