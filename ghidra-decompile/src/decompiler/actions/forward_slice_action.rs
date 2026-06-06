//! Port of `ForwardSliceAction`.
use std::collections::HashMap;
/// Struct porting `ForwardSliceAction`.
#[derive(Debug, Clone)]
pub struct ForwardSliceAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ForwardSliceAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ForwardSliceAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_forward_slice_action_new() { let _ = ForwardSliceAction::new(); }
}
