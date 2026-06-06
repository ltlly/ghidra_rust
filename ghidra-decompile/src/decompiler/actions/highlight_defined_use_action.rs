//! Port of `HighlightDefinedUseAction`.
use std::collections::HashMap;
/// Struct porting `HighlightDefinedUseAction`.
#[derive(Debug, Clone)]
pub struct HighlightDefinedUseAction {
    _phantom: std::marker::PhantomData<()>,
}
impl HighlightDefinedUseAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for HighlightDefinedUseAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_highlight_defined_use_action_new() { let _ = HighlightDefinedUseAction::new(); }
}
