//! Port of `ConvertDoubleAction`.
use std::collections::HashMap;
/// Struct porting `ConvertDoubleAction`.
#[derive(Debug, Clone)]
pub struct ConvertDoubleAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ConvertDoubleAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConvertDoubleAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convert_double_action_new() { let _ = ConvertDoubleAction::new(); }
}
