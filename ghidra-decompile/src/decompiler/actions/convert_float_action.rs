//! Port of `ConvertFloatAction`.
use std::collections::HashMap;
/// Struct porting `ConvertFloatAction`.
#[derive(Debug, Clone)]
pub struct ConvertFloatAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ConvertFloatAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConvertFloatAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convert_float_action_new() { let _ = ConvertFloatAction::new(); }
}
