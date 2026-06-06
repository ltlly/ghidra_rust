//! Port of `ConvertOctAction`.
use std::collections::HashMap;
/// Struct porting `ConvertOctAction`.
#[derive(Debug, Clone)]
pub struct ConvertOctAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ConvertOctAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConvertOctAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convert_oct_action_new() { let _ = ConvertOctAction::new(); }
}
