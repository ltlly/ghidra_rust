//! Port of `ConvertBinaryAction`.
use std::collections::HashMap;
/// Struct porting `ConvertBinaryAction`.
#[derive(Debug, Clone)]
pub struct ConvertBinaryAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ConvertBinaryAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConvertBinaryAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convert_binary_action_new() { let _ = ConvertBinaryAction::new(); }
}
