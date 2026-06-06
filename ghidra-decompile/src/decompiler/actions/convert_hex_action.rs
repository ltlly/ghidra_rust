//! Port of `ConvertHexAction`.
use std::collections::HashMap;
/// Struct porting `ConvertHexAction`.
#[derive(Debug, Clone)]
pub struct ConvertHexAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ConvertHexAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConvertHexAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convert_hex_action_new() { let _ = ConvertHexAction::new(); }
}
