//! Port of `ConvertCharAction`.
use std::collections::HashMap;
/// Struct porting `ConvertCharAction`.
#[derive(Debug, Clone)]
pub struct ConvertCharAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ConvertCharAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConvertCharAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convert_char_action_new() { let _ = ConvertCharAction::new(); }
}
