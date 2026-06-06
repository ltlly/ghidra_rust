//! Port of `ConvertDecAction`.
use std::collections::HashMap;
/// Struct porting `ConvertDecAction`.
#[derive(Debug, Clone)]
pub struct ConvertDecAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ConvertDecAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConvertDecAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convert_dec_action_new() { let _ = ConvertDecAction::new(); }
}
