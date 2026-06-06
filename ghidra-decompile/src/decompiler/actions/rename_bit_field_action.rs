//! Port of `RenameBitFieldAction`.
use std::collections::HashMap;
/// Struct porting `RenameBitFieldAction`.
#[derive(Debug, Clone)]
pub struct RenameBitFieldAction {
    _phantom: std::marker::PhantomData<()>,
}
impl RenameBitFieldAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameBitFieldAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_bit_field_action_new() { let _ = RenameBitFieldAction::new(); }
}
