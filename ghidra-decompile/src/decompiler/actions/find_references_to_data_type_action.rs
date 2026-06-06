//! Port of `FindReferencesToDataTypeAction`.
use std::collections::HashMap;
/// Struct porting `FindReferencesToDataTypeAction`.
#[derive(Debug, Clone)]
pub struct FindReferencesToDataTypeAction {
    _phantom: std::marker::PhantomData<()>,
}
impl FindReferencesToDataTypeAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FindReferencesToDataTypeAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_find_references_to_data_type_action_new() { let _ = FindReferencesToDataTypeAction::new(); }
}
