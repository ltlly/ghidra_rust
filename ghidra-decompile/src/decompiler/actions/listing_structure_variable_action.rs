//! Port of `ListingStructureVariableAction`.
use std::collections::HashMap;
/// Struct porting `ListingStructureVariableAction`.
#[derive(Debug, Clone)]
pub struct ListingStructureVariableAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ListingStructureVariableAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ListingStructureVariableAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_listing_structure_variable_action_new() { let _ = ListingStructureVariableAction::new(); }
}
