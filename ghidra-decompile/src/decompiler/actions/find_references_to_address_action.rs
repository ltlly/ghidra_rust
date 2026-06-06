//! Port of `FindReferencesToAddressAction`.
use std::collections::HashMap;
/// Struct porting `FindReferencesToAddressAction`.
#[derive(Debug, Clone)]
pub struct FindReferencesToAddressAction {
    _phantom: std::marker::PhantomData<()>,
}
impl FindReferencesToAddressAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FindReferencesToAddressAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_find_references_to_address_action_new() { let _ = FindReferencesToAddressAction::new(); }
}
