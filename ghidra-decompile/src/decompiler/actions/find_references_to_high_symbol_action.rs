//! Port of `FindReferencesToHighSymbolAction`.
use std::collections::HashMap;
/// Struct porting `FindReferencesToHighSymbolAction`.
#[derive(Debug, Clone)]
pub struct FindReferencesToHighSymbolAction {
    /// NAME
    pub name: String,
}
impl FindReferencesToHighSymbolAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FindReferencesToHighSymbolAction {
    fn default() -> Self {
        Self {
            name: String::new()
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_find_references_to_high_symbol_action_new() { let _ = FindReferencesToHighSymbolAction::new(); }
}
