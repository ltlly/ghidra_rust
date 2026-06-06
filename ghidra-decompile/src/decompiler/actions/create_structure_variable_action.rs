//! Port of `CreateStructureVariableAction`.
use std::collections::HashMap;
/// Struct porting `CreateStructureVariableAction`.
#[derive(Debug, Clone)]
pub struct CreateStructureVariableAction {
    /// controller
    pub controller: String,
}
impl CreateStructureVariableAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CreateStructureVariableAction {
    fn default() -> Self {
        Self {
            controller: String::new()
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_create_structure_variable_action_new() { let _ = CreateStructureVariableAction::new(); }
}
