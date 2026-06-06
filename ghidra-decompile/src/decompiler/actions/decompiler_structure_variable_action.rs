//! Port of `DecompilerStructureVariableAction`.
use std::collections::HashMap;
/// Struct porting `DecompilerStructureVariableAction`.
#[derive(Debug, Clone)]
pub struct DecompilerStructureVariableAction {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerStructureVariableAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerStructureVariableAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_structure_variable_action_new() { let _ = DecompilerStructureVariableAction::new(); }
}
