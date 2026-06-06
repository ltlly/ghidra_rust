//! Port of `VariableDecompilerLocation`.
use std::collections::HashMap;
/// Struct porting `VariableDecompilerLocation`.
#[derive(Debug, Clone)]
pub struct VariableDecompilerLocation {
    _phantom: std::marker::PhantomData<()>,
}
impl VariableDecompilerLocation {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VariableDecompilerLocation {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_variable_decompiler_location_new() { let _ = VariableDecompilerLocation::new(); }
}
