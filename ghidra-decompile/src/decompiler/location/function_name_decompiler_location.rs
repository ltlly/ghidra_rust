//! Port of `FunctionNameDecompilerLocation`.
use std::collections::HashMap;
/// Struct porting `FunctionNameDecompilerLocation`.
#[derive(Debug, Clone)]
pub struct FunctionNameDecompilerLocation {
    _phantom: std::marker::PhantomData<()>,
}
impl FunctionNameDecompilerLocation {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FunctionNameDecompilerLocation {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_function_name_decompiler_location_new() { let _ = FunctionNameDecompilerLocation::new(); }
}
