//! Port of `DecompilerDisposer`.
use std::collections::HashMap;
/// Struct porting `DecompilerDisposer`.
#[derive(Debug, Clone)]
pub struct DecompilerDisposer {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerDisposer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerDisposer {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_disposer_new() { let _ = DecompilerDisposer::new(); }
}
