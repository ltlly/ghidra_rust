//! Port of `DecompilerHoverProvider`.
use std::collections::HashMap;
/// Struct porting `DecompilerHoverProvider`.
#[derive(Debug, Clone)]
pub struct DecompilerHoverProvider {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerHoverProvider {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerHoverProvider {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_hover_provider_new() { let _ = DecompilerHoverProvider::new(); }
}
