//! Port of `DecompilerSearcher`.
use std::collections::HashMap;
/// Struct porting `DecompilerSearcher`.
#[derive(Debug, Clone)]
pub struct DecompilerSearcher {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerSearcher {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerSearcher {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_searcher_new() { let _ = DecompilerSearcher::new(); }
}
