//! Port of `DecompilerSearchResults`.
use std::collections::HashMap;
/// Struct porting `DecompilerSearchResults`.
#[derive(Debug, Clone)]
pub struct DecompilerSearchResults {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerSearchResults {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerSearchResults {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_search_results_new() { let _ = DecompilerSearchResults::new(); }
}
