//! Port of `DecompilerSearchLocation`.
use std::collections::HashMap;
/// Struct porting `DecompilerSearchLocation`.
#[derive(Debug, Clone)]
pub struct DecompilerSearchLocation {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerSearchLocation {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerSearchLocation {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_search_location_new() { let _ = DecompilerSearchLocation::new(); }
}
