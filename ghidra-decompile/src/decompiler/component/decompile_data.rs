//! Port of `DecompileData`.
use std::collections::HashMap;
/// Struct porting `DecompileData`.
#[derive(Debug, Clone)]
pub struct DecompileData {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompileData {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompileData {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompile_data_new() { let _ = DecompileData::new(); }
}
