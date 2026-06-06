//! Port of `DecompileProcessFactory`.
use std::collections::HashMap;
/// Struct porting `DecompileProcessFactory`.
#[derive(Debug, Clone)]
pub struct DecompileProcessFactory {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompileProcessFactory {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompileProcessFactory {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompile_process_factory_new() { let _ = DecompileProcessFactory::new(); }
}
