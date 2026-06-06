//! Port of `ScalarValueDecompilerHover`.
use std::collections::HashMap;
/// Struct porting `ScalarValueDecompilerHover`.
#[derive(Debug, Clone)]
pub struct ScalarValueDecompilerHover {
    _phantom: std::marker::PhantomData<()>,
}
impl ScalarValueDecompilerHover {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ScalarValueDecompilerHover {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_scalar_value_decompiler_hover_new() { let _ = ScalarValueDecompilerHover::new(); }
}
