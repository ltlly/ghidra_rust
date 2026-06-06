//! Port of `ReferenceDecompilerHover`.
use std::collections::HashMap;
/// Struct porting `ReferenceDecompilerHover`.
#[derive(Debug, Clone)]
pub struct ReferenceDecompilerHover {
    _phantom: std::marker::PhantomData<()>,
}
impl ReferenceDecompilerHover {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ReferenceDecompilerHover {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_reference_decompiler_hover_new() { let _ = ReferenceDecompilerHover::new(); }
}
