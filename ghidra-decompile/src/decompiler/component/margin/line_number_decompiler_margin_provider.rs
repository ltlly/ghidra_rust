//! Port of `LineNumberDecompilerMarginProvider`.
use std::collections::HashMap;
/// Struct porting `LineNumberDecompilerMarginProvider`.
#[derive(Debug, Clone)]
pub struct LineNumberDecompilerMarginProvider {
    _phantom: std::marker::PhantomData<()>,
}
impl LineNumberDecompilerMarginProvider {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for LineNumberDecompilerMarginProvider {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_line_number_decompiler_margin_provider_new() { let _ = LineNumberDecompilerMarginProvider::new(); }
}
