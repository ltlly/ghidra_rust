//! Port of `ScalarValueDecompilerHoverPlugin`.
use std::collections::HashMap;
/// Struct porting `ScalarValueDecompilerHoverPlugin`.
#[derive(Debug, Clone)]
pub struct ScalarValueDecompilerHoverPlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl ScalarValueDecompilerHoverPlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ScalarValueDecompilerHoverPlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_scalar_value_decompiler_hover_plugin_new() { let _ = ScalarValueDecompilerHoverPlugin::new(); }
}
