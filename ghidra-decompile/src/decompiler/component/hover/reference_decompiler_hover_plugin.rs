//! Port of `ReferenceDecompilerHoverPlugin`.
use std::collections::HashMap;
/// Struct porting `ReferenceDecompilerHoverPlugin`.
#[derive(Debug, Clone)]
pub struct ReferenceDecompilerHoverPlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl ReferenceDecompilerHoverPlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ReferenceDecompilerHoverPlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_reference_decompiler_hover_plugin_new() { let _ = ReferenceDecompilerHoverPlugin::new(); }
}
