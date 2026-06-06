//! Port of `DataTypeDecompilerHoverPlugin`.
use std::collections::HashMap;
/// Struct porting `DataTypeDecompilerHoverPlugin`.
#[derive(Debug, Clone)]
pub struct DataTypeDecompilerHoverPlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl DataTypeDecompilerHoverPlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DataTypeDecompilerHoverPlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_data_type_decompiler_hover_plugin_new() { let _ = DataTypeDecompilerHoverPlugin::new(); }
}
